//! # tt-inventory
//!
//! Read-only enumeration and hashing of the roots the submitter explicitly selected.
//!
//! ## Default-deny
//!
//! The scanner walks the supplied roots and nothing else. There is no "helpful"
//! widening: no drive scan, no `%USERPROFILE%` fallback, no following of a path that
//! a config file mentions. A root the submitter did not hand over is not evidence,
//! and reading it would be a privacy incident rather than a feature.
//!
//! ## Reparse points are never followed
//!
//! Symlinks, junctions and mount points are recorded and skipped
//! (`TT-INV-003`), never traversed. The consequence is worth stating explicitly:
//! **because no reparse point is ever followed, a traversal loop is structurally
//! impossible.** Every path this module visits is reached by descending real
//! directory entries from a selected root, so the walk is a finite tree and needs no
//! visited-set, no device/inode bookkeeping and no loop heuristic. Depth is bounded
//! anyway by `Limits::max_traversal_depth`, and breadth by
//! `Limits::max_files_enumerated`, so an adversarial tree costs bounded time and
//! bounded memory rather than a hang.
//!
//! Traversal is an explicit stack, not recursion, so a deep tree cannot overflow the
//! process stack even if a caller raises `max_traversal_depth`.
//!
//! ## Determinism
//!
//! Directory entries are sorted by file name before they are visited, so artifact ids
//! are assigned in the same order on every run. Two scans of an unchanged tree differ
//! only in `mtime`-derived values, which is an acceptance test rather than an
//! aspiration (`two_scans_of_one_tree_are_identical`).
//!
//! ## What this module refuses to decide
//!
//! Classification is not done here. The caller supplies a `classify` callback and
//! this module hands it a bounded head buffer; deciding that a file is a SafeTensors
//! checkpoint is `tt-formats`' job, and mixing the two would make "what is on disk"
//! depend on "what we think it means". Nothing here opens a file for any purpose
//! other than reading a bounded prefix and hashing bytes: no vendor content is
//! executed, deserialised or interpreted.

#![forbid(unsafe_code)]

use std::fs::{self, File, Metadata};
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use tt_core::error::{TtError, TtResult};
use tt_core::hash::{hash_file, HashScope};
use tt_core::ids::IdAllocator;
use tt_core::limits::Limits;
use tt_core::redact::Redactor;
use tt_core::time::Timestamp;
use tt_core::vocab::CoverageStatus;
use tt_facts::{ArtifactRecord, ArtifactType, CoverageNote, ReadStatus};

/// `FILE_ATTRIBUTE_REPARSE_POINT`. Declared here rather than pulled from a Windows
/// binding crate: one constant is cheaper to audit than a dependency.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Hard ceiling on the head buffer handed to `classify`, whatever the caller asks
/// for. Classification is a sniff, not a read.
pub const MAX_HEAD_BYTES: usize = 1024;

/// Detail prefix used when the depth bound stopped a descent.
const DETAIL_DEPTH: &str = "max_traversal_depth";
/// Detail prefix used when the enumeration bound stopped a listing.
const DETAIL_FILES: &str = "max_files_enumerated";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Everything the caller gets to choose about a scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub limits: Limits,
    /// When false, files are enumerated and classified but never hashed. Every
    /// record then carries [`ReadStatus::NotHashed`], so a metadata-only scan can
    /// never be mistaken for a hashed one.
    pub hash_files: bool,
    /// Submitter exclusions. A path at or under one of these is listed in the
    /// manifest as [`ReadStatus::SkippedBySubmitter`] and is never opened.
    pub excluded: Vec<PathBuf>,
    /// Bytes handed to `classify`, clamped to [`MAX_HEAD_BYTES`].
    pub head_bytes: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            limits: Limits::default(),
            hash_files: true,
            excluded: Vec::new(),
            head_bytes: MAX_HEAD_BYTES,
        }
    }
}

/// Progress derived from bytes actually seen. There is no estimated total and no
/// percentage: the size of the tree is not known until it has been walked, and an
/// invented denominator would be a number the product cannot stand behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanProgress {
    pub files_enumerated: u64,
    pub bytes_enumerated: u64,
    pub bytes_hashed: u64,
}

/// The result of one traversal.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub artifacts: Vec<ArtifactRecord>,
    pub coverage: Vec<CoverageNote>,
    /// One alias per supplied root, in the order supplied.
    pub root_aliases: Vec<String>,
    pub files_enumerated: u64,
    pub files_hashed: u64,
    pub bytes_enumerated: u64,
    pub bytes_hashed: u64,
    pub coverage_status: CoverageStatus,
}

impl Inventory {
    /// True when at least one artifact is a file the scanner actually enumerated,
    /// as opposed to a path it could only record as unreachable.
    fn any_readable(&self) -> bool {
        self.artifacts.iter().any(|a| {
            matches!(
                a.read_status,
                ReadStatus::Ok | ReadStatus::TooLarge | ReadStatus::Changed | ReadStatus::NotHashed
            )
        })
    }

    fn all_ok(&self) -> bool {
        self.artifacts.iter().all(|a| a.read_status == ReadStatus::Ok)
    }
}

/// Walk the selected roots and hash what is inside them.
///
/// Returns `Err(TtError::Io { detail: "cancelled" })` if `cancel` fires. A cancelled
/// scan yields no `Inventory` on purpose: a truncated walk must never be handed on as
/// if it were a complete one.
/// Walk the selected roots, hash what is inside them, and classify each file.
///
/// ## The path handed to `classify`
///
/// Roots are canonicalised before the walk, so on Windows `classify` receives a
/// *verbatim* path (`\?\C:\...`). `file_name()`, `extension()` and suffix
/// matching all behave normally on it, but it will never compare equal to a plain
/// path the caller assembled itself. Match on the file name, not on a whole path.
pub fn scan(
    roots: &[PathBuf],
    redactor: &mut Redactor,
    opts: &ScanOptions,
    classify: &dyn Fn(&Path, &[u8]) -> ArtifactType,
    cancel: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(ScanProgress),
) -> TtResult<Inventory> {
    let excluded: Vec<Vec<String>> = opts
        .excluded
        .iter()
        .map(|p| components_ci(&fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .filter(|c| !c.is_empty())
        .collect();

    let mut scanner = Scanner {
        opts,
        redactor,
        classify,
        cancel,
        progress,
        ids: IdAllocator::new(),
        excluded,
        inv: Inventory::default(),
        entries_examined: 0,
        enumeration_capped: false,
    };
    scanner.run(roots)?;

    let mut inv = scanner.inv;
    inv.coverage_status = if !inv.any_readable() {
        CoverageStatus::Minimal
    } else if inv.coverage.is_empty() && inv.all_ok() {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    };
    Ok(inv)
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

/// One directory being walked: its entries in name order, and how far through them
/// the walk has got.
struct Frame {
    entries: Vec<PathBuf>,
    next: usize,
    /// Depth of this directory itself. A selected root is depth 0, so its children
    /// are depth 1.
    depth: usize,
}

struct Scanner<'a> {
    opts: &'a ScanOptions,
    redactor: &'a mut Redactor,
    classify: &'a dyn Fn(&Path, &[u8]) -> ArtifactType,
    cancel: &'a dyn Fn() -> bool,
    progress: &'a mut dyn FnMut(ScanProgress),
    ids: IdAllocator,
    excluded: Vec<Vec<String>>,
    inv: Inventory,
    /// Files *and* directories examined. Directories count so that a tree of ten
    /// million empty folders is bounded by the same limit as a tree of files.
    entries_examined: u64,
    enumeration_capped: bool,
}

impl Scanner<'_> {
    fn run(&mut self, roots: &[PathBuf]) -> TtResult<()> {
        // `add_root` canonicalises internally with the same fallback, so the walk and
        // the redactor agree on what each root's prefix is.
        let canonical: Vec<PathBuf> = roots
            .iter()
            .map(|r| fs::canonicalize(r).unwrap_or_else(|_| r.clone()))
            .collect();
        for r in roots {
            let alias = self.redactor.add_root(r);
            self.inv.root_aliases.push(alias);
        }

        let comps: Vec<Vec<String>> = canonical.iter().map(|p| components_ci(p)).collect();
        for (i, root) in canonical.iter().enumerate() {
            // A root that lies inside another selected root is walked once, via the
            // outer root. Walking it twice would emit two artifact records for one
            // file, and `alias_path` would give both the same alias anyway.
            if covered_by_another_root(i, &comps) {
                continue;
            }
            self.walk_root(root)?;
        }
        self.emit_progress();
        Ok(())
    }

    fn walk_root(&mut self, root: &Path) -> TtResult<()> {
        self.check_cancel()?;
        let alias = self.redactor.alias_path(root);

        if self.is_excluded(root) {
            self.record_excluded(alias);
            return Ok(());
        }
        let md = match fs::symlink_metadata(root) {
            Ok(m) => m,
            Err(e) => {
                self.record_unreachable(alias, e.kind(), 0, None, ArtifactType::Unrecognised);
                return Ok(());
            }
        };
        if is_reparse_point(&md) {
            self.record_reparse(alias);
            return Ok(());
        }
        if !md.is_dir() {
            // A single selected file is a legitimate scope.
            return self.visit_file(root, alias, &md);
        }
        if self.opts.limits.max_traversal_depth == 0 {
            self.note_depth_limit(alias);
            return Ok(());
        }

        let mut stack: Vec<Frame> = Vec::new();
        match self.read_dir_sorted(root, &alias) {
            Ok(entries) => stack.push(Frame { entries, next: 0, depth: 0 }),
            Err(kind) => {
                self.record_unreachable(alias, kind, 0, None, ArtifactType::Unrecognised);
                return Ok(());
            }
        }

        loop {
            let (path, depth) = {
                let Some(frame) = stack.last_mut() else { break };
                let Some(slot) = frame.entries.get_mut(frame.next) else {
                    stack.pop();
                    continue;
                };
                // Taking the entry keeps peak memory to one copy of each pending path.
                let path = std::mem::take(slot);
                frame.next = frame.next.saturating_add(1);
                (path, frame.depth.saturating_add(1))
            };

            self.check_cancel()?;
            if self.entries_examined >= self.opts.limits.max_files_enumerated {
                let alias = self.redactor.alias_path(&path);
                self.note_enumeration_limit(alias);
                break;
            }
            self.entries_examined = self.entries_examined.saturating_add(1);

            let alias = self.redactor.alias_path(&path);
            if self.is_excluded(&path) {
                self.record_excluded(alias);
                continue;
            }
            let md = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    self.record_unreachable(alias, e.kind(), 0, None, ArtifactType::Unrecognised);
                    continue;
                }
            };
            if is_reparse_point(&md) {
                self.record_reparse(alias);
                continue;
            }
            if md.is_dir() {
                if depth >= self.opts.limits.max_traversal_depth {
                    self.note_depth_limit(alias);
                    continue;
                }
                match self.read_dir_sorted(&path, &alias) {
                    Ok(entries) => stack.push(Frame { entries, next: 0, depth }),
                    Err(kind) => {
                        self.record_unreachable(
                            alias,
                            kind,
                            0,
                            None,
                            ArtifactType::Unrecognised,
                        );
                    }
                }
                continue;
            }
            self.visit_file(&path, alias, &md)?;
        }
        Ok(())
    }

    /// List a directory in file-name order.
    ///
    /// The listing is capped by the remaining enumeration budget so that a directory
    /// with a hostile number of entries cannot be materialised in memory before the
    /// limit is consulted.
    fn read_dir_sorted(&mut self, dir: &Path, alias: &str) -> Result<Vec<PathBuf>, ErrorKind> {
        let rd = fs::read_dir(dir).map_err(|e| e.kind())?;
        let budget = self
            .opts
            .limits
            .max_files_enumerated
            .saturating_sub(self.entries_examined);

        let mut named: Vec<(Vec<u8>, PathBuf)> = Vec::new();
        let mut truncated = false;
        for entry in rd {
            if named.len() as u64 >= budget {
                truncated = true;
                break;
            }
            match entry {
                Ok(e) => {
                    // Raw OS bytes, so two names that differ only outside the Unicode
                    // subset still sort deterministically and never collide.
                    let key = e.file_name().as_encoded_bytes().to_vec();
                    named.push((key, e.path()));
                }
                Err(e) => {
                    // One unreadable entry must not discard the ones already listed,
                    // but it must not vanish silently either.
                    let detail = format!("directory entry not listed: {:?}", e.kind());
                    self.note("TT-INV-006", alias.to_string(), detail);
                }
            }
        }
        if truncated {
            self.note_enumeration_limit(alias.to_string());
        }
        named.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        Ok(named.into_iter().map(|(_, p)| p).collect())
    }

    /// Read a bounded prefix, classify it, hash it, and check whether it moved under
    /// the scanner's feet.
    fn visit_file(&mut self, path: &Path, alias: String, md: &Metadata) -> TtResult<()> {
        let size_before = md.len();
        let mtime_before = mtime_of(md);

        let head = match self.read_head(path) {
            Ok(h) => h,
            Err(kind) => {
                self.record_unreachable(
                    alias,
                    kind,
                    size_before,
                    mtime_before,
                    ArtifactType::Unrecognised,
                );
                return Ok(());
            }
        };
        let artifact_type = (self.classify)(path, &head);

        if !self.opts.hash_files {
            let id = self.ids.artifact();
            self.push_record(
                ArtifactRecord {
                    artifact_id: id,
                    path_alias: alias,
                    artifact_type,
                    size_bytes: size_before,
                    sha256: None,
                    hash_scope: HashScope::None,
                    parser: None,
                    parser_version: 0,
                    read_status: ReadStatus::NotHashed,
                    changed_during_scan: false,
                    mtime: mtime_before,
                },
                0,
            );
            return Ok(());
        }

        let hashed = match hash_file(path, self.opts.limits.per_file_hash_budget_bytes, self.cancel)
        {
            Ok(h) => h,
            Err(e) => {
                // `hash_file` reports cancellation as an IO error; only the cancel
                // flag itself distinguishes it from a genuine read failure.
                self.check_cancel()?;
                let kind = match e {
                    TtError::Io { .. } => ErrorKind::Other,
                    _ => ErrorKind::InvalidData,
                };
                self.record_unreachable(alias, kind, size_before, mtime_before, artifact_type);
                return Ok(());
            }
        };

        // (len, mtime) before versus after. A file that grew, shrank or was rewritten
        // while it was being read has a digest that belongs to no single version of
        // the file, and saying so is the whole point of the check.
        let changed = match fs::symlink_metadata(path) {
            Ok(after) => after.len() != size_before || mtime_of(&after) != mtime_before,
            Err(_) => true,
        };

        let head_only = matches!(hashed.scope, HashScope::HeadOnly { .. });
        let read_status = if changed {
            ReadStatus::Changed
        } else if head_only {
            ReadStatus::TooLarge
        } else {
            ReadStatus::Ok
        };

        if changed {
            self.note(
                "TT-INV-004",
                alias.clone(),
                "size or modification time differed before and after hashing; \
                 digest covers no single version of the file"
                    .to_string(),
            );
        }
        if head_only {
            let detail = format!(
                "per_file_hash_budget_bytes reached at {} of {} bytes; digest covers the head only",
                hashed.bytes_hashed, size_before
            );
            self.note("TT-INV-005", alias.clone(), detail);
        }

        let id = self.ids.artifact();
        let bytes_hashed = hashed.bytes_hashed;
        self.push_record(
            ArtifactRecord {
                artifact_id: id,
                path_alias: alias,
                artifact_type,
                size_bytes: size_before,
                sha256: Some(hashed.digest),
                hash_scope: hashed.scope,
                parser: None,
                parser_version: 0,
                read_status,
                changed_during_scan: changed,
                mtime: mtime_before,
            },
            bytes_hashed,
        );
        Ok(())
    }

    /// Read at most [`MAX_HEAD_BYTES`] for classification. Never more, whatever the
    /// caller configured: a sniff that grows into a read is how a "metadata only"
    /// tool starts loading models.
    fn read_head(&self, path: &Path) -> Result<Vec<u8>, ErrorKind> {
        let want = self.opts.head_bytes.min(MAX_HEAD_BYTES);
        if want == 0 {
            return Ok(Vec::new());
        }
        let mut f = File::open(path).map_err(|e| e.kind())?;
        let mut buf = vec![0u8; want];
        let mut filled: usize = 0;
        while filled < want {
            let Some(rest) = buf.get_mut(filled..) else { break };
            match f.read(rest) {
                Ok(0) => break,
                Ok(n) => filled = filled.saturating_add(n).min(want),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.kind()),
            }
        }
        buf.truncate(filled);
        Ok(buf)
    }

    // -----------------------------------------------------------------------
    // Records and notes
    // -----------------------------------------------------------------------

    fn push_record(&mut self, rec: ArtifactRecord, bytes_hashed: u64) {
        self.inv.files_enumerated = self.inv.files_enumerated.saturating_add(1);
        self.inv.bytes_enumerated = self.inv.bytes_enumerated.saturating_add(rec.size_bytes);
        if rec.sha256.is_some() {
            self.inv.files_hashed = self.inv.files_hashed.saturating_add(1);
            self.inv.bytes_hashed = self.inv.bytes_hashed.saturating_add(bytes_hashed);
        }
        self.inv.artifacts.push(rec);
        self.emit_progress();
    }

    /// A path the submitter excluded. It stays in the manifest: the vendor may
    /// withhold a source, but the fact that a source was withheld is not removable.
    fn record_excluded(&mut self, alias: String) {
        self.redactor.note_submitter_exclusion();
        self.note(
            "TT-PRIV-004",
            alias.clone(),
            "not enumerated: excluded from the selected scope by the submitter".to_string(),
        );
        let id = self.ids.artifact();
        self.push_record(
            ArtifactRecord {
                artifact_id: id,
                path_alias: alias,
                artifact_type: ArtifactType::Unrecognised,
                // Never stat an excluded path: the size and timestamp of a withheld
                // file are themselves information the submitter chose to withhold.
                size_bytes: 0,
                sha256: None,
                hash_scope: HashScope::None,
                parser: None,
                parser_version: 0,
                read_status: ReadStatus::SkippedBySubmitter,
                changed_during_scan: false,
                mtime: None,
            },
            0,
        );
    }

    fn record_reparse(&mut self, alias: String) {
        self.note(
            "TT-INV-003",
            alias.clone(),
            "reparse point not traversed; the target is outside the enumerated tree"
                .to_string(),
        );
        let id = self.ids.artifact();
        self.push_record(
            ArtifactRecord {
                artifact_id: id,
                path_alias: alias,
                artifact_type: ArtifactType::Unrecognised,
                // The length of a reparse point describes the link, not the target,
                // and reporting it would imply the target was measured.
                size_bytes: 0,
                sha256: None,
                hash_scope: HashScope::None,
                parser: None,
                parser_version: 0,
                read_status: ReadStatus::SkippedReparsePoint,
                changed_during_scan: false,
                mtime: None,
            },
            0,
        );
    }

    fn record_unreachable(
        &mut self,
        alias: String,
        kind: ErrorKind,
        size_bytes: u64,
        mtime: Option<Timestamp>,
        artifact_type: ArtifactType,
    ) {
        let (read_status, rule_id) = io_outcome(kind);
        self.note(rule_id, alias.clone(), format!("not read: {kind:?}"));
        let id = self.ids.artifact();
        self.push_record(
            ArtifactRecord {
                artifact_id: id,
                path_alias: alias,
                artifact_type,
                size_bytes,
                sha256: None,
                hash_scope: HashScope::None,
                parser: None,
                parser_version: 0,
                read_status,
                changed_during_scan: false,
                mtime,
            },
            0,
        );
    }

    fn note_depth_limit(&mut self, alias: String) {
        let detail = format!(
            "{DETAIL_DEPTH} of {} reached; this subtree was not descended",
            self.opts.limits.max_traversal_depth
        );
        self.note("TT-INV-006", alias, detail);
    }

    fn note_enumeration_limit(&mut self, alias: String) {
        // One note per scan: repeating it once per directory would bury every other
        // limitation in the report.
        if self.enumeration_capped {
            return;
        }
        self.enumeration_capped = true;
        let detail = format!(
            "{DETAIL_FILES} of {} reached; entries beyond it were not enumerated",
            self.opts.limits.max_files_enumerated
        );
        self.note("TT-INV-006", alias, detail);
    }

    fn note(&mut self, rule_id: &'static str, path_alias: String, detail: String) {
        self.inv.coverage.push(CoverageNote { rule_id, path_alias, detail });
    }

    fn emit_progress(&mut self) {
        let p = ScanProgress {
            files_enumerated: self.inv.files_enumerated,
            bytes_enumerated: self.inv.bytes_enumerated,
            bytes_hashed: self.inv.bytes_hashed,
        };
        (self.progress)(p);
    }

    fn check_cancel(&self) -> TtResult<()> {
        if (self.cancel)() {
            return Err(TtError::io("cancelled"));
        }
        Ok(())
    }

    fn is_excluded(&self, path: &Path) -> bool {
        if self.excluded.is_empty() {
            return false;
        }
        let p = components_ci(path);
        self.excluded.iter().any(|e| is_prefix_of(e, &p))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an IO failure onto a read status and the rule that reports it.
///
/// `TT-INV-002` is reserved for the permission case it names. Everything else — a
/// path that vanished, a name the filesystem would not accept, a path too long —
/// reports under `TT-INV-006`, the catalogue's other "the scanner could not reach
/// this path" limitation, with the concrete kind in the detail text.
fn io_outcome(kind: ErrorKind) -> (ReadStatus, &'static str) {
    match kind {
        ErrorKind::PermissionDenied => (ReadStatus::AccessDenied, "TT-INV-002"),
        _ => (ReadStatus::IoError, "TT-INV-006"),
    }
}

#[cfg(windows)]
fn is_reparse_point(md: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Junctions and mount points have no portable analogue, so elsewhere the symlink
/// bit is the whole test.
#[cfg(not(windows))]
fn is_reparse_point(md: &Metadata) -> bool {
    md.file_type().is_symlink()
}

fn mtime_of(md: &Metadata) -> Option<Timestamp> {
    let t = md.modified().ok()?;
    Some(match t.duration_since(UNIX_EPOCH) {
        Ok(d) => Timestamp(i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        Err(e) => match i64::try_from(e.duration().as_secs()) {
            Ok(v) => Timestamp(-v),
            Err(_) => Timestamp(i64::MIN),
        },
    })
}

/// Lower-cased path components, with the Windows verbatim prefix normalised away so
/// that `\\?\C:\x` and `C:\x` compare equal.
///
/// `.` and `..` are kept literally rather than resolved: silently collapsing them
/// would let a mis-specified exclusion match a path the submitter did not name.
fn components_ci(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            Component::Prefix(pf) => Some(normalise_prefix(&pf.as_os_str().to_string_lossy())),
            Component::RootDir => Some(String::new()),
            Component::CurDir => Some(".".to_string()),
            Component::ParentDir => Some("..".to_string()),
        })
        .collect()
}

fn normalise_prefix(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\\?\unc\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = lower.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    lower
}

fn is_prefix_of(prefix: &[String], path: &[String]) -> bool {
    if prefix.is_empty() || prefix.len() > path.len() {
        return false;
    }
    prefix.iter().zip(path.iter()).all(|(a, b)| a == b)
}

/// True when root `i` is the same as an earlier root, or lies strictly inside any
/// other root, and therefore does not need its own walk.
fn covered_by_another_root(i: usize, comps: &[Vec<String>]) -> bool {
    let Some(mine) = comps.get(i) else { return true };
    if mine.is_empty() {
        return false;
    }
    for (j, other) in comps.iter().enumerate() {
        if j == i || other.is_empty() {
            continue;
        }
        if other.len() == mine.len() && is_prefix_of(other, mine) {
            // An exact duplicate: keep the first occurrence only.
            if j < i {
                return true;
            }
        } else if other.len() < mine.len() && is_prefix_of(other, mine) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tt_core::hash::Digest;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// A throwaway tree under the system temp directory. Each test gets its own so a
    /// failed assertion in one cannot leave state that breaks another.
    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new(tag: &str) -> TempTree {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!(
                "tt-inv-{}-{}-{}",
                std::process::id(),
                tag,
                n
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("create temp root");
            TempTree { root }
        }

        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(&p).expect("create dir");
            p
        }

        fn file(&self, rel: &str, bytes: &[u8]) -> PathBuf {
            let p = self.root.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).expect("create parent");
            }
            fs::write(&p, bytes).expect("write file");
            p
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn unrecognised(_p: &Path, _h: &[u8]) -> ArtifactType {
        ArtifactType::Unrecognised
    }

    fn never() -> bool {
        false
    }

    fn run_with(roots: &[PathBuf], opts: &ScanOptions) -> (Inventory, Redactor) {
        let mut redactor = Redactor::new();
        let inv = scan(roots, &mut redactor, opts, &unrecognised, &never, &mut |_| {})
            .expect("scan should not fail");
        (inv, redactor)
    }

    fn run(root: &Path) -> (Inventory, Redactor) {
        run_with(&[root.to_path_buf()], &ScanOptions::default())
    }

    fn aliases(inv: &Inventory) -> Vec<String> {
        inv.artifacts.iter().map(|a| a.path_alias.clone()).collect()
    }

    fn has_note(inv: &Inventory, rule_id: &str) -> bool {
        inv.coverage.iter().any(|c| c.rule_id == rule_id)
    }

    // -- basic traversal ---------------------------------------------------

    #[test]
    fn nested_tree_is_enumerated_hashed_and_aliased() {
        let t = TempTree::new("nested");
        t.file("b.txt", b"beta");
        t.file("a.txt", b"alpha");
        t.file("sub/inner.txt", b"inner-bytes");
        t.dir("sub/empty");

        let (inv, _r) = run(&t.root);

        assert_eq!(inv.files_enumerated, 3);
        assert_eq!(inv.files_hashed, 3);
        assert_eq!(inv.bytes_enumerated, 4 + 5 + 11);
        assert_eq!(inv.bytes_hashed, 4 + 5 + 11);
        assert_eq!(inv.root_aliases, vec!["ROOT1".to_string()]);
        assert_eq!(inv.coverage_status, CoverageStatus::Complete);
        assert!(inv.coverage.is_empty(), "clean tree needs no notes: {:?}", inv.coverage);

        assert_eq!(
            aliases(&inv),
            vec!["ROOT1/a.txt", "ROOT1/b.txt", "ROOT1/sub/inner.txt"]
        );
        let a = inv.artifacts.first().expect("first artifact");
        assert_eq!(a.artifact_id, "A-0001");
        assert_eq!(a.sha256, Some(Digest::of(b"alpha")));
        assert_eq!(a.hash_scope, HashScope::Full);
        assert_eq!(a.read_status, ReadStatus::Ok);
        assert!(!a.changed_during_scan);
        assert!(a.mtime.is_some());
    }

    #[test]
    fn paths_never_appear_raw_in_output() {
        let t = TempTree::new("noraw");
        t.file("deep/nested/secret-name.bin", b"x");
        let (inv, _r) = run(&t.root);

        let raw = t.root.to_string_lossy().to_string();
        for a in &inv.artifacts {
            assert!(a.path_alias.starts_with("ROOT1"), "alias {}", a.path_alias);
            assert!(!a.path_alias.contains(&raw));
            assert!(!a.path_alias.contains(':'), "drive letter leaked: {}", a.path_alias);
        }
        for c in &inv.coverage {
            assert!(!c.detail.contains(&raw));
            assert!(!c.path_alias.contains(&raw));
        }
    }

    #[test]
    fn two_scans_of_one_tree_are_identical() {
        let t = TempTree::new("determinism");
        // Deliberately created out of name order.
        for name in ["z.txt", "m.txt", "a.txt", "M.txt", "0.txt"] {
            t.file(name, name.as_bytes());
        }
        t.file("sub/z.txt", b"zz");
        t.file("sub/a.txt", b"aa");
        t.file("another/q.txt", b"qq");

        let (first, _r1) = run(&t.root);
        let (second, _r2) = run(&t.root);

        assert_eq!(first.artifacts.len(), second.artifacts.len());
        assert_eq!(first.artifacts, second.artifacts, "records must be byte-identical");
        assert_eq!(first.coverage, second.coverage);
        assert_eq!(first.files_enumerated, second.files_enumerated);
        assert_eq!(first.bytes_hashed, second.bytes_hashed);

        // Ordering is by name, so ids are stable rather than incidental.
        let names: Vec<String> = aliases(&first);
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names.len(), sorted.len());
        assert!(names.contains(&"ROOT1/a.txt".to_string()));
    }

    #[test]
    fn artifact_ids_are_sequential_in_traversal_order() {
        let t = TempTree::new("ids");
        t.file("c.txt", b"c");
        t.file("a.txt", b"a");
        t.file("b.txt", b"b");
        let (inv, _r) = run(&t.root);
        let ids: Vec<&str> = inv.artifacts.iter().map(|a| a.artifact_id.as_str()).collect();
        assert_eq!(ids, vec!["A-0001", "A-0002", "A-0003"]);
        assert_eq!(aliases(&inv), vec!["ROOT1/a.txt", "ROOT1/b.txt", "ROOT1/c.txt"]);
    }

    #[test]
    fn a_single_file_is_a_valid_root() {
        let t = TempTree::new("fileroot");
        let f = t.file("only.bin", b"payload");
        let (inv, _r) = run_with(&[f], &ScanOptions::default());
        assert_eq!(inv.files_enumerated, 1);
        assert_eq!(inv.artifacts.first().map(|a| a.path_alias.as_str()), Some("ROOT1"));
        assert_eq!(inv.artifacts.first().and_then(|a| a.sha256), Some(Digest::of(b"payload")));
    }

    // -- limits ------------------------------------------------------------

    #[test]
    fn depth_limit_stops_descent_and_is_recorded() {
        let t = TempTree::new("depth");
        t.file("top.txt", b"0");
        t.file("a/one.txt", b"1");
        t.file("a/b/two.txt", b"2");
        t.file("a/b/c/three.txt", b"3");

        let mut opts = ScanOptions::default();
        opts.limits.max_traversal_depth = 2;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);

        let a = aliases(&inv);
        assert!(a.contains(&"ROOT1/top.txt".to_string()));
        assert!(a.contains(&"ROOT1/a/one.txt".to_string()));
        assert!(
            !a.iter().any(|x| x.contains("two.txt") || x.contains("three.txt")),
            "descended past the limit: {a:?}"
        );
        assert!(has_note(&inv, "TT-INV-006"));
        assert!(inv.coverage.iter().any(|c| c.detail.contains(DETAIL_DEPTH)));
        assert_eq!(inv.coverage_status, CoverageStatus::Partial);
    }

    #[test]
    fn depth_limit_of_zero_enumerates_nothing() {
        let t = TempTree::new("depth0");
        t.file("top.txt", b"0");
        let mut opts = ScanOptions::default();
        opts.limits.max_traversal_depth = 0;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);
        assert_eq!(inv.files_enumerated, 0);
        assert!(inv.coverage.iter().any(|c| c.detail.contains(DETAIL_DEPTH)));
        assert_eq!(inv.coverage_status, CoverageStatus::Minimal);
    }

    #[test]
    fn file_count_limit_stops_enumeration_and_is_recorded() {
        let t = TempTree::new("count");
        for i in 0..10 {
            t.file(&format!("f{i}.txt"), b"x");
        }
        let mut opts = ScanOptions::default();
        opts.limits.max_files_enumerated = 3;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);

        assert_eq!(inv.files_enumerated, 3, "hard cap must hold");
        assert_eq!(inv.artifacts.len(), 3);
        assert!(inv.coverage.iter().any(|c| c.detail.contains(DETAIL_FILES)));
        assert_eq!(inv.coverage_status, CoverageStatus::Partial);
    }

    #[test]
    fn enumeration_limit_is_noted_once_not_per_directory() {
        let t = TempTree::new("count-once");
        for d in 0..4 {
            for i in 0..4 {
                t.file(&format!("d{d}/f{i}.txt"), b"x");
            }
        }
        let mut opts = ScanOptions::default();
        opts.limits.max_files_enumerated = 5;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);
        let capped = inv
            .coverage
            .iter()
            .filter(|c| c.detail.contains(DETAIL_FILES))
            .count();
        assert_eq!(capped, 1, "one note, not a flood: {:?}", inv.coverage);
    }

    #[test]
    fn file_over_hash_budget_is_head_only() {
        let t = TempTree::new("budget");
        let body: Vec<u8> = (0u8..64).collect();
        t.file("big.bin", &body);

        let mut opts = ScanOptions::default();
        opts.limits.per_file_hash_budget_bytes = 16;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);

        let a = inv.artifacts.first().expect("one artifact");
        assert_eq!(a.hash_scope, HashScope::HeadOnly { bytes: 16 });
        assert_eq!(a.read_status, ReadStatus::TooLarge);
        assert_eq!(a.size_bytes, 64);
        assert_eq!(a.sha256, Some(Digest::of(&body[..16])));
        assert_eq!(inv.bytes_hashed, 16);
        assert!(has_note(&inv, "TT-INV-005"));
        assert_eq!(inv.coverage_status, CoverageStatus::Partial);
    }

    #[test]
    fn file_exactly_at_hash_budget_is_still_full() {
        let t = TempTree::new("budget-exact");
        t.file("exact.bin", &[7u8; 16]);
        let mut opts = ScanOptions::default();
        opts.limits.per_file_hash_budget_bytes = 16;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);
        let a = inv.artifacts.first().expect("one artifact");
        assert_eq!(a.hash_scope, HashScope::Full);
        assert_eq!(a.read_status, ReadStatus::Ok);
        assert!(!has_note(&inv, "TT-INV-005"));
    }

    // -- exclusions --------------------------------------------------------

    #[test]
    fn excluded_subtree_is_listed_but_never_read() {
        let t = TempTree::new("excl");
        t.file("keep/a.txt", b"keep");
        t.file("private/b.txt", b"secret-bytes");
        t.file("private/deeper/c.txt", b"more");

        let mut opts = ScanOptions::default();
        opts.excluded = vec![t.root.join("private")];
        let (inv, redactor) = run_with(&[t.root.clone()], &opts);

        let a = aliases(&inv);
        assert!(a.contains(&"ROOT1/keep/a.txt".to_string()));
        assert!(a.contains(&"ROOT1/private".to_string()), "exclusion must stay visible: {a:?}");
        assert!(
            !a.iter().any(|x| x.contains("b.txt") || x.contains("c.txt")),
            "excluded content was enumerated: {a:?}"
        );

        let rec = inv
            .artifacts
            .iter()
            .find(|r| r.path_alias == "ROOT1/private")
            .expect("excluded record");
        assert_eq!(rec.read_status, ReadStatus::SkippedBySubmitter);
        assert_eq!(rec.sha256, None);
        assert_eq!(rec.size_bytes, 0, "a withheld file's size is also withheld");
        assert!(has_note(&inv, "TT-PRIV-004"));
        assert!(
            redactor.ledger().iter().any(|e| e.rule == "TT-PRIV-004" && e.count == 1),
            "ledger: {:?}",
            redactor.ledger()
        );
    }

    #[test]
    fn exclusion_matches_whole_components_only() {
        let t = TempTree::new("excl-prefix");
        t.file("priv/x.txt", b"x");
        t.file("private/y.txt", b"y");

        let mut opts = ScanOptions::default();
        opts.excluded = vec![t.root.join("priv")];
        let (inv, _r) = run_with(&[t.root.clone()], &opts);

        let a = aliases(&inv);
        assert!(
            a.contains(&"ROOT1/private/y.txt".to_string()),
            "a sibling sharing a name prefix must not be excluded: {a:?}"
        );
        assert!(!a.iter().any(|x| x.contains("x.txt")));
    }

    #[test]
    fn exclusion_is_case_insensitive() {
        let t = TempTree::new("excl-case");
        t.file("Private/b.txt", b"secret");
        let mut opts = ScanOptions::default();
        opts.excluded = vec![t.root.join("PRIVATE")];
        let (inv, _r) = run_with(&[t.root.clone()], &opts);
        assert!(!aliases(&inv).iter().any(|x| x.contains("b.txt")));
    }

    #[test]
    fn an_excluded_root_is_still_listed() {
        let t = TempTree::new("excl-root");
        t.file("a.txt", b"a");
        let mut opts = ScanOptions::default();
        opts.excluded = vec![t.root.clone()];
        let (inv, _r) = run_with(&[t.root.clone()], &opts);
        assert_eq!(inv.artifacts.len(), 1);
        assert_eq!(
            inv.artifacts.first().map(|a| a.read_status),
            Some(ReadStatus::SkippedBySubmitter)
        );
        assert_eq!(inv.coverage_status, CoverageStatus::Minimal);
    }

    // -- degenerate and hostile roots --------------------------------------

    #[test]
    fn empty_root_yields_minimal_coverage() {
        let t = TempTree::new("empty");
        let (inv, _r) = run(&t.root);
        assert!(inv.artifacts.is_empty());
        assert_eq!(inv.files_enumerated, 0);
        assert_eq!(inv.root_aliases, vec!["ROOT1".to_string()]);
        assert_eq!(inv.coverage_status, CoverageStatus::Minimal);
    }

    #[test]
    fn no_roots_at_all_is_not_an_error() {
        let mut redactor = Redactor::new();
        let inv = scan(
            &[],
            &mut redactor,
            &ScanOptions::default(),
            &unrecognised,
            &never,
            &mut |_| {},
        )
        .expect("empty scope is a valid scope");
        assert!(inv.artifacts.is_empty());
        assert!(inv.root_aliases.is_empty());
        assert_eq!(inv.coverage_status, CoverageStatus::Minimal);
    }

    #[test]
    fn nonexistent_root_is_recorded_not_fatal() {
        let t = TempTree::new("missing");
        let ghost = t.root.join("does-not-exist");
        let (inv, _r) = run_with(&[ghost], &ScanOptions::default());

        assert_eq!(inv.artifacts.len(), 1);
        let a = inv.artifacts.first().expect("record");
        assert_eq!(a.read_status, ReadStatus::IoError);
        assert_eq!(a.path_alias, "ROOT1", "a missing root must still be aliased");
        assert!(has_note(&inv, "TT-INV-006"));
        assert_eq!(inv.coverage_status, CoverageStatus::Minimal);
    }

    #[test]
    fn nested_roots_do_not_double_count() {
        let t = TempTree::new("nested-roots");
        t.file("inner/a.txt", b"a");
        t.file("outer.txt", b"o");
        let roots = vec![t.root.clone(), t.root.join("inner")];
        let (inv, _r) = run_with(&roots, &ScanOptions::default());

        assert_eq!(inv.root_aliases.len(), 2, "both selections are still disclosed");
        assert_eq!(inv.files_enumerated, 2, "each file is recorded once");
        let a = aliases(&inv);
        assert_eq!(a.iter().filter(|x| x.ends_with("a.txt")).count(), 1);
    }

    #[test]
    fn duplicate_roots_are_walked_once() {
        let t = TempTree::new("dup-roots");
        t.file("a.txt", b"a");
        let roots = vec![t.root.clone(), t.root.clone()];
        let (inv, _r) = run_with(&roots, &ScanOptions::default());
        assert_eq!(inv.files_enumerated, 1);
        assert_eq!(inv.root_aliases, vec!["ROOT1".to_string(), "ROOT2".to_string()]);
    }

    // -- files that move under the scanner ---------------------------------

    #[test]
    fn file_changed_during_scan_is_flagged() {
        let t = TempTree::new("changed");
        let target = t.file("moving.bin", b"original");
        t.file("zzz-other.bin", b"stable");

        // `classify` runs after the pre-hash stat and before hashing, which is
        // exactly the window the change detector exists to cover.
        // Compare on the file name, not on a path the test constructed: `scan`
        // canonicalises its roots, and on Windows that yields a verbatim `\?\`
        // path which never compares equal to the plain one.
        let victim = target.file_name().expect("file name").to_os_string();
        let classify = move |p: &Path, _h: &[u8]| -> ArtifactType {
            if p.file_name() == Some(victim.as_os_str()) {
                use std::io::Write as _;
                if let Ok(mut f) = fs::OpenOptions::new().append(true).open(p) {
                    let _ = f.write_all(b"-appended-while-scanning");
                }
            }
            ArtifactType::Unrecognised
        };

        let mut redactor = Redactor::new();
        let inv = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &classify,
            &never,
            &mut |_| {},
        )
        .expect("scan");

        let rec = inv
            .artifacts
            .iter()
            .find(|a| a.path_alias.ends_with("moving.bin"))
            .expect("record for the moving file");
        assert!(rec.changed_during_scan, "growth during hashing must be visible");
        assert_eq!(rec.read_status, ReadStatus::Changed);
        assert!(has_note(&inv, "TT-INV-004"));

        let stable = inv
            .artifacts
            .iter()
            .find(|a| a.path_alias.ends_with("zzz-other.bin"))
            .expect("record for the stable file");
        assert!(!stable.changed_during_scan, "one unstable file must not taint others");
        assert_eq!(stable.read_status, ReadStatus::Ok);
    }

    #[test]
    fn file_deleted_mid_walk_is_recorded_not_fatal() {
        let t = TempTree::new("vanish");
        t.file("a.txt", b"a");
        let doomed = t.file("b.txt", b"b");

        let victim = doomed.clone();
        let classify = move |p: &Path, _h: &[u8]| -> ArtifactType {
            if p.file_name().map(|n| n == "a.txt").unwrap_or(false) {
                let _ = fs::remove_file(&victim);
            }
            ArtifactType::Unrecognised
        };

        let mut redactor = Redactor::new();
        let inv = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &classify,
            &never,
            &mut |_| {},
        )
        .expect("a vanished file is a coverage limitation, not a crash");

        assert_eq!(inv.artifacts.len(), 2);
        assert!(inv.artifacts.iter().any(|a| a.read_status == ReadStatus::IoError));
        assert!(has_note(&inv, "TT-INV-006"));
    }

    // -- cancellation, progress, classification ----------------------------

    #[test]
    fn cancellation_before_any_work_returns_an_error() {
        let t = TempTree::new("cancel-early");
        t.file("a.txt", b"a");
        let mut redactor = Redactor::new();
        let err = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &unrecognised,
            &|| true,
            &mut |_| {},
        )
        .expect_err("cancellation must not yield an inventory");
        assert_eq!(err, TtError::io("cancelled"));
    }

    #[test]
    fn cancellation_mid_walk_returns_an_error() {
        let t = TempTree::new("cancel-mid");
        for i in 0..8 {
            t.file(&format!("f{i}.txt"), b"xxxx");
        }
        let polls = Cell::new(0u32);
        let cancel = || {
            let n = polls.get().saturating_add(1);
            polls.set(n);
            n > 3
        };
        let mut redactor = Redactor::new();
        let err = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &unrecognised,
            &cancel,
            &mut |_| {},
        )
        .expect_err("cancellation must not yield a partial inventory");
        assert_eq!(err, TtError::io("cancelled"));
    }

    #[test]
    fn progress_is_monotonic_and_ends_at_the_totals() {
        let t = TempTree::new("progress");
        t.file("a.txt", b"aaaa");
        t.file("b.txt", b"bb");
        t.file("s/c.txt", b"cccccc");

        let mut seen: Vec<ScanProgress> = Vec::new();
        let mut redactor = Redactor::new();
        let inv = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &unrecognised,
            &never,
            &mut |p| seen.push(p),
        )
        .expect("scan");

        assert!(seen.len() >= 3, "one report per file at least");
        for w in seen.windows(2) {
            let (a, b) = (w[0], w[1]);
            assert!(b.files_enumerated >= a.files_enumerated);
            assert!(b.bytes_enumerated >= a.bytes_enumerated);
            assert!(b.bytes_hashed >= a.bytes_hashed);
        }
        let last = seen.last().copied().expect("at least one report");
        assert_eq!(last.files_enumerated, inv.files_enumerated);
        assert_eq!(last.bytes_enumerated, inv.bytes_enumerated);
        assert_eq!(last.bytes_hashed, inv.bytes_hashed);
        assert_eq!(inv.bytes_enumerated, 12);
    }

    #[test]
    fn classify_sees_a_bounded_head_and_decides_the_type() {
        let t = TempTree::new("classify");
        t.file("cfg.json", b"{\"a\":1}");
        let big = vec![b'Z'; 4096];
        t.file("blob.bin", &big);

        let widest = Cell::new(0usize);
        let classify = |p: &Path, head: &[u8]| -> ArtifactType {
            widest.set(widest.get().max(head.len()));
            if head.first() == Some(&b'{') {
                ArtifactType::GenericJson
            } else if p.extension().map(|e| e == "bin").unwrap_or(false) {
                ArtifactType::OpaqueSerialization
            } else {
                ArtifactType::Unrecognised
            }
        };

        let mut redactor = Redactor::new();
        let inv = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &classify,
            &never,
            &mut |_| {},
        )
        .expect("scan");

        assert!(widest.get() <= MAX_HEAD_BYTES, "head buffer must stay bounded");
        assert_eq!(widest.get(), MAX_HEAD_BYTES);
        let types: Vec<ArtifactType> = inv.artifacts.iter().map(|a| a.artifact_type).collect();
        assert_eq!(
            types,
            vec![ArtifactType::OpaqueSerialization, ArtifactType::GenericJson]
        );
        // The opaque file is hashed and counted, and nothing else.
        let opaque = inv.artifacts.first().expect("blob record");
        assert_eq!(opaque.sha256, Some(Digest::of(&big)));
        assert_eq!(opaque.parser, None);
    }

    #[test]
    fn head_request_larger_than_the_cap_is_clamped() {
        let t = TempTree::new("head-clamp");
        t.file("a.bin", &vec![1u8; 8192]);
        let widest = Cell::new(0usize);
        let classify = |_p: &Path, head: &[u8]| -> ArtifactType {
            widest.set(head.len());
            ArtifactType::Unrecognised
        };
        let mut opts = ScanOptions::default();
        opts.head_bytes = 1_000_000;
        let mut redactor = Redactor::new();
        scan(&[t.root.clone()], &mut redactor, &opts, &classify, &never, &mut |_| {})
            .expect("scan");
        assert_eq!(widest.get(), MAX_HEAD_BYTES);
    }

    #[test]
    fn empty_file_classifies_on_an_empty_head() {
        let t = TempTree::new("emptyfile");
        t.file("zero.bin", b"");
        let saw_empty = Cell::new(false);
        let classify = |_p: &Path, head: &[u8]| -> ArtifactType {
            if head.is_empty() {
                saw_empty.set(true);
            }
            ArtifactType::Unrecognised
        };
        let mut redactor = Redactor::new();
        let inv = scan(
            &[t.root.clone()],
            &mut redactor,
            &ScanOptions::default(),
            &classify,
            &never,
            &mut |_| {},
        )
        .expect("scan");
        assert!(saw_empty.get());
        let a = inv.artifacts.first().expect("record");
        assert_eq!(a.size_bytes, 0);
        assert_eq!(a.sha256, Some(Digest::of(b"")));
        assert_eq!(a.hash_scope, HashScope::Full);
    }

    #[test]
    fn hashing_disabled_marks_every_record_not_hashed() {
        let t = TempTree::new("nohash");
        t.file("a.txt", b"aaaa");
        let mut opts = ScanOptions::default();
        opts.hash_files = false;
        let (inv, _r) = run_with(&[t.root.clone()], &opts);

        let a = inv.artifacts.first().expect("record");
        assert_eq!(a.read_status, ReadStatus::NotHashed);
        assert_eq!(a.sha256, None);
        assert_eq!(a.hash_scope, HashScope::None);
        assert_eq!(inv.files_hashed, 0);
        assert_eq!(inv.bytes_hashed, 0);
        assert_eq!(inv.bytes_enumerated, 4, "sizes are still enumerated");
        assert_eq!(
            inv.coverage_status,
            CoverageStatus::Partial,
            "a metadata-only scan is never complete coverage"
        );
    }

    // -- reparse points ----------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn reparse_point_is_recorded_and_not_followed() {
        let t = TempTree::new("reparse");
        t.file("real/inside.txt", b"inside");
        t.file("plain.txt", b"plain");
        // Creating a symlink needs Developer Mode or elevation. Where the OS refuses,
        // there is nothing to assert, so the test yields rather than reporting a
        // failure it cannot distinguish from a real one.
        let link = t.root.join("link");
        if std::os::windows::fs::symlink_dir(t.root.join("real"), &link).is_err() {
            return;
        }

        let (inv, _r) = run(&t.root);
        let rec = inv
            .artifacts
            .iter()
            .find(|a| a.path_alias == "ROOT1/link")
            .expect("the link itself must be listed");
        assert_eq!(rec.read_status, ReadStatus::SkippedReparsePoint);
        assert_eq!(rec.sha256, None);
        assert!(has_note(&inv, "TT-INV-003"));
        assert_eq!(
            aliases(&inv).iter().filter(|a| a.contains("inside.txt")).count(),
            1,
            "the target is enumerated once, through the real path only"
        );
        assert!(!aliases(&inv).iter().any(|a| a.starts_with("ROOT1/link/")));
    }

    // -- unit level --------------------------------------------------------

    #[test]
    fn io_outcome_reserves_access_denied_for_permissions() {
        assert_eq!(
            io_outcome(ErrorKind::PermissionDenied),
            (ReadStatus::AccessDenied, "TT-INV-002")
        );
        assert_eq!(io_outcome(ErrorKind::NotFound), (ReadStatus::IoError, "TT-INV-006"));
        assert_eq!(
            io_outcome(ErrorKind::InvalidInput),
            (ReadStatus::IoError, "TT-INV-006")
        );
    }

    #[test]
    fn verbatim_prefix_normalises_to_the_plain_form() {
        assert_eq!(
            components_ci(Path::new(r"\\?\C:\Users\x")),
            components_ci(Path::new(r"C:\users\X"))
        );
        assert_eq!(normalise_prefix(r"\\?\UNC\server\share"), r"\\server\share");
    }

    #[test]
    fn prefix_matching_is_component_wise() {
        let priv_ = vec!["c:".to_string(), String::new(), "priv".to_string()];
        let a = vec!["c:".to_string(), String::new(), "priv".to_string(), "x".to_string()];
        let b = vec!["c:".to_string(), String::new(), "private".to_string()];
        assert!(is_prefix_of(&priv_, &a));
        assert!(!is_prefix_of(&priv_, &b));
        assert!(!is_prefix_of(&a, &priv_), "a longer prefix cannot match");
        assert!(!is_prefix_of(&[], &a), "an empty exclusion excludes nothing");
    }

    #[test]
    fn root_coverage_detects_duplicates_and_nesting() {
        let outer = vec!["c:".to_string(), String::new(), "a".to_string()];
        let inner = vec!["c:".to_string(), String::new(), "a".to_string(), "b".to_string()];
        let other = vec!["c:".to_string(), String::new(), "z".to_string()];

        let comps = vec![outer.clone(), inner.clone(), other.clone()];
        assert!(!covered_by_another_root(0, &comps));
        assert!(covered_by_another_root(1, &comps), "inner is inside outer");
        assert!(!covered_by_another_root(2, &comps));

        // Order does not matter: the inner root is skipped either way.
        let comps = vec![inner.clone(), outer.clone()];
        assert!(covered_by_another_root(0, &comps));
        assert!(!covered_by_another_root(1, &comps));

        // Exact duplicates keep the first occurrence only.
        let comps = vec![outer.clone(), outer.clone()];
        assert!(!covered_by_another_root(0, &comps));
        assert!(covered_by_another_root(1, &comps));
    }

    #[test]
    fn coverage_notes_name_scanner_limits_not_vendor_behaviour() {
        // Rule invariant: a `Kind = C` rule describes what the scanner could not do.
        // The prohibited-language list from the frozen vocabulary must never appear.
        const FORBIDDEN: &[&str] = &[
            "lied", "lying", "liar", "fraud", "dishonest", "deceptive", "faked", "scam",
            "certified", "certification", "guarantee", "authentic", "verified true",
        ];
        let t = TempTree::new("language");
        t.file("a/b/c/d/deep.txt", b"x");
        t.file("excluded/x.txt", b"x");
        let mut opts = ScanOptions::default();
        opts.limits.max_traversal_depth = 2;
        opts.limits.per_file_hash_budget_bytes = 0;
        opts.excluded = vec![t.root.join("excluded")];
        let (inv, _r) = run_with(&[t.root.clone()], &opts);

        assert!(!inv.coverage.is_empty());
        for note in &inv.coverage {
            let lower = note.detail.to_ascii_lowercase();
            for bad in FORBIDDEN {
                assert!(!lower.contains(bad), "note {:?} contains {bad}", note.detail);
            }
        }
    }
}
