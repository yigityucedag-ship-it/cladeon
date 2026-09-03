//! Stored-only ZIP writer and hostile-input reader for the `.clade` container.
//!
//! ## Why the writer is boring on purpose
//!
//! Two scans of unchanged evidence must produce byte-identical bundles, so every
//! field that a general ZIP writer would fill from the environment is pinned here:
//! entry order comes from `docs/02-SCHEMAS.md` §7, timestamps are frozen at
//! 1980-01-01 00:00:00 (the earliest instant MS-DOS date fields can express), and
//! version, flag, attribute and extra-field bytes are constants. Nothing is read from
//! the clock, the locale, the filesystem or the process environment.
//!
//! ## Why the reader is paranoid
//!
//! The reader's input is an archive that arrived by email from the party under
//! examination. Its every declared length is a claim, not a fact. So each length is
//! checked against [`BundleLimits`] *and* against the bytes actually present before
//! anything is allocated, the central directory and the local headers must agree
//! field for field, and the archive must end exactly at the end of central directory
//! record with nothing appended.
//!
//! ### The central/local agreement check
//!
//! A ZIP file describes every entry twice. Tools that read the central directory and
//! tools that scan local headers can therefore be shown different files by one
//! archive — the classic way to make a verifier and a human看 disagree. This reader
//! parses both and rejects any disagreement about name, size or CRC rather than
//! preferring one view.

use crate::crc32::crc32;
use crate::{validate_entry_name, Payload};
use cl_core::error::{ClError, ClResult};
use cl_core::limits::BundleLimits;

const LOCAL_SIG: u32 = 0x0403_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

const LOCAL_FIXED: usize = 30;
const CENTRAL_FIXED: usize = 46;
const EOCD_FIXED: usize = 22;

/// MS-DOS date for 1980-01-01: `(year - 1980) << 9 | month << 5 | day`.
const DOS_DATE_EPOCH: u16 = (1 << 5) | 1;
/// MS-DOS time for 00:00:00.
const DOS_TIME_MIDNIGHT: u16 = 0;

/// Upper byte 0 (MS-DOS / FAT), lower byte 20 (PKZIP 2.0). Constant so that the
/// bundle does not carry the identity of the machine that produced it.
const VERSION_MADE_BY: u16 = 20;
/// 1.0 — the version needed for a stored entry with no other feature in use.
const VERSION_NEEDED: u16 = 10;
/// The only compression method this format permits.
const METHOD_STORED: u16 = 0;

fn malformed(at: usize, detail: impl Into<String>) -> ClError {
    ClError::malformed("clade container", at, detail)
}

fn truncated(at: usize) -> ClError {
    malformed(at, "structure runs past the end of the archive")
}

// ---------------------------------------------------------------------------
// Little-endian field readers that cannot panic or overflow
// ---------------------------------------------------------------------------

fn read_u16(bytes: &[u8], off: usize) -> ClResult<u16> {
    let end = off.checked_add(2).ok_or_else(|| truncated(off))?;
    let slice = bytes.get(off..end).ok_or_else(|| truncated(off))?;
    let arr: [u8; 2] = slice.try_into().map_err(|_| truncated(off))?;
    Ok(u16::from_le_bytes(arr))
}

fn read_u32(bytes: &[u8], off: usize) -> ClResult<u32> {
    let end = off.checked_add(4).ok_or_else(|| truncated(off))?;
    let slice = bytes.get(off..end).ok_or_else(|| truncated(off))?;
    let arr: [u8; 4] = slice.try_into().map_err(|_| truncated(off))?;
    Ok(u32::from_le_bytes(arr))
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Serialise `payloads` into a stored-only ZIP.
///
/// Entries are emitted in the fixed schema order regardless of the order they were
/// supplied in, so the same set of payloads always produces the same bytes. Names
/// outside the known set, duplicate names and payloads beyond
/// [`BundleLimits::default`] are rejected: the writer must never produce a bundle the
/// reader would refuse.
pub fn write_archive(payloads: &[Payload]) -> ClResult<Vec<u8>> {
    let limits = BundleLimits::default();
    let ordered = order_payloads(payloads, &limits)?;

    let mut total: u64 = 0;
    for p in &ordered {
        let len = p.bytes.len() as u64;
        if len > limits.max_entry_bytes {
            return Err(ClError::LimitExceeded {
                limit: "bundle_max_entry_bytes",
                value: len,
                max: limits.max_entry_bytes,
            });
        }
        total = total.checked_add(len).ok_or_else(|| ClError::LimitExceeded {
            limit: "bundle_max_total_bytes",
            value: u64::MAX,
            max: limits.max_total_bytes,
        })?;
    }
    if total > limits.max_total_bytes {
        return Err(ClError::LimitExceeded {
            limit: "bundle_max_total_bytes",
            value: total,
            max: limits.max_total_bytes,
        });
    }

    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    for p in &ordered {
        let name = p.name.as_bytes();
        let crc = crc32(&p.bytes);
        let size = u32::try_from(p.bytes.len())
            .map_err(|_| ClError::contract("entry does not fit a 32-bit ZIP size field"))?;
        let name_len = u16::try_from(name.len())
            .map_err(|_| ClError::contract("entry name does not fit a 16-bit length"))?;
        let local_offset = u32::try_from(out.len())
            .map_err(|_| ClError::contract("archive does not fit a 32-bit offset"))?;

        out.extend_from_slice(&LOCAL_SIG.to_le_bytes());
        out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
        out.extend_from_slice(&METHOD_STORED.to_le_bytes());
        out.extend_from_slice(&DOS_TIME_MIDNIGHT.to_le_bytes());
        out.extend_from_slice(&DOS_DATE_EPOCH.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed == uncompressed
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        out.extend_from_slice(name);
        out.extend_from_slice(&p.bytes);

        central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
        central.extend_from_slice(&VERSION_MADE_BY.to_le_bytes());
        central.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&METHOD_STORED.to_le_bytes());
        central.extend_from_slice(&DOS_TIME_MIDNIGHT.to_le_bytes());
        central.extend_from_slice(&DOS_DATE_EPOCH.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        central.extend_from_slice(&0u16.to_le_bytes()); // file comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name);
    }

    let central_offset = u32::try_from(out.len())
        .map_err(|_| ClError::contract("archive does not fit a 32-bit offset"))?;
    let central_size = u32::try_from(central.len())
        .map_err(|_| ClError::contract("central directory does not fit a 32-bit size"))?;
    let count = u16::try_from(ordered.len())
        .map_err(|_| ClError::contract("entry count does not fit a 16-bit field"))?;

    out.extend_from_slice(&central);
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with central directory
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length

    Ok(out)
}

/// Validate names and sort into the frozen schema order.
fn order_payloads<'a>(
    payloads: &'a [Payload],
    limits: &BundleLimits,
) -> ClResult<Vec<&'a Payload>> {
    if payloads.len() > limits.max_entries {
        return Err(ClError::LimitExceeded {
            limit: "bundle_max_entries",
            value: payloads.len() as u64,
            max: limits.max_entries as u64,
        });
    }
    for p in payloads {
        validate_entry_name(&p.name, limits)?;
    }
    let mut ordered = Vec::with_capacity(payloads.len());
    for name in crate::ENTRY_ORDER {
        let mut matches = payloads.iter().filter(|p| p.name == *name);
        if let Some(first) = matches.next() {
            if matches.next().is_some() {
                return Err(ClError::contract(format!("duplicate bundle entry `{name}`")));
            }
            ordered.push(first);
        }
    }
    // Unreachable while `validate_entry_name` enforces the known set, but the
    // invariant is cheap to assert and would otherwise silently drop an entry.
    if ordered.len() != payloads.len() {
        return Err(ClError::contract(
            "payload set contains an entry outside the frozen bundle order".to_string(),
        ));
    }
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// One entry as described by the central directory, before its data is trusted.
struct CentralEntry {
    name: String,
    crc: u32,
    size: u32,
    local_offset: u32,
}

/// Parse a `.clade` archive.
///
/// Every rejection below is deliberate; none of them is a heuristic:
///
/// * compression method other than stored — a compressed entry is refused, never
///   decompressed and then measured;
/// * a name that is empty, duplicated, unknown, over-long, or that contains a path
///   separator, `..`, a leading slash or a drive letter;
/// * a general-purpose flag word other than zero, which in particular refuses bit 3
///   (data descriptor), the mode that moves sizes into a trailer where the two views
///   of the archive can differ;
/// * an extra field anywhere — a second place to declare a length, and where Zip64
///   hides a different one;
/// * any disagreement between central directory and local header;
/// * data that overlaps the central directory or runs past the end of the archive;
/// * a wrong CRC;
/// * trailing bytes after the end of central directory record.
///
/// Entries are returned in central-directory order, which for a bundle this crate
/// wrote is the frozen schema order.
pub fn read_archive(bytes: &[u8], limits: &BundleLimits) -> ClResult<Vec<Payload>> {
    // Bound the whole file before touching it. The stored-only rule means total
    // uncompressed content can never exceed the archive length, so one length check
    // plus a per-entry-overhead allowance covers every allocation below.
    let overhead = (limits.max_entries as u64)
        .saturating_mul((LOCAL_FIXED + CENTRAL_FIXED + 2 * limits.max_name_bytes) as u64)
        .saturating_add(EOCD_FIXED as u64);
    let max_archive = limits.max_total_bytes.saturating_add(overhead);
    if bytes.len() as u64 > max_archive {
        return Err(ClError::LimitExceeded {
            limit: "bundle_max_total_bytes",
            value: bytes.len() as u64,
            max: max_archive,
        });
    }

    let eocd_at = locate_eocd(bytes)?;

    if read_u16(bytes, eocd_at + 4)? != 0 || read_u16(bytes, eocd_at + 6)? != 0 {
        return Err(malformed(eocd_at + 4, "multi-disk archives are not accepted"));
    }
    let on_this_disk = read_u16(bytes, eocd_at + 8)?;
    let total_entries = read_u16(bytes, eocd_at + 10)?;
    if on_this_disk != total_entries {
        return Err(malformed(
            eocd_at + 8,
            "end of central directory disagrees with itself about the entry count",
        ));
    }
    if total_entries as usize > limits.max_entries {
        return Err(ClError::LimitExceeded {
            limit: "bundle_max_entries",
            value: total_entries as u64,
            max: limits.max_entries as u64,
        });
    }
    if read_u16(bytes, eocd_at + 20)? != 0 {
        return Err(malformed(eocd_at + 20, "archive comment is not permitted"));
    }

    let central_size = read_u32(bytes, eocd_at + 12)? as usize;
    let central_offset = read_u32(bytes, eocd_at + 16)? as usize;
    // Where the central directory must begin if nothing is prepended and nothing
    // overlaps. A mismatch means the archive was assembled so that its two views of
    // its own layout disagree.
    let expected_start = eocd_at
        .checked_sub(central_size)
        .ok_or_else(|| malformed(eocd_at + 12, "central directory size overruns the archive"))?;
    if central_offset != expected_start {
        return Err(malformed(
            eocd_at + 16,
            format!(
                "central directory offset {central_offset} does not resolve \
                 (expected {expected_start}); prepended or overlapping data"
            ),
        ));
    }

    let central = read_central_directory(bytes, central_offset, eocd_at, total_entries, limits)?;

    let mut out = Vec::with_capacity(central.len());
    for entry in &central {
        out.push(read_local_entry(bytes, entry, central_offset)?);
    }
    Ok(out)
}

/// The end of central directory record must be the last 22 bytes of the file.
///
/// ZIP permits a trailing comment, and readers therefore scan backwards for the
/// signature. That scan is what lets an archive carry appended data that some tools
/// ignore and others execute, so this reader refuses it: the record is either exactly
/// at the end or the archive is rejected.
fn locate_eocd(bytes: &[u8]) -> ClResult<usize> {
    if bytes.is_empty() {
        return Err(malformed(0, "archive is empty"));
    }
    let at = match bytes.len().checked_sub(EOCD_FIXED) {
        Some(at) => at,
        None => {
            return Err(malformed(
                bytes.len(),
                "archive is too short to contain an end of central directory record",
            ))
        }
    };
    if read_u32(bytes, at)? == EOCD_SIG {
        return Err_ok(at);
    }
    // Distinguish "not a zip" from "a zip with something appended", because the two
    // say different things to a person reading the verification output.
    let sig = EOCD_SIG.to_le_bytes();
    let found = bytes.windows(4).rposition(|w| w == sig);
    match found {
        Some(pos) => Err(malformed(
            pos,
            "trailing data after the end of central directory record",
        )),
        None => Err(malformed(at, "no end of central directory record")),
    }
}

/// Tiny helper so [`locate_eocd`] reads as a single expression chain.
#[allow(non_snake_case)]
fn Err_ok(at: usize) -> ClResult<usize> {
    Ok(at)
}

fn read_central_directory(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: u16,
    limits: &BundleLimits,
) -> ClResult<Vec<CentralEntry>> {
    let mut entries: Vec<CentralEntry> = Vec::with_capacity(count as usize);
    let mut at = start;
    let mut total_bytes: u64 = 0;

    for _ in 0..count {
        if read_u32(bytes, at)? != CENTRAL_SIG {
            return Err(malformed(at, "expected a central directory file header"));
        }
        let flags = read_u16(bytes, at + 8)?;
        if flags != 0 {
            return Err(malformed(
                at + 8,
                format!("general purpose flags {flags:#06x} are not permitted"),
            ));
        }
        let method = read_u16(bytes, at + 10)?;
        if method != METHOD_STORED {
            return Err(malformed(
                at + 10,
                format!(
                    "entry uses compression method {method}; \
                     .clade is stored-only and a compressed entry is rejected, not decompressed"
                ),
            ));
        }
        let crc = read_u32(bytes, at + 16)?;
        let compressed = read_u32(bytes, at + 20)?;
        let uncompressed = read_u32(bytes, at + 24)?;
        if compressed != uncompressed {
            return Err(malformed(
                at + 20,
                "stored entry declares different compressed and uncompressed sizes",
            ));
        }
        if uncompressed as u64 > limits.max_entry_bytes {
            return Err(ClError::LimitExceeded {
                limit: "bundle_max_entry_bytes",
                value: uncompressed as u64,
                max: limits.max_entry_bytes,
            });
        }
        total_bytes = total_bytes.saturating_add(uncompressed as u64);
        if total_bytes > limits.max_total_bytes {
            return Err(ClError::LimitExceeded {
                limit: "bundle_max_total_bytes",
                value: total_bytes,
                max: limits.max_total_bytes,
            });
        }

        let name_len = read_u16(bytes, at + 28)? as usize;
        let extra_len = read_u16(bytes, at + 30)?;
        let comment_len = read_u16(bytes, at + 32)?;
        let disk_start = read_u16(bytes, at + 34)?;
        let local_offset = read_u32(bytes, at + 42)?;
        if extra_len != 0 || comment_len != 0 {
            return Err(malformed(
                at + 30,
                "extra fields and file comments are not permitted",
            ));
        }
        if disk_start != 0 {
            return Err(malformed(at + 34, "multi-disk archives are not accepted"));
        }

        let name_at = at
            .checked_add(CENTRAL_FIXED)
            .ok_or_else(|| truncated(at))?;
        let name_end = name_at.checked_add(name_len).ok_or_else(|| truncated(at))?;
        if name_end > end {
            return Err(malformed(name_at, "entry name runs past the central directory"));
        }
        let raw = bytes.get(name_at..name_end).ok_or_else(|| truncated(name_at))?;
        let name = std::str::from_utf8(raw)
            .map_err(|_| malformed(name_at, "entry name is not valid UTF-8"))?;
        validate_entry_name(name, limits)?;
        if entries.iter().any(|e| e.name == name) {
            return Err(malformed(name_at, format!("duplicate entry name `{name}`")));
        }

        entries.push(CentralEntry {
            name: name.to_string(),
            crc,
            size: uncompressed,
            local_offset,
        });
        at = name_end;
    }

    if at != end {
        return Err(malformed(
            at,
            "unaccounted bytes between the last central directory header and the end record",
        ));
    }
    Ok(entries)
}

fn read_local_entry(
    bytes: &[u8],
    entry: &CentralEntry,
    central_offset: usize,
) -> ClResult<Payload> {
    let at = entry.local_offset as usize;
    if at >= central_offset {
        return Err(malformed(
            at,
            "local header offset points into or past the central directory",
        ));
    }
    if read_u32(bytes, at)? != LOCAL_SIG {
        return Err(malformed(at, "expected a local file header"));
    }
    let flags = read_u16(bytes, at + 6)?;
    if flags != 0 {
        return Err(malformed(
            at + 6,
            format!("general purpose flags {flags:#06x} are not permitted"),
        ));
    }
    let method = read_u16(bytes, at + 8)?;
    if method != METHOD_STORED {
        return Err(malformed(
            at + 8,
            format!(
                "entry uses compression method {method}; \
                 .clade is stored-only and a compressed entry is rejected, not decompressed"
            ),
        ));
    }
    let crc = read_u32(bytes, at + 14)?;
    let compressed = read_u32(bytes, at + 18)?;
    let uncompressed = read_u32(bytes, at + 22)?;
    let name_len = read_u16(bytes, at + 26)? as usize;
    let extra_len = read_u16(bytes, at + 28)?;
    if extra_len != 0 {
        return Err(malformed(at + 28, "extra fields are not permitted"));
    }

    if crc != entry.crc {
        return Err(malformed(
            at + 14,
            format!(
                "local header and central directory disagree about the CRC of `{}`",
                entry.name
            ),
        ));
    }
    if compressed != uncompressed || uncompressed != entry.size {
        return Err(malformed(
            at + 18,
            format!(
                "local header and central directory disagree about the size of `{}`",
                entry.name
            ),
        ));
    }

    let name_at = at.checked_add(LOCAL_FIXED).ok_or_else(|| truncated(at))?;
    let name_end = name_at.checked_add(name_len).ok_or_else(|| truncated(at))?;
    let raw = bytes
        .get(name_at..name_end)
        .ok_or_else(|| truncated(name_at))?;
    if raw != entry.name.as_bytes() {
        return Err(malformed(
            name_at,
            "local header and central directory disagree about an entry name",
        ));
    }

    let data_end = name_end
        .checked_add(entry.size as usize)
        .ok_or_else(|| truncated(name_end))?;
    if data_end > central_offset {
        return Err(malformed(
            name_end,
            format!(
                "entry `{}` declares more bytes than the archive holds before its central directory",
                entry.name
            ),
        ));
    }
    let data = bytes
        .get(name_end..data_end)
        .ok_or_else(|| truncated(name_end))?;
    if crc32(data) != entry.crc {
        return Err(ClError::integrity(format!(
            "CRC mismatch for bundle entry `{}`",
            entry.name
        )));
    }

    Ok(Payload {
        name: entry.name.clone(),
        bytes: data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Payload, ARTIFACT_MANIFEST_JSON, CHALLENGE_JSON, REPORT_JSON, VERIFY_TXT};

    fn p(name: &str, body: &[u8]) -> Payload {
        Payload { name: name.to_string(), bytes: body.to_vec() }
    }

    fn sample() -> Vec<Payload> {
        vec![
            p(REPORT_JSON, b"{\"schema_version\":1}"),
            p(CHALLENGE_JSON, b"{\"case_id\":\"CL-2026-0F3A9C\"}"),
            p(VERIFY_TXT, b"Cladeon Verify\n"),
        ]
    }

    // -- helpers for hand-built hostile archives ---------------------------

    /// A structurally valid stored ZIP over arbitrary names and bodies, bypassing
    /// every policy check the real writer applies. Tests use it to construct the
    /// archives a hostile party would send.
    fn raw_zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let crc = crc32(data);
            let size = data.len() as u32;
            let local_offset = out.len() as u32;
            out.extend_from_slice(&LOCAL_SIG.to_le_bytes());
            out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&METHOD_STORED.to_le_bytes());
            out.extend_from_slice(&DOS_TIME_MIDNIGHT.to_le_bytes());
            out.extend_from_slice(&DOS_DATE_EPOCH.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name);
            out.extend_from_slice(data);

            central.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
            central.extend_from_slice(&VERSION_MADE_BY.to_le_bytes());
            central.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&METHOD_STORED.to_le_bytes());
            central.extend_from_slice(&DOS_TIME_MIDNIGHT.to_le_bytes());
            central.extend_from_slice(&DOS_DATE_EPOCH.to_le_bytes());
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&size.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name);
        }
        let central_offset = out.len() as u32;
        let central_size = central.len() as u32;
        let count = entries.len() as u16;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn eocd_at(z: &[u8]) -> usize {
        z.len() - EOCD_FIXED
    }

    fn central_at(z: &[u8]) -> usize {
        read_u32(z, eocd_at(z) + 16).unwrap() as usize
    }

    fn put_u16(z: &mut [u8], off: usize, v: u16) {
        z[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u32(z: &mut [u8], off: usize, v: u32) {
        z[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn lim() -> BundleLimits {
        BundleLimits::default()
    }

    // -- writer -------------------------------------------------------------

    #[test]
    fn round_trip_preserves_every_payload() {
        let payloads = sample();
        let archive = write_archive(&payloads).unwrap();
        let back = read_archive(&archive, &lim()).unwrap();
        assert_eq!(back.len(), payloads.len());
        for original in &payloads {
            let found = back.iter().find(|e| e.name == original.name).unwrap();
            assert_eq!(found.bytes, original.bytes);
        }
    }

    #[test]
    fn writer_is_byte_identical_across_runs_and_input_orders() {
        let a = write_archive(&sample()).unwrap();
        let b = write_archive(&sample()).unwrap();
        assert_eq!(a, b, "same payloads must produce identical bytes");

        let mut shuffled = sample();
        shuffled.reverse();
        let c = write_archive(&shuffled).unwrap();
        assert_eq!(a, c, "input order must not reach the container");
    }

    #[test]
    fn entries_are_emitted_in_the_frozen_schema_order() {
        let payloads = vec![
            p(VERIFY_TXT, b"v"),
            p(ARTIFACT_MANIFEST_JSON, b"{}"),
            p(CHALLENGE_JSON, b"{}"),
        ];
        let archive = write_archive(&payloads).unwrap();
        let names: Vec<String> = read_archive(&archive, &lim())
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec![CHALLENGE_JSON, ARTIFACT_MANIFEST_JSON, VERIFY_TXT]);
    }

    #[test]
    fn timestamps_are_pinned_to_the_dos_epoch() {
        let archive = write_archive(&sample()).unwrap();
        assert_eq!(read_u16(&archive, 10).unwrap(), DOS_TIME_MIDNIGHT);
        assert_eq!(read_u16(&archive, 12).unwrap(), DOS_DATE_EPOCH);
        let c = central_at(&archive);
        assert_eq!(read_u16(&archive, c + 12).unwrap(), DOS_TIME_MIDNIGHT);
        assert_eq!(read_u16(&archive, c + 14).unwrap(), DOS_DATE_EPOCH);
    }

    #[test]
    fn writer_rejects_unknown_and_duplicate_names() {
        assert!(write_archive(&[p("evil.exe", b"MZ")]).is_err());
        assert!(write_archive(&[p(REPORT_JSON, b"a"), p(REPORT_JSON, b"b")]).is_err());
    }

    #[test]
    fn empty_payload_set_produces_a_readable_empty_archive() {
        let archive = write_archive(&[]).unwrap();
        assert_eq!(archive.len(), EOCD_FIXED);
        assert!(read_archive(&archive, &lim()).unwrap().is_empty());
    }

    #[test]
    fn zero_length_payload_round_trips() {
        let archive = write_archive(&[p(REPORT_JSON, b"")]).unwrap();
        let back = read_archive(&archive, &lim()).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back[0].bytes.is_empty());
    }

    // -- reader: shape ------------------------------------------------------

    #[test]
    fn rejects_empty_file() {
        assert!(read_archive(b"", &lim()).is_err());
    }

    #[test]
    fn rejects_a_file_that_is_not_a_zip() {
        let not_zip = b"%PDF-1.7\nthis is definitely not a container\n".to_vec();
        let err = read_archive(&not_zip, &lim()).unwrap_err();
        assert!(matches!(err, ClError::Malformed { .. }));
    }

    #[test]
    fn rejects_truncated_eocd() {
        let archive = write_archive(&sample()).unwrap();
        for cut in [1usize, 10, EOCD_FIXED - 1] {
            let short = &archive[..archive.len() - cut];
            assert!(read_archive(short, &lim()).is_err(), "cut {cut} must be rejected");
        }
    }

    #[test]
    fn rejects_trailing_garbage_after_the_eocd() {
        let mut archive = write_archive(&sample()).unwrap();
        archive.extend_from_slice(b"appended");
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("trailing data")),
            other => panic!("expected trailing-data rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_prepended_data_whose_offset_does_not_resolve() {
        let archive = write_archive(&sample()).unwrap();
        let mut prepended = b"SFX-STUB".to_vec();
        prepended.extend_from_slice(&archive);
        // Offsets in the copied directory now point 8 bytes too early.
        let err = read_archive(&prepended, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("does not resolve")),
            other => panic!("expected offset rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_central_directory_offset_that_points_elsewhere() {
        let mut archive = write_archive(&sample()).unwrap();
        let e = eocd_at(&archive);
        put_u32(&mut archive, e + 16, 4);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    // -- reader: limits -----------------------------------------------------

    #[test]
    fn rejects_thirty_three_entries_before_parsing_them() {
        let body: &[u8] = b"x";
        let entries: Vec<(&[u8], &[u8])> = (0..33).map(|_| (REPORT_JSON.as_bytes(), body)).collect();
        let archive = raw_zip(&entries);
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::LimitExceeded { limit, value, max } => {
                assert_eq!(limit, "bundle_max_entries");
                assert_eq!(value, 33);
                assert_eq!(max, 32);
            }
            other => panic!("expected an entry-count limit, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_entry_claiming_one_gigabyte_without_allocating() {
        let mut archive = write_archive(&sample()).unwrap();
        let c = central_at(&archive);
        put_u32(&mut archive, c + 20, 1_073_741_824);
        put_u32(&mut archive, c + 24, 1_073_741_824);
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::LimitExceeded { limit, value, .. } => {
                assert_eq!(limit, "bundle_max_entry_bytes");
                assert_eq!(value, 1_073_741_824);
            }
            other => panic!("expected an entry-size limit, got {other:?}"),
        }
    }

    #[test]
    fn rejects_total_size_over_the_limit() {
        // Two entries that each fit but together do not.
        let tight = BundleLimits { max_total_bytes: 8, ..BundleLimits::default() };
        let archive = write_archive(&[p(REPORT_JSON, b"12345"), p(VERIFY_TXT, b"12345")]).unwrap();
        let err = read_archive(&archive, &tight).unwrap_err();
        assert!(matches!(err, ClError::LimitExceeded { limit: "bundle_max_total_bytes", .. }));
    }

    #[test]
    fn rejects_a_name_longer_than_the_limit() {
        let tight = BundleLimits { max_name_bytes: 4, ..BundleLimits::default() };
        let archive = write_archive(&sample()).unwrap();
        let err = read_archive(&archive, &tight).unwrap_err();
        assert!(matches!(err, ClError::LimitExceeded { limit: "bundle_max_name_bytes", .. }));
    }

    // -- reader: names ------------------------------------------------------

    #[test]
    fn rejects_zip_slip_and_other_hostile_names() {
        // Same length as `report.json`, so only the name bytes differ.
        for name in [
            &b"..\\rep.json"[..],
            &b"aa/rep.json"[..],
            &b"C:rep.json."[..],
            &b"/report.jso"[..],
            &b"repor?.json"[..],
            &b"reporT.json"[..],
        ] {
            let archive = raw_zip(&[(name, b"{}")]);
            assert!(
                read_archive(&archive, &lim()).is_err(),
                "name {:?} must be rejected",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn rejects_an_empty_name() {
        let archive = raw_zip(&[(&b""[..], b"{}")]);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_duplicate_names() {
        let archive = raw_zip(&[
            (REPORT_JSON.as_bytes(), b"first"),
            (REPORT_JSON.as_bytes(), b"second"),
        ]);
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("duplicate")),
            other => panic!("expected a duplicate-name rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_name_that_is_not_utf8() {
        let archive = raw_zip(&[(&[0xff, 0xfe, 0x80, 0x81][..], b"{}")]);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    // -- reader: methods, flags, extra fields -------------------------------

    #[test]
    fn rejects_a_deflated_entry_rather_than_decompressing_it() {
        let mut archive = write_archive(&sample()).unwrap();
        let c = central_at(&archive);
        put_u16(&mut archive, c + 10, 8); // deflate, central directory view
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("stored-only")),
            other => panic!("expected a method rejection, got {other:?}"),
        }

        // ... and when only the local header claims deflate.
        let mut archive = write_archive(&sample()).unwrap();
        put_u16(&mut archive, 8, 8);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_a_data_descriptor_flag() {
        let mut archive = write_archive(&sample()).unwrap();
        let c = central_at(&archive);
        put_u16(&mut archive, c + 8, 0x0008);
        assert!(read_archive(&archive, &lim()).is_err());

        let mut archive = write_archive(&sample()).unwrap();
        put_u16(&mut archive, 6, 0x0008);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_extra_fields() {
        let mut archive = write_archive(&sample()).unwrap();
        let c = central_at(&archive);
        put_u16(&mut archive, c + 30, 4);
        assert!(read_archive(&archive, &lim()).is_err());

        let mut archive = write_archive(&sample()).unwrap();
        put_u16(&mut archive, 28, 4);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    // -- reader: content vs headers ----------------------------------------

    #[test]
    fn rejects_a_size_field_that_lies_about_the_content() {
        let mut archive = write_archive(&sample()).unwrap();
        let c = central_at(&archive);
        // Claim far more bytes than the archive holds, consistently in both views.
        put_u32(&mut archive, c + 20, 100_000);
        put_u32(&mut archive, c + 24, 100_000);
        put_u32(&mut archive, 18, 100_000);
        put_u32(&mut archive, 22, 100_000);
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("more bytes")),
            other => panic!("expected an overrun rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_crc_that_does_not_match_the_bytes() {
        let archive = write_archive(&sample()).unwrap();
        // Flip a byte of the first entry's data, leaving both CRC fields intact.
        let name_len = read_u16(&archive, 26).unwrap() as usize;
        let data_at = LOCAL_FIXED + name_len;
        let mut tampered = archive.clone();
        tampered[data_at] ^= 0x20;
        let err = read_archive(&tampered, &lim()).unwrap_err();
        assert!(matches!(err, ClError::Integrity { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_central_and_local_disagreement_about_crc() {
        let mut archive = write_archive(&sample()).unwrap();
        put_u32(&mut archive, 14, 0xdead_beef); // local CRC only
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("disagree")),
            other => panic!("expected a disagreement rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_central_and_local_disagreement_about_size() {
        let mut archive = write_archive(&sample()).unwrap();
        put_u32(&mut archive, 18, 3);
        put_u32(&mut archive, 22, 3);
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("disagree")),
            other => panic!("expected a disagreement rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_central_and_local_disagreement_about_name() {
        let mut archive = write_archive(&[p(REPORT_JSON, b"{}")]).unwrap();
        let name_at = LOCAL_FIXED;
        // `report.json` -> `report.jso` + a byte the central directory does not have.
        archive[name_at + 10] = b'x';
        let err = read_archive(&archive, &lim()).unwrap_err();
        match err {
            ClError::Malformed { detail, .. } => assert!(detail.contains("disagree")),
            other => panic!("expected a disagreement rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_local_offset_pointing_into_the_central_directory() {
        let mut archive = write_archive(&sample()).unwrap();
        let c = central_at(&archive);
        put_u32(&mut archive, c + 42, c as u32);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_a_local_header_that_is_not_a_local_header() {
        let mut archive = write_archive(&sample()).unwrap();
        put_u32(&mut archive, 0, 0x1234_5678);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_an_entry_count_that_disagrees_with_the_directory() {
        let mut archive = write_archive(&sample()).unwrap();
        let e = eocd_at(&archive);
        put_u16(&mut archive, e + 8, 2);
        put_u16(&mut archive, e + 10, 3);
        assert!(read_archive(&archive, &lim()).is_err());

        // Both fields lowered: the directory then has bytes nobody accounts for.
        let mut archive = write_archive(&sample()).unwrap();
        let e = eocd_at(&archive);
        put_u16(&mut archive, e + 8, 2);
        put_u16(&mut archive, e + 10, 2);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_an_archive_comment() {
        let mut archive = write_archive(&sample()).unwrap();
        let e = eocd_at(&archive);
        put_u16(&mut archive, e + 20, 5);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn rejects_multi_disk_archives() {
        let mut archive = write_archive(&sample()).unwrap();
        let e = eocd_at(&archive);
        put_u16(&mut archive, e + 4, 1);
        assert!(read_archive(&archive, &lim()).is_err());
    }

    #[test]
    fn every_single_byte_truncation_is_rejected_without_panicking() {
        let archive = write_archive(&sample()).unwrap();
        for cut in 1..archive.len() {
            let short = &archive[..cut];
            assert!(read_archive(short, &lim()).is_err(), "prefix of {cut} bytes accepted");
        }
    }

    #[test]
    fn every_single_byte_corruption_is_rejected_or_read_safely() {
        // The point is that nothing panics and nothing is silently mis-read: any
        // accepted variant must still round-trip to identical content.
        let payloads = sample();
        let archive = write_archive(&payloads).unwrap();
        for i in 0..archive.len() {
            let mut mutated = archive.clone();
            mutated[i] ^= 0xff;
            if let Ok(entries) = read_archive(&mutated, &lim()) {
                for e in entries {
                    let original = payloads.iter().find(|p| p.name == e.name);
                    match original {
                        Some(o) => assert_eq!(o.bytes, e.bytes, "byte {i} altered content silently"),
                        None => panic!("byte {i} produced an entry that was never written"),
                    }
                }
            }
        }
    }
}
