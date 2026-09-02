//! Training-log reading, from the **tail** and nothing else.
//!
//! A training log is the cheapest operational record a vendor can supply and one of
//! the most useful: it is the only place where a loss series, a step series, a device
//! inventory and a wall-clock figure tend to sit next to each other. It is also
//! unbounded, frequently gigabytes, and written by whoever is under scrutiny.
//!
//! ## Why the tail
//!
//! The end of a run is where the summary lives — final loss, `train_runtime`,
//! `total_flos`, the last checkpoint save. Reading a bounded suffix
//! ([`Limits::log_tail_bytes`]) buys most of the evidence for a fixed cost, and the
//! cost is what makes it safe: no log, however large, can make this module allocate
//! more than the limit. When the caller hands over a suffix rather than a whole file
//! the first line is almost certainly cut in half, so [`parse_tail`] is told and
//! discards it. Guessing would mean reporting half a number as a whole one.
//!
//! ## Why this is not a general log parser
//!
//! There is no such thing. This module recognises four shapes that account for nearly
//! every Python training stack in use — HF `Trainer` dict lines, `key=value` lines,
//! JSONL, and the `***** Running training *****` banner — and it recognises nothing
//! else. A line it does not understand contributes nothing at all; it is never
//! guessed at. That is the difference between "no evidence" and a fabricated series.
//!
//! JSONL lines are read with the same tolerant pair scanner as the other shapes
//! rather than with [`tt_core::json`]. That is deliberate: the strict reader rejects a
//! whole document on a duplicate key or a stray byte, which is correct for an
//! authoritative config and wrong for a log, where one corrupt line must not erase the
//! other ten thousand. Nothing read here is authoritative — every value lands in a
//! fact that says only "the log contained this text".
//!
//! ## Facts carry no verdicts
//!
//! This module records that a run start was logged at one time and a checkpoint at
//! another. Whether those two can both be true is `TT-CHRONO-004`'s question, not
//! this module's. The one judgement made here is a *pairing* judgement: a start and a
//! checkpoint are only reported together when the checkpoint line came at or after
//! the start line, because two concatenated runs in one tail would otherwise
//! manufacture a chronology conflict out of ordinary log rotation.

use std::collections::BTreeSet;

use tt_core::error::TtResult;
use tt_core::limits::Limits;
use tt_core::time::Timestamp;
use tt_facts::{ArtifactType, FactKind, FieldValue};

use crate::{FormatParser, ParseOutput, PendingFact, ReadNeed};

/// Stable parser name recorded in the artifact manifest.
pub const PARSER_NAME: &str = "training_log_tail";
/// Bumping this invalidates cached parses of the same bytes.
pub const PARSER_VERSION: i64 = 1;

/// `docs/01-RULE-CATALOGUE.md`: "Config rejected: depth, key count, or size limit".
/// The parse-status family is where every parser bound surfaces.
const NOTE_ID: &str = "TT-FMT-010";

/// A hostile log can contain millions of unreadable lines. Notes are capped so one
/// file cannot flood the report; the overflow is summarised in a final note.
const MAX_NOTES: usize = 16;

/// Pairs read from a single line. A line crafted to hold a million `a=1` pairs must
/// not turn into a million allocations.
const MAX_PAIRS_PER_LINE: usize = 256;

/// Distinct `checkpoint-<n>` directories reported. Beyond this the series is
/// summarised by its endpoints rather than enumerated.
const MAX_CHECKPOINT_FACTS: usize = 64;

/// Keys whose integer value is a training step.
const STEP_KEYS: &[&str] = &["step", "global_step", "iter", "iteration"];
/// Keys whose value is the training loss. Evaluation loss is deliberately excluded:
/// interleaving two different series would produce a history that never existed.
const LOSS_KEYS: &[&str] = &["loss", "train_loss", "training_loss"];
/// Keys whose presence makes a line a metric entry.
const ENTRY_KEYS: &[&str] = &[
    "step",
    "global_step",
    "iter",
    "iteration",
    "loss",
    "train_loss",
    "training_loss",
    "eval_loss",
    "learning_rate",
    "lr",
    "epoch",
    "grad_norm",
];

/// Keys carrying a cumulative token count.
const TOKEN_KEYS: &[&str] = &[
    "tokens",
    "total_tokens",
    "num_tokens",
    "train_tokens",
    "num_train_tokens",
    "token_count",
    "tokens_seen",
    "consumed_tokens",
];
/// Substrings that turn a token key into a *rate*. A throughput figure is not a
/// corpus size and must never be reported as one.
const RATE_MARKERS: &[&str] = &["per_sec", "per_second", "persec", "throughput", "speed", "_ps", "/s"];

/// Accelerator families recognised in a free-text `8x A100` description.
const ACCELERATORS: &[&str] = &[
    "a100", "h100", "h200", "b200", "gh200", "v100", "a10", "a10g", "l4", "l40", "l40s", "t4",
    "p100", "a6000", "rtx", "3090", "4090", "mi250", "mi300", "tpu", "gaudi", "trainium",
];

/// The training-log tail parser.
pub struct TrainingLogTail;

impl FormatParser for TrainingLogTail {
    fn name() -> &'static str {
        PARSER_NAME
    }
    fn version() -> i64 {
        PARSER_VERSION
    }
    fn read_need(limits: &Limits) -> ReadNeed {
        ReadNeed::Suffix(limits.log_tail_bytes)
    }
    /// Parse bytes assumed to start at the beginning of the file.
    ///
    /// A caller that performed a [`ReadNeed::Suffix`] read must use [`parse_tail`]
    /// with `is_suffix = true` instead, so the truncated first line is discarded.
    fn parse(bytes: &[u8], limits: &Limits) -> TtResult<ParseOutput> {
        parse_tail(bytes, limits, false)
    }
}

/// Parse a training log.
///
/// `is_suffix` says whether `bytes` begins mid-file. When it does, the first line is
/// dropped: a suffix read almost always slices a line in half, and half a number is
/// not a smaller number.
///
/// Input longer than [`Limits::log_tail_bytes`] is trimmed to its own tail here as
/// well, so a caller that hands over a whole 40 GB file gets bounded work and an
/// explicit note rather than a bounded surprise.
pub fn parse_tail(bytes: &[u8], limits: &Limits, is_suffix: bool) -> TtResult<ParseOutput> {
    let mut out = ParseOutput::new(ArtifactType::TrainingLog, PARSER_NAME, PARSER_VERSION);
    let mut suppressed = 0usize;

    let limit = limits.log_tail_bytes.max(1) as usize;
    let (body, trimmed) = if bytes.len() > limit {
        let start = bytes.len() - limit;
        (bytes.get(start..).unwrap_or(bytes), true)
    } else {
        (bytes, false)
    };
    if trimmed {
        note(
            &mut out,
            &mut suppressed,
            format!(
                "Log is {} bytes; only the final {} bytes were read.",
                bytes.len(),
                body.len()
            ),
        );
    }
    let partial_first_line = trimmed || is_suffix;

    let mut s = Series::default();
    let mut hw = Hardware::default();
    let mut compute = Compute::default();
    let mut seeds = Seeds::default();
    let mut chrono = Chronology::default();
    let mut banner = Banner::default();
    let mut ckpt_dirs: BTreeSet<i64> = BTreeSet::new();
    let mut long_lines = 0usize;

    for (index, raw) in body.split(|c| *c == b'\n').enumerate() {
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if index == 0 && partial_first_line {
            continue;
        }
        if raw.len() > limits.log_max_line_bytes {
            long_lines += 1;
            continue;
        }
        if raw.is_empty() {
            continue;
        }
        let line = String::from_utf8_lossy(raw);
        read_line(
            &line,
            &mut s,
            &mut hw,
            &mut compute,
            &mut seeds,
            &mut chrono,
            &mut banner,
            &mut ckpt_dirs,
        );
    }

    if long_lines > 0 {
        note(
            &mut out,
            &mut suppressed,
            format!(
                "{long_lines} line(s) exceeded the {} byte line limit and were not read.",
                limits.log_max_line_bytes
            ),
        );
    }

    emit_series(&mut out, &s, &banner);
    emit_checkpoints(&mut out, &s, &ckpt_dirs);
    emit_tokens(&mut out, &s, &banner);
    hw.emit(&mut out);
    compute.emit(&mut out);
    seeds.emit(&mut out);
    chrono.emit(&mut out);

    if suppressed > 0 {
        out.note(NOTE_ID, format!("{suppressed} further note(s) were suppressed."));
    }
    Ok(out)
}

fn note(out: &mut ParseOutput, suppressed: &mut usize, detail: String) {
    if out.notes.len() < MAX_NOTES {
        out.note(NOTE_ID, detail);
    } else {
        *suppressed += 1;
    }
}

// ---------------------------------------------------------------------------
// Accumulators
// ---------------------------------------------------------------------------

/// The metric series, accumulated in file order.
struct Series {
    entries: i64,
    first_step: Option<i64>,
    last_step: Option<i64>,
    prev_step: Option<i64>,
    monotonic: bool,
    saw_two_steps: bool,
    first_loss: Option<String>,
    last_loss: Option<String>,
    tokens: Option<i64>,
}

/// `Default` is written out rather than derived, because `monotonic` must start
/// `true`.
///
/// A derived `Default` gives it `false`, and the walk below only ever *clears* the
/// flag — so a perfectly ordered log would end up reporting `steps_monotonic =
/// false`. Rule `TT-DENSE-007` turns that into a contradiction, which means the
/// derive would have made the scanner raise a contradiction against every honest
/// vendor whose steps were in order. A field whose safe value is not the type's
/// zero value cannot be derived.
impl Default for Series {
    fn default() -> Self {
        Series {
            entries: 0,
            first_step: None,
            last_step: None,
            prev_step: None,
            monotonic: true,
            saw_two_steps: false,
            first_loss: None,
            last_loss: None,
            tokens: None,
        }
    }
}

impl Series {
    fn note_step(&mut self, v: i64) {
        if self.first_step.is_none() {
            self.first_step = Some(v);
        } else {
            self.saw_two_steps = true;
        }
        if let Some(p) = self.prev_step {
            if v < p {
                self.monotonic = false;
            }
        }
        self.prev_step = Some(v);
        self.last_step = Some(v);
    }
    fn note_loss(&mut self, text: &str) {
        if self.first_loss.is_none() {
            self.first_loss = Some(text.to_string());
        }
        self.last_loss = Some(text.to_string());
    }
}

/// The `***** Running training *****` banner, which states the run's intended shape
/// before any of it has happened.
#[derive(Default)]
struct Banner {
    num_examples: Option<i64>,
    num_epochs: Option<FieldValue>,
    total_optimization_steps: Option<i64>,
    trainable_params: Option<i64>,
    total_params: Option<i64>,
    tokens: Option<i64>,
}

#[derive(Default)]
struct Hardware {
    world_size: Option<i64>,
    gpu_count: Option<i64>,
    devices: BTreeSet<String>,
    descriptions: BTreeSet<String>,
}

impl Hardware {
    fn emit(&self, out: &mut ParseOutput) {
        if self.world_size.is_none()
            && self.gpu_count.is_none()
            && self.devices.is_empty()
            && self.descriptions.is_empty()
        {
            return;
        }
        let mut f = PendingFact::new(FactKind::HardwareRecord)
            .with_opt("world_size", self.world_size)
            .with_opt("gpu_count", self.gpu_count);
        if !self.devices.is_empty() {
            let v: Vec<String> = self.devices.iter().cloned().collect();
            f = f.with("device_name", v.join("; "));
        }
        if !self.descriptions.is_empty() {
            let v: Vec<String> = self.descriptions.iter().cloned().collect();
            f = f.with("description", v.join("; "));
        }
        out.push(f);
    }
}

#[derive(Default)]
struct Compute {
    wall_clock_seconds: Option<i64>,
    gpu_hours: Option<i64>,
    total_flos: Option<i64>,
}

impl Compute {
    fn emit(&self, out: &mut ParseOutput) {
        if self.wall_clock_seconds.is_none() && self.gpu_hours.is_none() && self.total_flos.is_none()
        {
            return;
        }
        out.push(
            PendingFact::new(FactKind::ComputeRecord)
                .with_opt("wall_clock_seconds", self.wall_clock_seconds)
                .with_opt("gpu_hours", self.gpu_hours)
                .with_opt("total_flos", self.total_flos),
        );
    }
}

#[derive(Default)]
struct Seeds {
    seed: Option<i64>,
    data_seed: Option<i64>,
}

impl Seeds {
    fn emit(&self, out: &mut ParseOutput) {
        if self.seed.is_none() && self.data_seed.is_none() {
            return;
        }
        out.push(
            PendingFact::new(FactKind::SeedRecord)
                .with_opt("seed", self.seed)
                .with_opt("data_seed", self.data_seed),
        );
    }
}

/// Timestamps, with the pairing rule that keeps two concatenated runs from
/// manufacturing a chronology conflict.
#[derive(Default)]
struct Chronology {
    first_seen: Option<Stamp>,
    last_seen: Option<Stamp>,
    /// Most recent run-start marker, and its line index.
    start: Option<(Stamp, usize)>,
    /// Most recent checkpoint marker, and its line index.
    checkpoint: Option<(Stamp, usize)>,
    /// Most recent checkpoint marker at or after `start`.
    checkpoint_after_start: Option<Stamp>,
    line: usize,
}

#[derive(Clone)]
struct Stamp {
    raw: String,
    rfc3339: Option<String>,
}

impl Chronology {
    fn emit(&self, out: &mut ParseOutput) {
        let start = self.start.as_ref().map(|(s, _)| s.clone());
        // Pair within one run only: a checkpoint logged *before* the newest run start
        // belongs to an older run, and reporting the two together would invent a
        // conflict out of log rotation.
        let checkpoint = match (&start, &self.checkpoint_after_start, &self.checkpoint) {
            (Some(_), Some(c), _) => Some(c.clone()),
            (Some(_), None, _) => None,
            (None, _, Some((c, _))) => Some(c.clone()),
            (None, _, None) => None,
        };
        if start.is_none() && checkpoint.is_none() && self.first_seen.is_none() {
            return;
        }
        let mut f = PendingFact::new(FactKind::FileChronology);
        if let Some(s) = &start {
            f = f.with("run_started_at_text", s.raw.clone());
            if let Some(n) = &s.rfc3339 {
                f = f.with("run_started_at", n.clone());
            }
        }
        if let Some(c) = &checkpoint {
            f = f.with("checkpoint_at_text", c.raw.clone());
            if let Some(n) = &c.rfc3339 {
                f = f.with("checkpoint_at", n.clone());
            }
        }
        if let Some(s) = &self.first_seen {
            f = f.with("observed_first_at", s.raw.clone());
        }
        if let Some(s) = &self.last_seen {
            f = f.with("observed_last_at", s.raw.clone());
        }
        out.push(f);
    }
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

fn emit_series(out: &mut ParseOutput, s: &Series, b: &Banner) {
    let has_banner = b.num_examples.is_some()
        || b.num_epochs.is_some()
        || b.total_optimization_steps.is_some();
    if s.entries == 0 && !has_banner {
        return;
    }
    let mut f = PendingFact::new(FactKind::TrainingMetric)
        .with("entry_count", s.entries)
        .with_opt("first_step", s.first_step)
        .with_opt("last_step", s.last_step)
        .with_opt("num_examples", b.num_examples)
        .with_opt("total_optimization_steps", b.total_optimization_steps);
    if let Some(v) = &b.num_epochs {
        f = f.with("num_epochs", v.clone());
    }
    if let Some(t) = &s.first_loss {
        f = f.with("first_loss", FieldValue::Num(t.clone()));
    }
    if let Some(t) = &s.last_loss {
        f = f.with("last_loss", FieldValue::Num(t.clone()));
    }
    // Only assert an ordering when there were at least two steps to order. A single
    // step is not a monotone series, and `false` here is read as a contradiction.
    if s.saw_two_steps {
        f = f.with("steps_monotonic", s.monotonic);
    }
    if let (Some(a), Some(z)) = (&s.first_loss, &s.last_loss) {
        if let Some(pct) = decrease_percent(a, z) {
            f = f.with("loss_decreasing_percent", pct);
        }
    }
    out.push(f);
}

/// Percentage decrease from `first` to `last`, rounded toward zero. Negative when the
/// loss rose. `None` when either value is unreadable or the first is zero.
fn decrease_percent(first: &str, last: &str) -> Option<i64> {
    let a = parse_micros(first)?;
    let z = parse_micros(last)?;
    if a == 0 {
        return None;
    }
    let pct = ((a as i128 - z as i128) * 100) / (a as i128);
    i64::try_from(pct).ok()
}

fn emit_checkpoints(out: &mut ParseOutput, s: &Series, dirs: &BTreeSet<i64>) {
    let mut seen: BTreeSet<i64> = BTreeSet::new();
    for (v, origin) in [(s.first_step, "series_first"), (s.last_step, "series_last")] {
        if let Some(v) = v {
            if seen.insert(v) {
                out.push(
                    PendingFact::new(FactKind::CheckpointStep)
                        .with("step", v)
                        .with("origin", origin),
                );
            }
        }
    }
    for v in dirs.iter().take(MAX_CHECKPOINT_FACTS) {
        if seen.insert(*v) {
            out.push(
                PendingFact::new(FactKind::CheckpointStep)
                    .with("step", *v)
                    .with("origin", "checkpoint_directory"),
            );
        }
    }
}

fn emit_tokens(out: &mut ParseOutput, s: &Series, b: &Banner) {
    if let Some(t) = s.tokens.or(b.tokens) {
        out.push(PendingFact::new(FactKind::TokenCountRecord).with("tokens", t));
    }
    if let (Some(tr), Some(all)) = (b.trainable_params, b.total_params) {
        out.push(
            PendingFact::new(FactKind::TrainableParameterRecord)
                .with("trainable", tr)
                .with("total", all),
        );
    }
}

// ---------------------------------------------------------------------------
// Line reading
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn read_line(
    line: &str,
    s: &mut Series,
    hw: &mut Hardware,
    compute: &mut Compute,
    seeds: &mut Seeds,
    chrono: &mut Chronology,
    banner: &mut Banner,
    ckpt_dirs: &mut BTreeSet<i64>,
) {
    chrono.line += 1;
    let lower = line.to_ascii_lowercase();

    if let Some(stamp) = find_timestamp(line) {
        if chrono.first_seen.is_none() {
            chrono.first_seen = Some(stamp.clone());
        }
        chrono.last_seen = Some(stamp.clone());
        if is_run_start(&lower) {
            chrono.start = Some((stamp.clone(), chrono.line));
            chrono.checkpoint_after_start = None;
        }
        if is_checkpoint_write(&lower) {
            let at = chrono.line;
            chrono.checkpoint = Some((stamp.clone(), at));
            if chrono.start.as_ref().is_some_and(|(_, l)| at >= *l) {
                chrono.checkpoint_after_start = Some(stamp);
            }
        }
    }

    if is_checkpoint_write(&lower) {
        collect_checkpoint_dirs(&lower, ckpt_dirs);
    }

    // Label-and-value lines: `  Num examples = 50000`, `trainable params: 4,194,304`.
    read_labels(strip_leading_timestamp(line), banner, hw, seeds, s);

    // Structured pairs: dict lines, JSONL, and `key=value`.
    let mut pairs: Vec<(String, String)> = Vec::new();
    scan_pairs(line, &mut pairs);
    if pairs.is_empty() {
        read_free_text_hardware(line, hw);
        return;
    }

    let mut is_entry = false;
    for (k, v) in &pairs {
        if ENTRY_KEYS.contains(&k.as_str()) {
            is_entry = true;
        }
        if STEP_KEYS.contains(&k.as_str()) {
            if let Some(n) = parse_int(v) {
                s.note_step(n);
            }
        }
        if LOSS_KEYS.contains(&k.as_str()) && parse_micros(v).is_some() {
            s.note_loss(v);
        }
        if TOKEN_KEYS.contains(&k.as_str()) && !is_rate_key(k) {
            if let Some(n) = parse_int(v) {
                s.tokens = Some(s.tokens.map_or(n, |p| p.max(n)));
            }
        }
        match k.as_str() {
            "world_size" => hw.world_size = parse_int(v).or(hw.world_size),
            "n_gpu" | "num_gpus" | "gpu_count" | "num_devices" | "device_count"
            | "nproc_per_node" => hw.gpu_count = parse_int(v).or(hw.gpu_count),
            "device" | "device_name" | "gpu_name" | "accelerator" => {
                let v = v.trim();
                if !v.is_empty() && v.len() <= 128 {
                    hw.devices.insert(v.to_string());
                }
            }
            "seed" | "random_seed" => seeds.seed = parse_int(v).or(seeds.seed),
            "data_seed" => seeds.data_seed = parse_int(v).or(seeds.data_seed),
            "train_runtime" | "runtime" | "wall_clock" | "wall_time" | "elapsed"
            | "elapsed_seconds" => {
                if let Some(n) = parse_seconds(v) {
                    compute.wall_clock_seconds = Some(n.max(compute.wall_clock_seconds.unwrap_or(0)));
                }
            }
            "gpu_hours" | "gpu_hrs" | "accelerator_hours" => {
                compute.gpu_hours = parse_int(v).or(compute.gpu_hours)
            }
            "total_flos" | "total_flops" | "flops" => {
                if let Some(n) = parse_int(v) {
                    compute.total_flos = Some(n.max(compute.total_flos.unwrap_or(0)));
                }
            }
            _ => {}
        }
    }
    if is_entry {
        s.entries = s.entries.saturating_add(1);
    }
    read_free_text_hardware(line, hw);
}

fn is_rate_key(k: &str) -> bool {
    RATE_MARKERS.iter().any(|m| k.contains(m))
}

fn is_run_start(lower: &str) -> bool {
    lower.contains("running training")
        || lower.contains("starting training")
        || lower.contains("start training")
        || lower.contains("training started")
        || lower.contains("begin training")
        || lower.contains("run started")
}

fn is_checkpoint_write(lower: &str) -> bool {
    lower.contains("checkpoint")
        && (lower.contains("sav") || lower.contains("writ") || lower.contains("dump"))
}

/// Pull `checkpoint-500` step numbers out of a save line.
fn collect_checkpoint_dirs(lower: &str, into: &mut BTreeSet<i64>) {
    let b = lower.as_bytes();
    let needle = b"checkpoint-";
    let mut i = 0usize;
    while i + needle.len() < b.len() {
        if b.get(i..i + needle.len()) == Some(&needle[..]) {
            let mut j = i + needle.len();
            let start = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j > start && j - start <= 18 {
                if let Some(n) = lower.get(start..j).and_then(|t| t.parse::<i64>().ok()) {
                    if into.len() < MAX_CHECKPOINT_FACTS {
                        into.insert(n);
                    }
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
}

/// `8x A100`, `8 x H100`, `4xA10G`.
fn read_free_text_hardware(line: &str, hw: &mut Hardware) {
    let lower = line.to_ascii_lowercase();
    let b = lower.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        // A count must not be the tail of a longer number-word.
        if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.') {
            i += 1;
            continue;
        }
        let ds = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let count = match lower.get(ds..i).and_then(|t| t.parse::<i64>().ok()) {
            Some(n) if (1..=100_000).contains(&n) => n,
            _ => continue,
        };
        let mut j = i;
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        if b.get(j) != Some(&b'x') {
            continue;
        }
        j += 1;
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        let ts = j;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'-') {
            j += 1;
        }
        let Some(token) = lower.get(ts..j) else { continue };
        if token.is_empty() || token.len() > 32 {
            continue;
        }
        if ACCELERATORS.iter().any(|a| token.starts_with(a)) {
            hw.descriptions.insert(format!("{count}x {token}"));
            if hw.gpu_count.is_none() {
                hw.gpu_count = Some(count);
            }
        }
        i = j.max(i);
    }
}

// ---------------------------------------------------------------------------
// Label lines
// ---------------------------------------------------------------------------

/// `  Num examples = 50000` and `trainable params: 4,194,304 || all params: 6,742,609,920`.
///
/// A label is distinguished from a `key=value` pair by containing a space, which is
/// what keeps `INFO: Saving ...` from being read as a field called `info`.
fn read_labels(line: &str, b: &mut Banner, hw: &mut Hardware, seeds: &mut Seeds, s: &mut Series) {
    for segment in line.split("||") {
        let Some((label, value)) = split_label(segment) else { continue };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if label.ends_with("num examples") || label.ends_with("num training examples") {
            b.num_examples = parse_int(value).or(b.num_examples);
        } else if label.ends_with("num epochs") || label.ends_with("num train epochs") {
            b.num_epochs = b.num_epochs.take().or_else(|| number_field(value));
        } else if label.ends_with("total optimization steps")
            || label.ends_with("total optimisation steps")
        {
            b.total_optimization_steps = parse_int(value).or(b.total_optimization_steps);
        } else if label.ends_with("trainable params")
            || label.ends_with("number of trainable parameters")
        {
            b.trainable_params = parse_int(value).or(b.trainable_params);
        } else if label.ends_with("all params") || label.ends_with("total params") {
            b.total_params = parse_int(value).or(b.total_params);
        } else if label.ends_with("num tokens") || label.ends_with("total tokens") {
            b.tokens = parse_int(value).or(b.tokens);
        } else if label.ends_with("world size") {
            hw.world_size = parse_int(value).or(hw.world_size);
        } else if label.ends_with("setting seed") || label.ends_with("random seed") {
            seeds.seed = parse_int(value).or(seeds.seed);
        } else if label.ends_with("train loss") || label.ends_with("final loss") {
            if parse_micros(value).is_some() {
                s.note_loss(value);
            }
        }
    }
}

/// Split `  Num examples = 50000` into a normalised label and its value.
fn split_label(segment: &str) -> Option<(String, &str)> {
    let cut = segment
        .char_indices()
        .find(|(_, c)| *c == '=' || *c == ':')
        .map(|(i, c)| (i, c.len_utf8()))?;
    let label_raw = segment.get(..cut.0)?;
    let value = segment.get(cut.0 + cut.1..)?;
    if !label_raw.trim().contains(' ') {
        return None;
    }
    let mut label = String::new();
    let mut space = false;
    for c in label_raw.chars() {
        if c.is_whitespace() {
            space = !label.is_empty();
        } else {
            if space {
                label.push(' ');
                space = false;
            }
            for l in c.to_lowercase() {
                label.push(l);
            }
        }
    }
    Some((label, value))
}

fn number_field(v: &str) -> Option<FieldValue> {
    if let Some(n) = parse_int(v) {
        Some(FieldValue::Int(n))
    } else if parse_micros(v).is_some() {
        Some(FieldValue::Num(v.to_string()))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Pair scanning
// ---------------------------------------------------------------------------

fn is_key_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')
}

/// Extract `key=value`, `'key': value` and `"key": value` pairs from one line.
///
/// Nested structures are skipped rather than flattened: a value that opens a `{` or
/// `[` is consumed and contributes nothing, so a nested `loss` never masquerades as
/// the top-level one.
fn scan_pairs(line: &str, out: &mut Vec<(String, String)>) {
    let b = line.as_bytes();
    let mut i = 0usize;
    while i < b.len() && out.len() < MAX_PAIRS_PER_LINE {
        let c = b[i];
        match c {
            b'"' | b'\'' => {
                let (key, next) = read_quoted(line, i);
                i = next;
                let j = skip_spaces(b, i);
                if b.get(j) == Some(&b':') {
                    let (value, next) = read_value(line, j + 1, true);
                    i = next;
                    if let (Some(k), Some(v)) = (key, value) {
                        push_pair(out, &k, &v);
                    }
                }
            }
            _ if is_key_byte(c) => {
                let start = i;
                while i < b.len() && is_key_byte(b[i]) {
                    i += 1;
                }
                let key = line.get(start..i).unwrap_or("");
                if b.get(i) == Some(&b'=') && b.get(i + 1) != Some(&b'=') {
                    let (value, next) = read_value(line, i + 1, false);
                    i = next;
                    if let Some(v) = value {
                        push_pair(out, key, &v);
                    }
                } else if b.get(i) == Some(&b':') {
                    // A bare `loss: 1.23`. Restricted to numeric values so that
                    // `INFO: Saving ...` is not read as a field.
                    let (value, next) = read_value(line, i + 1, true);
                    if let Some(v) = value {
                        if parse_micros(&v).is_some() {
                            i = next;
                            push_pair(out, key, &v);
                        }
                    }
                }
            }
            _ => i += 1,
        }
    }
}

fn push_pair(out: &mut Vec<(String, String)>, key: &str, value: &str) {
    let key = key.trim().trim_matches(|c| c == '"' || c == '\'').to_ascii_lowercase();
    if key.is_empty() || key.len() > 64 {
        return;
    }
    let value = value.trim();
    if value.len() > 512 {
        return;
    }
    out.push((key, value.to_string()));
}

fn skip_spaces(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b.get(i), Some(b' ') | Some(b'\t')) {
        i += 1;
    }
    i
}

/// Read a quoted run starting at `i`. Returns the content and the index past the
/// closing quote, or past the opening quote when the string never closes.
fn read_quoted(line: &str, i: usize) -> (Option<String>, usize) {
    let b = line.as_bytes();
    let Some(&quote) = b.get(i) else { return (None, i + 1) };
    let start = i + 1;
    let mut j = start;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            c if c == quote => {
                return (line.get(start..j).map(|s| s.to_string()), j + 1);
            }
            _ => j += 1,
        }
    }
    (None, b.len())
}

/// Read the value that follows a `=` or `:` at `i`.
///
/// `structured` selects the terminator set: a dict or JSON value ends at a comma or a
/// closing bracket, while a bare `key=value` also ends at whitespace.
fn read_value(line: &str, i: usize, structured: bool) -> (Option<String>, usize) {
    let b = line.as_bytes();
    let mut i = skip_spaces(b, i);
    match b.get(i) {
        None => (None, i),
        Some(b'"') | Some(b'\'') => read_quoted(line, i),
        Some(b'{') | Some(b'[') => (None, skip_group(b, i)),
        _ => {
            let start = i;
            while i < b.len() {
                let c = b[i];
                let stop = c == b','
                    || c == b'}'
                    || c == b']'
                    || (!structured && (c == b' ' || c == b'\t'));
                if stop {
                    break;
                }
                i += 1;
            }
            (line.get(start..i).map(|s| s.trim().to_string()), i)
        }
    }
}

/// Skip a balanced `{...}` or `[...]`, tolerating an unbalanced tail.
fn skip_group(b: &[u8], mut i: usize) -> usize {
    let mut depth = 0i32;
    while i < b.len() {
        match b[i] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth <= 0 {
                    return i + 1;
                }
            }
            b'"' | b'\'' => {
                let quote = b[i];
                i += 1;
                while i < b.len() && b[i] != quote {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

// ---------------------------------------------------------------------------
// Numbers
// ---------------------------------------------------------------------------

/// Parse an integer, tolerating `1_000` and `1,000` grouping and a `.0` tail.
fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim().trim_matches(|c| c == '"' || c == '\'');
    let mut digits = String::new();
    let mut neg = false;
    let mut seen_point = false;
    for (idx, c) in s.char_indices() {
        match c {
            '-' if idx == 0 => neg = true,
            '+' if idx == 0 => {}
            '_' | ',' if !seen_point && idx > 0 => {}
            '.' if !seen_point && idx > 0 => seen_point = true,
            '0' if seen_point => {}
            c if c.is_ascii_digit() && !seen_point => {
                if digits.len() >= 19 {
                    return None;
                }
                digits.push(c);
            }
            _ => return None,
        }
    }
    if digits.is_empty() {
        return None;
    }
    let v = digits.parse::<i64>().ok()?;
    Some(if neg { -v } else { v })
}

/// Parse any decimal or exponential literal into millionths.
///
/// Returns `None` rather than an approximation when the value cannot be represented,
/// so nothing derived from it is ever reported as if it had been measured.
fn parse_micros(s: &str) -> Option<i64> {
    let s = s.trim().trim_matches(|c| c == '"' || c == '\'');
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut neg = false;
    if matches!(b.first(), Some(b'+') | Some(b'-')) {
        neg = b.first() == Some(&b'-');
        i = 1;
    }
    let mut mant: i128 = 0;
    let mut digits = 0usize;
    let mut exp: i32 = 0;
    let mut seen = false;
    while i < b.len() && b[i].is_ascii_digit() {
        seen = true;
        if digits < 24 {
            mant = mant * 10 + i128::from(b[i] - b'0');
            digits += 1;
        } else {
            exp = exp.saturating_add(1);
        }
        i += 1;
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            seen = true;
            if digits < 24 {
                mant = mant * 10 + i128::from(b[i] - b'0');
                digits += 1;
                exp = exp.saturating_sub(1);
            }
            i += 1;
        }
    }
    if !seen {
        return None;
    }
    if matches!(b.get(i), Some(b'e') | Some(b'E')) {
        i += 1;
        let mut eneg = false;
        if matches!(b.get(i), Some(b'+') | Some(b'-')) {
            eneg = b.get(i) == Some(&b'-');
            i += 1;
        }
        let mut e: i32 = 0;
        let mut any = false;
        while i < b.len() && b[i].is_ascii_digit() {
            any = true;
            e = e.saturating_mul(10).saturating_add(i32::from(b[i] - b'0')).min(100_000);
            i += 1;
        }
        if !any {
            return None;
        }
        exp = exp.saturating_add(if eneg { -e } else { e });
    }
    if i != b.len() {
        return None;
    }
    let mut scale = exp.saturating_add(6);
    let mut v = mant;
    let mut guard = 0;
    while scale > 0 {
        v = v.checked_mul(10)?;
        scale -= 1;
        guard += 1;
        if guard > 64 {
            return None;
        }
    }
    while scale < 0 {
        v /= 10;
        scale += 1;
        if v == 0 {
            scale = 0;
        }
        guard += 1;
        if guard > 4096 {
            return None;
        }
    }
    let v = if neg { -v } else { v };
    i64::try_from(v).ok()
}

/// Seconds, truncated toward zero. `train_runtime` is normally fractional.
fn parse_seconds(s: &str) -> Option<i64> {
    parse_micros(s).map(|m| m / 1_000_000)
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Find the first `YYYY-MM-DD?HH:MM:SS` run in a line, with optional fractional
/// seconds and optional `Z` or `+HH:MM` offset.
fn find_timestamp(line: &str) -> Option<Stamp> {
    let b = line.as_bytes();
    let mut i = 0usize;
    while i + 19 <= b.len() {
        if let Some(end) = timestamp_at(b, i) {
            let raw = line.get(i..end)?.to_string();
            let rfc3339 = normalise(line, i);
            return Some(Stamp { raw, rfc3339 });
        }
        i += 1;
    }
    None
}

/// End index of a timestamp starting at `i`, or `None`.
fn timestamp_at(b: &[u8], i: usize) -> Option<usize> {
    let digit = |k: usize| b.get(k).is_some_and(|c| c.is_ascii_digit());
    let at = |k: usize, c: u8| b.get(k) == Some(&c);
    let shape = digit(i)
        && digit(i + 1)
        && digit(i + 2)
        && digit(i + 3)
        && at(i + 4, b'-')
        && digit(i + 5)
        && digit(i + 6)
        && at(i + 7, b'-')
        && digit(i + 8)
        && digit(i + 9)
        && matches!(b.get(i + 10), Some(b'T') | Some(b' ') | Some(b'_'))
        && digit(i + 11)
        && digit(i + 12)
        && at(i + 13, b':')
        && digit(i + 14)
        && digit(i + 15)
        && at(i + 16, b':')
        && digit(i + 17)
        && digit(i + 18);
    if !shape {
        return None;
    }
    let mut j = i + 19;
    if matches!(b.get(j), Some(b'.') | Some(b',')) && b.get(j + 1).is_some_and(|c| c.is_ascii_digit())
    {
        j += 1;
        while b.get(j).is_some_and(|c| c.is_ascii_digit()) {
            j += 1;
        }
    }
    if b.get(j) == Some(&b'Z') {
        j += 1;
    } else if matches!(b.get(j), Some(b'+') | Some(b'-')) && offset_seconds(b, j).is_some() {
        j += if b.get(j + 3) == Some(&b':') { 6 } else { 5 };
    }
    Some(j)
}

/// Signed seconds of a `+HH:MM` or `+HHMM` offset beginning at `j`.
fn offset_seconds(b: &[u8], j: usize) -> Option<i64> {
    let sign: i64 = match b.get(j) {
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return None,
    };
    let d = |k: usize| b.get(k).filter(|c| c.is_ascii_digit()).map(|c| i64::from(c - b'0'));
    let h = d(j + 1)? * 10 + d(j + 2)?;
    let m = if b.get(j + 3) == Some(&b':') {
        d(j + 4)? * 10 + d(j + 5)?
    } else {
        d(j + 3)? * 10 + d(j + 4)?
    };
    if h > 23 || m > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60))
}

/// Rewrite a timestamp at `i` into the strict RFC 3339 form the rule engine parses.
///
/// A numeric offset is applied so the emitted value is genuinely UTC. A shape that
/// does not survive [`Timestamp::parse_rfc3339`] yields `None` and only the raw text
/// is recorded — an unparsed timestamp is missing evidence, never a wrong one.
fn normalise(line: &str, i: usize) -> Option<String> {
    let b = line.as_bytes();
    let date = line.get(i..i + 10)?;
    let time = line.get(i + 11..i + 19)?;
    let t = Timestamp::parse_rfc3339(&format!("{date}T{time}Z")).ok()?;
    let mut j = i + 19;
    if matches!(b.get(j), Some(b'.') | Some(b',')) {
        j += 1;
        while b.get(j).is_some_and(|c| c.is_ascii_digit()) {
            j += 1;
        }
    }
    let shifted = match offset_seconds(b, j) {
        Some(off) => Timestamp(t.0.checked_sub(off)?),
        None => t,
    };
    Some(shifted.to_rfc3339())
}

/// Remove a leading timestamp, with its surrounding brackets, so that label parsing
/// does not trip over the colons inside `03:04:05`.
fn strip_leading_timestamp(line: &str) -> &str {
    let b = line.as_bytes();
    let bracket = b.first() == Some(&b'[');
    let start = usize::from(bracket);
    let Some(mut end) = timestamp_at(b, start) else { return line };
    if bracket {
        while b.get(end).is_some_and(|c| *c != b']') {
            end += 1;
        }
        if b.get(end) == Some(&b']') {
            end += 1;
        }
    }
    line.get(end..).unwrap_or(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ParseOutput {
        parse_tail(text.as_bytes(), &Limits::default(), false).expect("log parse")
    }

    fn field<'a>(out: &'a ParseOutput, kind: FactKind, key: &str) -> Option<&'a FieldValue> {
        out.facts_of(kind).find_map(|f| f.get(key))
    }

    fn int(out: &ParseOutput, kind: FactKind, key: &str) -> Option<i64> {
        field(out, kind, key).and_then(|v| v.as_int())
    }

    fn text<'a>(out: &'a ParseOutput, kind: FactKind, key: &str) -> Option<&'a str> {
        field(out, kind, key).and_then(|v| v.as_text())
    }

    // -- shapes ------------------------------------------------------------

    #[test]
    fn hf_trainer_dict_lines_become_one_series() {
        let log = "\
{'loss': 2.4012, 'learning_rate': 5e-05, 'epoch': 0.12}
{'loss': 1.8000, 'learning_rate': 4e-05, 'epoch': 0.24}
{'loss': 1.2006, 'learning_rate': 3e-05, 'epoch': 0.36}
";
        let out = parse(log);
        assert_eq!(int(&out, FactKind::TrainingMetric, "entry_count"), Some(3));
        assert_eq!(text(&out, FactKind::TrainingMetric, "first_loss"), Some("2.4012"));
        assert_eq!(text(&out, FactKind::TrainingMetric, "last_loss"), Some("1.2006"));
        // 50% exactly, rounded toward zero.
        assert_eq!(int(&out, FactKind::TrainingMetric, "loss_decreasing_percent"), Some(50));
        // No step key appeared, so no ordering is asserted and no step fact exists.
        assert!(field(&out, FactKind::TrainingMetric, "steps_monotonic").is_none());
        assert_eq!(out.facts_of(FactKind::CheckpointStep).count(), 0);
    }

    #[test]
    fn key_value_lines() {
        let log = "\
step=100 loss=1.23 lr=5e-5
step=200 loss=0.90 lr=4e-5
step=300 loss=0.61 lr=3e-5
";
        let out = parse(log);
        assert_eq!(int(&out, FactKind::TrainingMetric, "entry_count"), Some(3));
        assert_eq!(int(&out, FactKind::TrainingMetric, "first_step"), Some(100));
        assert_eq!(int(&out, FactKind::TrainingMetric, "last_step"), Some(300));
        assert_eq!(
            field(&out, FactKind::TrainingMetric, "steps_monotonic").and_then(|v| v.as_bool()),
            Some(true)
        );
        let steps: Vec<i64> =
            out.facts_of(FactKind::CheckpointStep).filter_map(|f| f.get("step")?.as_int()).collect();
        assert_eq!(steps, vec![100, 300]);
    }

    #[test]
    fn jsonl_lines() {
        let log = "\
{\"global_step\": 10, \"loss\": 3.5, \"learning_rate\": 0.0001}
{\"global_step\": 20, \"loss\": 3.0, \"learning_rate\": 0.0001}
";
        let out = parse(log);
        assert_eq!(int(&out, FactKind::TrainingMetric, "entry_count"), Some(2));
        assert_eq!(int(&out, FactKind::TrainingMetric, "first_step"), Some(10));
        assert_eq!(text(&out, FactKind::TrainingMetric, "last_loss"), Some("3.0"));
    }

    #[test]
    fn running_training_banner() {
        let log = "\
***** Running training *****
  Num examples = 50,000
  Num Epochs = 3
  Instantaneous batch size per device = 4
  Total optimization steps = 4,687
  Number of trainable parameters = 4194304
";
        let out = parse(log);
        assert_eq!(int(&out, FactKind::TrainingMetric, "num_examples"), Some(50_000));
        assert_eq!(int(&out, FactKind::TrainingMetric, "num_epochs"), Some(3));
        assert_eq!(
            int(&out, FactKind::TrainingMetric, "total_optimization_steps"),
            Some(4_687)
        );
        assert_eq!(int(&out, FactKind::TrainingMetric, "entry_count"), Some(0));
    }

    #[test]
    fn trainable_and_total_parameters_from_a_peft_banner() {
        let log = "trainable params: 4,194,304 || all params: 6,742,609,920 || trainable%: 0.0622\n";
        let out = parse(log);
        assert_eq!(int(&out, FactKind::TrainableParameterRecord, "trainable"), Some(4_194_304));
        assert_eq!(int(&out, FactKind::TrainableParameterRecord, "total"), Some(6_742_609_920));
    }

    #[test]
    fn label_lines_survive_a_logging_prefix() {
        let log = "2026-01-02 03:04:05,123 INFO trainable params: 4,194,304 || all params: 100\n";
        let out = parse(log);
        assert_eq!(int(&out, FactKind::TrainableParameterRecord, "trainable"), Some(4_194_304));
    }

    // -- side records ------------------------------------------------------

    #[test]
    fn token_counts_but_never_token_rates() {
        let out = parse("step=1 total_tokens=1200000000 train_tokens_per_second=4501.2\n");
        assert_eq!(int(&out, FactKind::TokenCountRecord, "tokens"), Some(1_200_000_000));
        let out = parse("step=1 tokens_per_second=4501\n");
        assert_eq!(out.facts_of(FactKind::TokenCountRecord).count(), 0);
    }

    #[test]
    fn hardware_from_fields_and_from_free_text() {
        let out = parse("world_size=8 n_gpu=8 device=cuda:0\nTraining on 8x A100 nodes\n");
        assert_eq!(int(&out, FactKind::HardwareRecord, "world_size"), Some(8));
        assert_eq!(int(&out, FactKind::HardwareRecord, "gpu_count"), Some(8));
        assert_eq!(text(&out, FactKind::HardwareRecord, "device_name"), Some("cuda:0"));
        assert_eq!(text(&out, FactKind::HardwareRecord, "description"), Some("8x a100"));
    }

    #[test]
    fn a_bare_number_before_x_is_not_hardware() {
        // "3x faster" and version strings must not become an accelerator inventory.
        let out = parse("throughput improved 3x faster than v1.2x baseline\n");
        assert_eq!(out.facts_of(FactKind::HardwareRecord).count(), 0);
    }

    #[test]
    fn compute_and_seed_records() {
        let out = parse(
            "{'train_runtime': 3600.75, 'total_flos': 123456789012345, 'seed': 42, 'data_seed': 7}\n",
        );
        assert_eq!(int(&out, FactKind::ComputeRecord, "wall_clock_seconds"), Some(3600));
        assert_eq!(int(&out, FactKind::ComputeRecord, "total_flos"), Some(123_456_789_012_345));
        assert_eq!(int(&out, FactKind::SeedRecord, "seed"), Some(42));
        assert_eq!(int(&out, FactKind::SeedRecord, "data_seed"), Some(7));
    }

    #[test]
    fn checkpoint_directories_become_steps() {
        let log = "\
2026-01-02T03:04:05Z Saving model checkpoint to out/checkpoint-500
2026-01-02T03:40:05Z Saving model checkpoint to out/checkpoint-1000
";
        let out = parse(log);
        let steps: Vec<i64> =
            out.facts_of(FactKind::CheckpointStep).filter_map(|f| f.get("step")?.as_int()).collect();
        assert_eq!(steps, vec![500, 1000]);
    }

    // -- ordering ----------------------------------------------------------

    #[test]
    fn out_of_order_steps_are_reported_as_such() {
        let out = parse("step=300 loss=1.0\nstep=100 loss=0.9\n");
        assert_eq!(
            field(&out, FactKind::TrainingMetric, "steps_monotonic").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn a_single_step_asserts_no_ordering() {
        // families::dense turns `steps_monotonic = false` into a contradiction, so a
        // one-entry series must not claim an ordering it never observed.
        let out = parse("step=100 loss=1.0\n");
        assert!(field(&out, FactKind::TrainingMetric, "steps_monotonic").is_none());
    }

    #[test]
    fn rising_loss_yields_a_negative_percentage_not_a_verdict() {
        let out = parse("step=1 loss=1.0\nstep=2 loss=2.0\n");
        assert_eq!(int(&out, FactKind::TrainingMetric, "loss_decreasing_percent"), Some(-100));
    }

    // -- chronology --------------------------------------------------------

    #[test]
    fn chronology_pairs_a_start_with_a_later_checkpoint() {
        let log = "\
2026-01-02T03:00:00Z ***** Running training *****
2026-01-02T04:00:00Z Saving model checkpoint to out/checkpoint-500
";
        let out = parse(log);
        assert_eq!(
            text(&out, FactKind::FileChronology, "run_started_at"),
            Some("2026-01-02T03:00:00Z")
        );
        assert_eq!(
            text(&out, FactKind::FileChronology, "checkpoint_at"),
            Some("2026-01-02T04:00:00Z")
        );
    }

    #[test]
    fn a_checkpoint_from_an_earlier_run_is_not_paired() {
        // Two runs concatenated in one tail. Pairing across them would manufacture a
        // TT-CHRONO-004 contradiction out of ordinary log rotation.
        let log = "\
2026-01-01T09:00:00Z Saving model checkpoint to out/checkpoint-9000
2026-01-02T03:00:00Z ***** Running training *****
";
        let out = parse(log);
        assert_eq!(
            text(&out, FactKind::FileChronology, "run_started_at"),
            Some("2026-01-02T03:00:00Z")
        );
        assert!(field(&out, FactKind::FileChronology, "checkpoint_at").is_none());
    }

    #[test]
    fn timestamp_offsets_are_converted_to_utc() {
        let log = "2026-01-02 05:00:00+02:00 Starting training run\n";
        let out = parse(log);
        assert_eq!(
            text(&out, FactKind::FileChronology, "run_started_at"),
            Some("2026-01-02T03:00:00Z")
        );
        assert_eq!(
            text(&out, FactKind::FileChronology, "run_started_at_text"),
            Some("2026-01-02 05:00:00+02:00")
        );
    }

    #[test]
    fn emitted_chronology_parses_under_the_rule_engines_reader() {
        let out = parse("[2026-01-02 03:04:05,123] INFO Running training\n");
        let v = text(&out, FactKind::FileChronology, "run_started_at").expect("normalised");
        assert!(Timestamp::parse_rfc3339(v).is_ok(), "{v}");
    }

    #[test]
    fn an_impossible_date_is_kept_as_text_and_never_normalised() {
        let out = parse("2026-02-30 03:04:05 Running training\n");
        assert_eq!(
            text(&out, FactKind::FileChronology, "run_started_at_text"),
            Some("2026-02-30 03:04:05")
        );
        assert!(field(&out, FactKind::FileChronology, "run_started_at").is_none());
    }

    // -- abuse -------------------------------------------------------------

    #[test]
    fn a_log_larger_than_the_tail_limit_is_trimmed_and_says_so() {
        let mut log = String::new();
        for i in 0..400_000 {
            log.push_str(&format!("step={i} loss=1.0\n"));
        }
        assert!(log.len() > Limits::default().log_tail_bytes as usize);
        let out = parse_tail(log.as_bytes(), &Limits::default(), false).unwrap();
        assert!(out.has_note(NOTE_ID));
        let entries = int(&out, FactKind::TrainingMetric, "entry_count").unwrap_or(0);
        assert!(entries > 0 && entries < 400_000, "{entries}");
    }

    #[test]
    fn a_ten_megabyte_line_is_skipped_rather_than_read() {
        let mut log = String::from("step=1 loss=1.0\n");
        log.push_str(&"a".repeat(10 * 1024 * 1024));
        log.push('\n');
        log.push_str("step=2 loss=0.5\n");
        let out = parse_tail(log.as_bytes(), &Limits::default(), false).unwrap();
        assert!(out.has_note(NOTE_ID));
        // The readable lines on either side of it survive.
        assert!(int(&out, FactKind::TrainingMetric, "entry_count").unwrap_or(0) >= 1);
    }

    #[test]
    fn a_line_crafted_to_hold_a_million_pairs_is_capped() {
        let line = "a=1 ".repeat(200_000);
        let out = parse_tail(line.as_bytes(), &Limits::default(), false).unwrap();
        assert_eq!(out.facts.len(), 0);
    }

    #[test]
    fn deep_nesting_in_one_line_does_not_recurse() {
        let line = format!("{{\"loss\": {}1{}}}", "[".repeat(50_000), "]".repeat(50_000));
        let out = parse_tail(line.as_bytes(), &Limits::tiny(), false).unwrap();
        assert!(out.facts_of(FactKind::TrainingMetric).next().is_none());
    }

    #[test]
    fn empty_and_garbage_inputs_produce_nothing_and_never_panic() {
        for bytes in [
            &b""[..],
            &b"\n\n\n"[..],
            &[0u8, 1, 2, 3, 0xff, 0xfe][..],
            &b"{{{{{{"[..],
            &b"'''\"\"\"===:::,,,"[..],
            &b"loss="[..],
            &b"step="[..],
            &b"2026-01-02T03:04:0"[..],
        ] {
            let out = parse_tail(bytes, &Limits::default(), false).unwrap();
            assert!(out.facts_of(FactKind::TrainingMetric).next().is_none());
        }
    }

    #[test]
    fn a_suffix_read_discards_its_truncated_first_line() {
        let log = "s=1 loss=99.0\nstep=200 loss=1.0\n";
        let whole = parse_tail(log.as_bytes(), &Limits::default(), false).unwrap();
        let suffix = parse_tail(log.as_bytes(), &Limits::default(), true).unwrap();
        assert_eq!(int(&whole, FactKind::TrainingMetric, "entry_count"), Some(2));
        assert_eq!(int(&suffix, FactKind::TrainingMetric, "entry_count"), Some(1));
        assert_eq!(text(&suffix, FactKind::TrainingMetric, "first_loss"), Some("1.0"));
    }

    #[test]
    fn output_is_deterministic_for_identical_bytes() {
        let log = "\
2026-01-02T03:00:00Z ***** Running training *****
  Num examples = 10
step=1 loss=2.0 world_size=8
step=2 loss=1.0 device=cuda:1
step=3 loss=0.5 device=cuda:0
2026-01-02T04:00:00Z Saving model checkpoint to out/checkpoint-3
";
        let a = parse(log);
        let b = parse(log);
        assert_eq!(a.facts, b.facts);
        assert_eq!(a.notes, b.notes);
    }

    // -- numeric helpers ---------------------------------------------------

    #[test]
    fn micros_parsing_is_exact_or_absent() {
        assert_eq!(parse_micros("1"), Some(1_000_000));
        assert_eq!(parse_micros("1.5"), Some(1_500_000));
        assert_eq!(parse_micros("5e-5"), Some(50));
        assert_eq!(parse_micros("-2.25"), Some(-2_250_000));
        assert_eq!(parse_micros("0.0000001"), Some(0));
        assert_eq!(parse_micros(""), None);
        assert_eq!(parse_micros("abc"), None);
        assert_eq!(parse_micros("1.2.3"), None);
        assert_eq!(parse_micros("1e"), None);
        // Far outside i64 micros: absent rather than saturated.
        assert_eq!(parse_micros("1e40"), None);
        assert_eq!(parse_micros(&"9".repeat(400)), None);
    }

    #[test]
    fn integer_parsing_rejects_what_it_cannot_represent() {
        assert_eq!(parse_int("1000"), Some(1000));
        assert_eq!(parse_int("1,000"), Some(1000));
        assert_eq!(parse_int("1_000"), Some(1000));
        assert_eq!(parse_int("-5"), Some(-5));
        assert_eq!(parse_int("3.0"), Some(3));
        assert_eq!(parse_int("3.5"), None);
        assert_eq!(parse_int(&"9".repeat(30)), None);
        assert_eq!(parse_int("abc"), None);
        assert_eq!(parse_int(""), None);
    }

    #[test]
    fn nested_values_never_masquerade_as_top_level_ones() {
        let mut pairs = Vec::new();
        scan_pairs("{\"a\": {\"loss\": 9.0}, \"loss\": 1.0}", &mut pairs);
        let losses: Vec<&String> =
            pairs.iter().filter(|(k, _)| k == "loss").map(|(_, v)| v).collect();
        assert_eq!(losses, vec!["1.0"]);
    }

    #[test]
    fn a_bare_colon_pair_is_only_read_when_numeric() {
        let mut pairs = Vec::new();
        scan_pairs("INFO: Saving model checkpoint to out", &mut pairs);
        assert!(pairs.iter().all(|(k, _)| k != "info"), "{pairs:?}");
        pairs.clear();
        scan_pairs("loss: 1.25", &mut pairs);
        assert_eq!(pairs, vec![("loss".to_string(), "1.25".to_string())]);
    }
}
