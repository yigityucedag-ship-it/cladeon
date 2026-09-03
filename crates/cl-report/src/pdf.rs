//! A minimal, deterministic PDF 1.7 writer, and a reader for the PDFs it writes.
//!
//! ## Why this exists at all
//!
//! `report.pdf` is a bundle entry whose SHA-256 sits inside the integrity envelope,
//! so two scans of the same evidence must produce the *same bytes*. Every general
//! purpose PDF library reachable from crates.io stamps a `CreationDate`, a random
//! file `ID`, and often a producer build hash, and none of them may parse untrusted
//! bytes here in any case (`Cargo.toml`, dependency policy). So the writer is local,
//! it takes its file `ID` from the caller's document digest, and it never reads a
//! clock. Building twice from the same builder yields byte-identical output, and
//! that is asserted, not assumed.
//!
//! ## Why the reader exists
//!
//! Two checks have to run over the *rendered* document rather than over the model
//! that produced it:
//!
//! * the forbidden-language guard (`docs/00-FROZEN-VOCABULARY.md` §2) must see what
//!   a reader sees, because a phrase can be assembled from a heading plus a table
//!   cell that neither string contains on its own; and
//! * Verify has to recover the footer tint raster to compare it against
//!   `forensic-markers.json`.
//!
//! Both therefore read the PDF back. The reader is deliberately not a general PDF
//! parser: it recognises the small, fixed shape this writer emits, and on anything
//! else it returns [`ClError`] rather than guessing. It is nonetheless written to
//! the same standard as the vendor-facing parsers, because a `.clade` arriving from
//! the party under scrutiny is hostile input by definition — bounded, no panic on
//! truncation, no unbounded allocation.
//!
//! ## Why no compression
//!
//! There is no flate implementation in this workspace and adding one would mean a
//! dependency that parses bytes we later read back. Content streams and the marker
//! image are therefore stored raw. For the marker that is a feature: the tint
//! carrier is recoverable by a reader anyone can audit in an afternoon, which is the
//! only honest position for a marker that is explicitly *not* a root of trust.
//!
//! ## Fonts
//!
//! Helvetica and Helvetica-Bold are base-14 Type1 fonts, so nothing is embedded. But
//! the advance widths still have to be exact: wrapping decides where a line ends, and
//! a table of guessed widths puts a 64-character digest through the right margin.
//! The two AFM width tables are therefore transcribed in full below, indexed by
//! WinAnsi code, and all layout arithmetic is integer millipoints — no floating point
//! anywhere, so the same input cannot lay out two ways.
//!
//! ## Bounds
//!
//! Reader bounds come from [`Limits`]: `config_bytes` caps both the PDF accepted and
//! the text recovered from it, `json_max_string_bytes` caps one literal string, and
//! `json_max_object_keys` caps the number of streams examined. The writer's own caps
//! are constants here because they bound *our* output, not vendor input.

use cl_core::error::{ClError, ClResult};
use cl_core::limits::Limits;
use cl_core::raster::Raster;

// ---------------------------------------------------------------------------
// Page geometry, in millipoints (1/1000 pt). US Letter, 54 pt margins.
// ---------------------------------------------------------------------------

const PAGE_W_MP: i64 = 612_000;
const PAGE_H_MP: i64 = 792_000;
const MARGIN_MP: i64 = 54_000;
/// Top of the first line box on a page.
const CONTENT_TOP_MP: i64 = PAGE_H_MP - MARGIN_MP;
/// Body text stops here; below it is the footer band.
const CONTENT_BOTTOM_MP: i64 = 60_000;
const TEXT_W_MP: i64 = PAGE_W_MP - 2 * MARGIN_MP;

/// Bottom edge of the footer raster.
const FOOTER_IMAGE_Y_MP: i64 = 24_000;
/// Baseline of the footer text line.
const FOOTER_TEXT_Y_MP: i64 = 28_000;
const FOOTER_SIZE: i64 = 7;
/// Largest the footer raster may be drawn.
const FOOTER_IMAGE_MAX_W_MP: i64 = 200_000;
const FOOTER_IMAGE_MAX_H_MP: i64 = 24_000;

const SIZE_BODY: i64 = 10;
const SIZE_H1: i64 = 16;
const SIZE_H2: i64 = 13;
const SIZE_H3: i64 = 11;

/// Line height as a multiple of the font size, in thousandths.
const LEADING: i64 = 1200;
/// Baseline drop from the top of a line box, in thousandths of the font size.
const BASELINE_DROP: i64 = 800;

const BULLET_INDENT_MP: i64 = 14_000;
const KEY_COLUMN_MP: i64 = 140_000;
const GUTTER_MP: i64 = 8_000;
const MIN_COLUMN_MP: i64 = 28_000;

// ---------------------------------------------------------------------------
// Writer caps. These bound our own output, so exceeding one is a recorded
// truncation rather than an error: `build` has no way to report a failure and a
// report that renders 90% of a hostile string is better than one that renders none.
// ---------------------------------------------------------------------------

/// Longest single string any block may carry.
const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Most blocks a document may hold.
const MAX_BLOCKS: usize = 65_536;
/// Most columns a table may have.
const MAX_COLUMNS: usize = 12;
/// Most rows a table may have.
const MAX_TABLE_ROWS: usize = 8192;
/// Most pages a document may occupy.
const MAX_PAGES: usize = 4096;
/// Largest footer raster accepted, in bytes.
const MAX_RASTER_BYTES: usize = 4 * 1024 * 1024;
/// Marker appended to a string the writer had to shorten, so a truncated value is
/// never presented as a whole one.
const TRUNCATION_SUFFIX: &[u8] = b" [truncated]";

// ---------------------------------------------------------------------------
// Base-14 advance widths, 1/1000 em, indexed by WinAnsi code.
// Transcribed from the Adobe Core font metrics. Zero marks a code with no glyph
// in WinAnsiEncoding; the encoder never produces one.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const HELVETICA_W: [u16; 256] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,
    556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,
    1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,
    667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,
    333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,
    556,556,333,500,278,556,500,722,500,500,500,334,260,334,584,0,
    556,0,222,556,333,1000,556,556,333,1000,667,333,1000,0,611,0,
    0,222,222,333,333,350,556,1000,333,1000,500,333,944,0,500,667,
    278,333,556,556,556,556,260,556,333,737,370,556,584,333,737,333,
    400,584,333,333,333,556,537,278,333,333,365,556,834,834,834,611,
    667,667,667,667,667,667,1000,722,667,667,667,667,278,278,278,278,
    722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,
    556,556,556,556,556,556,889,500,556,556,556,556,278,278,278,278,
    556,556,556,556,556,556,556,584,611,556,556,556,556,500,556,500,
];

#[rustfmt::skip]
const HELVETICA_BOLD_W: [u16; 256] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,
    556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
    975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,
    667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
    333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,
    611,611,389,556,333,611,556,778,556,556,500,389,280,389,584,0,
    556,0,278,556,500,1000,556,556,333,1000,667,333,1000,0,611,0,
    0,278,278,500,500,350,556,1000,333,1000,556,333,944,0,500,667,
    278,333,556,556,556,556,280,556,333,737,370,556,584,333,737,333,
    400,584,333,333,333,611,556,278,333,333,365,556,834,834,834,611,
    722,722,722,722,722,722,1000,722,667,667,667,667,278,278,278,278,
    722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,
    556,556,556,556,556,556,889,556,556,556,556,556,278,278,278,278,
    611,611,611,611,611,611,611,584,611,611,611,611,611,556,611,556,
];

/// The two faces this writer can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Font {
    Regular,
    Bold,
}

impl Font {
    fn resource(self) -> &'static str {
        match self {
            Font::Regular => "/F1",
            Font::Bold => "/F2",
        }
    }
    fn table(self) -> &'static [u16; 256] {
        match self {
            Font::Regular => &HELVETICA_W,
            Font::Bold => &HELVETICA_BOLD_W,
        }
    }
}

/// Advance of one WinAnsi code at `size` points, in millipoints.
fn width_mp(font: Font, size: i64, code: u8) -> i64 {
    (font.table()[code as usize] as i64).saturating_mul(size)
}

/// Advance of a WinAnsi byte run at `size` points, in millipoints.
fn run_width_mp(font: Font, size: i64, bytes: &[u8]) -> i64 {
    let mut units: i64 = 0;
    for b in bytes {
        units = units.saturating_add(font.table()[*b as usize] as i64);
    }
    units.saturating_mul(size)
}

// ---------------------------------------------------------------------------
// WinAnsiEncoding
// ---------------------------------------------------------------------------

/// WinAnsi code for a character, or `None` when the encoding has no glyph for it.
///
/// Tab, carriage return and newline map to a space rather than to the substitute:
/// they are layout, not content, and turning a line break into `?` would look like
/// data loss where there is none.
fn winansi_code(c: char) -> Option<u8> {
    match c {
        '\t' | '\n' | '\r' => Some(b' '),
        '\u{20}'..='\u{7E}' => Some(c as u8),
        '\u{A0}'..='\u{FF}' => Some(c as u32 as u8),
        '\u{20AC}' => Some(128),
        '\u{201A}' => Some(130),
        '\u{0192}' => Some(131),
        '\u{201E}' => Some(132),
        '\u{2026}' => Some(133),
        '\u{2020}' => Some(134),
        '\u{2021}' => Some(135),
        '\u{02C6}' => Some(136),
        '\u{2030}' => Some(137),
        '\u{0160}' => Some(138),
        '\u{2039}' => Some(139),
        '\u{0152}' => Some(140),
        '\u{017D}' => Some(142),
        '\u{2018}' => Some(145),
        '\u{2019}' => Some(146),
        '\u{201C}' => Some(147),
        '\u{201D}' => Some(148),
        '\u{2022}' => Some(149),
        '\u{2013}' => Some(150),
        '\u{2014}' => Some(151),
        '\u{02DC}' => Some(152),
        '\u{2122}' => Some(153),
        '\u{0161}' => Some(154),
        '\u{203A}' => Some(155),
        '\u{0153}' => Some(156),
        '\u{017E}' => Some(158),
        '\u{0178}' => Some(159),
        _ => None,
    }
}

/// Character for a WinAnsi code. `None` for codes the encoding leaves undefined.
fn winansi_char(code: u8) -> Option<char> {
    match code {
        0x20..=0x7E => Some(code as char),
        0xA0..=0xFF => char::from_u32(code as u32),
        128 => Some('\u{20AC}'),
        130 => Some('\u{201A}'),
        131 => Some('\u{0192}'),
        132 => Some('\u{201E}'),
        133 => Some('\u{2026}'),
        134 => Some('\u{2020}'),
        135 => Some('\u{2021}'),
        136 => Some('\u{02C6}'),
        137 => Some('\u{2030}'),
        138 => Some('\u{0160}'),
        139 => Some('\u{2039}'),
        140 => Some('\u{0152}'),
        142 => Some('\u{017D}'),
        145 => Some('\u{2018}'),
        146 => Some('\u{2019}'),
        147 => Some('\u{201C}'),
        148 => Some('\u{201D}'),
        149 => Some('\u{2022}'),
        150 => Some('\u{2013}'),
        151 => Some('\u{2014}'),
        152 => Some('\u{02DC}'),
        153 => Some('\u{2122}'),
        154 => Some('\u{0161}'),
        155 => Some('\u{203A}'),
        156 => Some('\u{0153}'),
        158 => Some('\u{017E}'),
        159 => Some('\u{0178}'),
        _ => None,
    }
}

/// Encode text to WinAnsi, returning the bytes and the number of characters that had
/// no mapping and became `?`.
fn encode_winansi(s: &str) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(s.len());
    let mut unmapped = 0usize;
    for c in s.chars() {
        match winansi_code(c) {
            Some(b) => out.push(b),
            None => {
                out.push(b'?');
                unmapped += 1;
            }
        }
    }
    (out, unmapped)
}

/// Decode a WinAnsi byte run. Undefined codes become U+FFFD, which marks the loss
/// instead of inventing a character that was never in the file.
fn decode_winansi(bytes: &[u8], out: &mut String) {
    for b in bytes {
        out.push(winansi_char(*b).unwrap_or('\u{FFFD}'));
    }
}

/// Escape a WinAnsi run for a PDF literal string.
fn escape_pdf_string(bytes: &[u8], out: &mut Vec<u8>) {
    for b in bytes {
        match *b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(*b);
            }
            c if c < 0x20 || c == 0x7F => {
                // Octal, so a control byte can never terminate the string early.
                out.push(b'\\');
                out.push(b'0' + ((c >> 6) & 7));
                out.push(b'0' + ((c >> 3) & 7));
                out.push(b'0' + (c & 7));
            }
            c => out.push(c),
        }
    }
}

/// Format millipoints as a PDF real with no trailing zeros.
fn mp(v: i64) -> String {
    let neg = v < 0;
    let a = v.unsigned_abs();
    let whole = a / 1000;
    let frac = a % 1000;
    let mut s = String::new();
    if neg && (whole != 0 || frac != 0) {
        s.push('-');
    }
    s.push_str(&whole.to_string());
    if frac != 0 {
        let mut f = format!("{frac:03}");
        while f.ends_with('0') {
            f.pop();
        }
        s.push('.');
        s.push_str(&f);
    }
    s
}

// ---------------------------------------------------------------------------
// Word wrapping
// ---------------------------------------------------------------------------

/// Break a WinAnsi run into lines no wider than `max_mp`.
///
/// A token wider than the whole column — a 64-character digest is the case that
/// matters — is split at whatever character still fits rather than allowed through
/// the margin. Progress is guaranteed: at least one byte leaves the token every
/// iteration, so the loop terminates even for a one-character-wide column.
fn wrap(bytes: &[u8], font: Font, size: i64, max_mp: i64) -> Vec<Vec<u8>> {
    let max_mp = max_mp.max(size);
    let space_w = width_mp(font, size, b' ');
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    let mut line_w: i64 = 0;

    for word in bytes.split(|c| *c == b' ') {
        if word.is_empty() {
            continue;
        }
        let mut rest = word;
        loop {
            let ww = run_width_mp(font, size, rest);
            let need = if line.is_empty() { ww } else { line_w.saturating_add(space_w).saturating_add(ww) };
            if need <= max_mp {
                if !line.is_empty() {
                    line.push(b' ');
                    line_w = line_w.saturating_add(space_w);
                }
                line.extend_from_slice(rest);
                line_w = line_w.saturating_add(ww);
                break;
            }
            if !line.is_empty() {
                out.push(std::mem::take(&mut line));
                line_w = 0;
                continue;
            }
            let mut take = 0usize;
            let mut acc: i64 = 0;
            for (k, c) in rest.iter().enumerate() {
                let cw = width_mp(font, size, *c);
                if k > 0 && acc.saturating_add(cw) > max_mp {
                    break;
                }
                acc = acc.saturating_add(cw);
                take = k + 1;
            }
            out.push(rest[..take].to_vec());
            rest = &rest[take..];
            if rest.is_empty() {
                break;
            }
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(Vec::new());
    }
    out
}

// ---------------------------------------------------------------------------
// Blocks and laid-out pages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Block {
    Heading { level: u8, text: Vec<u8> },
    Paragraph(Vec<u8>),
    Bullet(Vec<u8>),
    KeyValue { key: Vec<u8>, value: Vec<u8> },
    Table { headers: Vec<Vec<u8>>, rows: Vec<Vec<Vec<u8>>> },
    Rule,
    PageBreak,
}

/// One drawing instruction, already positioned. Layout produces these; content
/// stream generation only serialises them, so the two concerns cannot disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Text { x: i64, y: i64, font: Font, size: i64, bytes: Vec<u8> },
    HLine { x0: i64, x1: i64, y: i64 },
}

#[derive(Debug, Clone, Default)]
struct Page {
    ops: Vec<Op>,
}

struct Layout {
    pages: Vec<Page>,
    ops: Vec<Op>,
    /// Top of the next line box.
    y: i64,
    full: bool,
}

impl Layout {
    fn new() -> Self {
        Layout { pages: Vec::new(), ops: Vec::new(), y: CONTENT_TOP_MP, full: false }
    }

    fn at_page_top(&self) -> bool {
        self.ops.is_empty() && self.y == CONTENT_TOP_MP
    }

    fn new_page(&mut self) {
        if self.pages.len() + 1 >= MAX_PAGES {
            self.full = true;
            return;
        }
        self.pages.push(Page { ops: std::mem::take(&mut self.ops) });
        self.y = CONTENT_TOP_MP;
    }

    /// Make room for `h` millipoints, breaking the page if it will not fit.
    fn ensure(&mut self, h: i64) {
        if self.y - h < CONTENT_BOTTOM_MP && !self.at_page_top() {
            self.new_page();
        }
    }

    fn gap(&mut self, h: i64) {
        if !self.at_page_top() {
            self.y -= h;
        }
    }

    fn line(&mut self, x: i64, font: Font, size: i64, bytes: Vec<u8>) {
        let lh = size * LEADING;
        self.ensure(lh);
        let y = self.y - size * BASELINE_DROP;
        self.ops.push(Op::Text { x, y, font, size, bytes });
        self.y -= lh;
    }

    fn finish(mut self) -> Vec<Page> {
        self.pages.push(Page { ops: std::mem::take(&mut self.ops) });
        self.pages
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Accumulates logical blocks, then lays them out and serialises a PDF.
///
/// Pagination happens in [`PdfBuilder::build`] rather than as blocks arrive, so the
/// same builder always produces the same document and callers never have to think
/// about page boundaries.
pub struct PdfBuilder {
    title: Vec<u8>,
    footer_note: Vec<u8>,
    footer_raster: Option<Raster>,
    footer_raster_rejected: bool,
    blocks: Vec<Block>,
    unmapped: usize,
    truncated: usize,
    dropped: usize,
}

impl PdfBuilder {
    /// A document with a title (used for `/Info /Title`) and a footer note printed on
    /// every page.
    pub fn new(title: &str, footer_note: &str) -> Self {
        let mut b = PdfBuilder {
            title: Vec::new(),
            footer_note: Vec::new(),
            footer_raster: None,
            footer_raster_rejected: false,
            blocks: Vec::new(),
            unmapped: 0,
            truncated: 0,
            dropped: 0,
        };
        b.title = b.take_text(title);
        b.footer_note = b.take_text(footer_note);
        b
    }

    /// Encode caller text, capping its length and recording both substitutions and
    /// truncation so neither is silent.
    fn take_text(&mut self, s: &str) -> Vec<u8> {
        let (mut bytes, unmapped) = encode_winansi(s);
        self.unmapped += unmapped;
        if bytes.len() > MAX_TEXT_BYTES {
            bytes.truncate(MAX_TEXT_BYTES);
            bytes.extend_from_slice(TRUNCATION_SUFFIX);
            self.truncated += 1;
        }
        bytes
    }

    fn push(&mut self, b: Block) {
        if self.blocks.len() >= MAX_BLOCKS {
            self.dropped += 1;
            return;
        }
        self.blocks.push(b);
    }

    /// Install the footer tint carrier. A raster whose dimensions and buffer length
    /// disagree, or one over the size cap, is rejected rather than drawn partially;
    /// [`PdfBuilder::footer_raster_accepted`] reports which happened.
    pub fn set_footer_raster(&mut self, r: cl_core::raster::Raster) {
        let expect = (r.width as usize)
            .checked_mul(r.height as usize)
            .and_then(|n| n.checked_mul(3));
        let ok = r.width > 0
            && r.height > 0
            && expect == Some(r.rgb.len())
            && r.rgb.len() <= MAX_RASTER_BYTES;
        if ok {
            self.footer_raster = Some(r);
            self.footer_raster_rejected = false;
        } else {
            self.footer_raster = None;
            self.footer_raster_rejected = true;
        }
    }

    /// Section heading. Levels above 3 render as level 3.
    pub fn heading(&mut self, level: u8, text: &str) {
        let text = self.take_text(text);
        self.push(Block::Heading { level: level.clamp(1, 3), text });
    }

    /// Body paragraph, wrapped to the text column.
    pub fn paragraph(&mut self, text: &str) {
        let t = self.take_text(text);
        self.push(Block::Paragraph(t));
    }

    /// Bulleted item with a hanging indent.
    pub fn bullet(&mut self, text: &str) {
        let t = self.take_text(text);
        self.push(Block::Bullet(t));
    }

    /// A bold label and its value, side by side in two columns.
    pub fn key_value(&mut self, key: &str, value: &str) {
        let key = self.take_text(key);
        let value = self.take_text(value);
        self.push(Block::KeyValue { key, value });
    }

    /// A table with a bold header row that repeats after every page break.
    ///
    /// Columns beyond [`MAX_COLUMNS`] and rows beyond [`MAX_TABLE_ROWS`] are dropped
    /// and counted; a row shorter than the header is padded with empty cells.
    pub fn table(&mut self, headers: &[&str], rows: &[Vec<String>]) {
        if headers.is_empty() {
            self.dropped += 1;
            return;
        }
        let ncols = headers.len().min(MAX_COLUMNS);
        if headers.len() > ncols {
            self.dropped += 1;
        }
        let mut h = Vec::with_capacity(ncols);
        for name in headers.iter().take(ncols) {
            h.push(self.take_text(name));
        }
        let mut out_rows: Vec<Vec<Vec<u8>>> = Vec::new();
        for row in rows.iter() {
            if out_rows.len() >= MAX_TABLE_ROWS {
                self.dropped += 1;
                break;
            }
            let mut cells = Vec::with_capacity(ncols);
            for c in 0..ncols {
                match row.get(c) {
                    Some(v) => {
                        let t = self.take_text(v);
                        cells.push(t);
                    }
                    None => cells.push(Vec::new()),
                }
            }
            out_rows.push(cells);
        }
        self.push(Block::Table { headers: h, rows: out_rows });
    }

    /// A horizontal rule across the text column.
    pub fn rule(&mut self) {
        self.push(Block::Rule);
    }

    /// Force the next block onto a fresh page.
    pub fn page_break(&mut self) {
        self.push(Block::PageBreak);
    }

    /// Characters that had no WinAnsi glyph and were rendered as `?`.
    pub fn unmapped_character_count(&self) -> usize {
        self.unmapped
    }

    /// Strings the writer had to shorten to stay inside its own caps.
    pub fn truncated_text_count(&self) -> usize {
        self.truncated
    }

    /// Blocks, columns or rows discarded because a writer cap was reached.
    pub fn dropped_block_count(&self) -> usize {
        self.dropped
    }

    /// False when [`PdfBuilder::set_footer_raster`] was called with a raster this
    /// writer declined to draw.
    pub fn footer_raster_accepted(&self) -> bool {
        !self.footer_raster_rejected
    }

    /// Number of pages the current content occupies.
    pub fn page_count(&self) -> usize {
        self.layout().len()
    }

    // -----------------------------------------------------------------------
    // Layout
    // -----------------------------------------------------------------------

    fn layout(&self) -> Vec<Page> {
        let mut lay = Layout::new();
        for block in &self.blocks {
            if lay.full {
                break;
            }
            match block {
                Block::Heading { level, text } => {
                    let (size, before, after) = match level {
                        1 => (SIZE_H1, 12_000, 5_000),
                        2 => (SIZE_H2, 10_000, 4_000),
                        _ => (SIZE_H3, 8_000, 3_000),
                    };
                    lay.gap(before);
                    for line in wrap(text, Font::Bold, size, TEXT_W_MP) {
                        lay.line(MARGIN_MP, Font::Bold, size, line);
                    }
                    lay.y -= after;
                }
                Block::Paragraph(text) => {
                    for line in wrap(text, Font::Regular, SIZE_BODY, TEXT_W_MP) {
                        lay.line(MARGIN_MP, Font::Regular, SIZE_BODY, line);
                    }
                    lay.y -= 5_000;
                }
                Block::Bullet(text) => {
                    let lines = wrap(text, Font::Regular, SIZE_BODY, TEXT_W_MP - BULLET_INDENT_MP);
                    let lh = SIZE_BODY * LEADING;
                    for (i, line) in lines.into_iter().enumerate() {
                        lay.ensure(lh);
                        let y = lay.y - SIZE_BODY * BASELINE_DROP;
                        if i == 0 {
                            lay.ops.push(Op::Text {
                                x: MARGIN_MP,
                                y,
                                font: Font::Regular,
                                size: SIZE_BODY,
                                bytes: vec![149],
                            });
                        }
                        lay.ops.push(Op::Text {
                            x: MARGIN_MP + BULLET_INDENT_MP,
                            y,
                            font: Font::Regular,
                            size: SIZE_BODY,
                            bytes: line,
                        });
                        lay.y -= lh;
                    }
                    lay.y -= 2_000;
                }
                Block::KeyValue { key, value } => {
                    let value_x = MARGIN_MP + KEY_COLUMN_MP + GUTTER_MP;
                    let value_w = PAGE_W_MP - MARGIN_MP - value_x;
                    let kl = wrap(key, Font::Bold, SIZE_BODY, KEY_COLUMN_MP);
                    let vl = wrap(value, Font::Regular, SIZE_BODY, value_w);
                    let n = kl.len().max(vl.len());
                    let lh = SIZE_BODY * LEADING;
                    for i in 0..n {
                        lay.ensure(lh);
                        let y = lay.y - SIZE_BODY * BASELINE_DROP;
                        if let Some(k) = kl.get(i) {
                            lay.ops.push(Op::Text {
                                x: MARGIN_MP,
                                y,
                                font: Font::Bold,
                                size: SIZE_BODY,
                                bytes: k.clone(),
                            });
                        }
                        if let Some(v) = vl.get(i) {
                            lay.ops.push(Op::Text {
                                x: value_x,
                                y,
                                font: Font::Regular,
                                size: SIZE_BODY,
                                bytes: v.clone(),
                            });
                        }
                        lay.y -= lh;
                    }
                    lay.y -= 2_000;
                }
                Block::Table { headers, rows } => {
                    layout_table(&mut lay, headers, rows);
                }
                Block::Rule => {
                    lay.ensure(8_000);
                    let y = lay.y - 4_000;
                    lay.ops.push(Op::HLine { x0: MARGIN_MP, x1: PAGE_W_MP - MARGIN_MP, y });
                    lay.y -= 8_000;
                }
                Block::PageBreak => {
                    if !lay.at_page_top() {
                        lay.new_page();
                    }
                }
            }
        }
        lay.finish()
    }

    /// Drawn size of the footer raster, preserving its aspect ratio.
    fn image_size(&self) -> Option<(i64, i64)> {
        let r = self.footer_raster.as_ref()?;
        let mut w = (r.width as i64).saturating_mul(500);
        let mut h = (r.height as i64).saturating_mul(500);
        if w <= 0 || h <= 0 {
            return None;
        }
        if w > FOOTER_IMAGE_MAX_W_MP {
            h = h.saturating_mul(FOOTER_IMAGE_MAX_W_MP) / w;
            w = FOOTER_IMAGE_MAX_W_MP;
        }
        if h > FOOTER_IMAGE_MAX_H_MP {
            w = w.saturating_mul(FOOTER_IMAGE_MAX_H_MP) / h;
            h = FOOTER_IMAGE_MAX_H_MP;
        }
        if w <= 0 || h <= 0 {
            None
        } else {
            Some((w, h))
        }
    }

    // -----------------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------------

    /// Serialise the document. `doc_id` supplies the file `/ID`, which is the only
    /// place a general PDF writer would have put a random value or a clock reading.
    pub fn build(&self, doc_id: &cl_core::hash::Digest) -> Vec<u8> {
        let pages = self.layout();
        let image = self.image_size();
        let has_image = image.is_some();
        let n_pages = pages.len().max(1);

        // Fixed object order keeps offsets, and therefore bytes, reproducible.
        const OBJ_CATALOG: usize = 1;
        const OBJ_PAGES: usize = 2;
        const OBJ_FONT_REGULAR: usize = 3;
        const OBJ_FONT_BOLD: usize = 4;
        const OBJ_INFO: usize = 5;
        const OBJ_IMAGE: usize = 6;
        let first_page_obj = if has_image { OBJ_IMAGE + 1 } else { OBJ_IMAGE };
        let n_objs = first_page_obj - 1 + 2 * n_pages;

        let mut buf: Vec<u8> = Vec::new();
        let mut offsets: Vec<usize> = Vec::with_capacity(n_objs);

        buf.extend_from_slice(b"%PDF-1.7\n");
        // Binary comment: tells transports this file is not plain text.
        buf.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

        let begin = |buf: &mut Vec<u8>, offsets: &mut Vec<usize>, n: usize| {
            debug_assert_eq!(offsets.len() + 1, n);
            offsets.push(buf.len());
            buf.extend_from_slice(n.to_string().as_bytes());
            buf.extend_from_slice(b" 0 obj\n");
        };

        begin(&mut buf, &mut offsets, OBJ_CATALOG);
        buf.extend_from_slice(b"<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        begin(&mut buf, &mut offsets, OBJ_PAGES);
        buf.extend_from_slice(b"<< /Type /Pages /Count ");
        buf.extend_from_slice(n_pages.to_string().as_bytes());
        buf.extend_from_slice(b" /Kids [");
        for i in 0..n_pages {
            buf.push(b' ');
            buf.extend_from_slice((first_page_obj + 2 * i).to_string().as_bytes());
            buf.extend_from_slice(b" 0 R");
        }
        buf.extend_from_slice(b" ] >>\nendobj\n");

        begin(&mut buf, &mut offsets, OBJ_FONT_REGULAR);
        buf.extend_from_slice(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n",
        );

        begin(&mut buf, &mut offsets, OBJ_FONT_BOLD);
        buf.extend_from_slice(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n",
        );

        begin(&mut buf, &mut offsets, OBJ_INFO);
        buf.extend_from_slice(b"<< /Title (");
        escape_pdf_string(&self.title, &mut buf);
        buf.extend_from_slice(b") /Producer (");
        let (producer, _) = encode_winansi(&format!(
            "{} {}",
            cl_core::SCANNER_NAME,
            cl_core::PRODUCT_VERSION
        ));
        escape_pdf_string(&producer, &mut buf);
        // No CreationDate and no ModDate: a clock read here would make two scans of
        // the same evidence produce different bytes and different bundle digests.
        buf.extend_from_slice(b") >>\nendobj\n");

        if let Some(r) = self.footer_raster.as_ref() {
            begin(&mut buf, &mut offsets, OBJ_IMAGE);
            buf.extend_from_slice(b"<< /Type /XObject /Subtype /Image /Width ");
            buf.extend_from_slice(r.width.to_string().as_bytes());
            buf.extend_from_slice(b" /Height ");
            buf.extend_from_slice(r.height.to_string().as_bytes());
            buf.extend_from_slice(
                b" /ColorSpace /DeviceRGB /BitsPerComponent 8 /TTMarker true /Length ",
            );
            buf.extend_from_slice(r.rgb.len().to_string().as_bytes());
            buf.extend_from_slice(b" >>\nstream\n");
            buf.extend_from_slice(&r.rgb);
            buf.extend_from_slice(b"\nendstream\nendobj\n");
        }

        let blank = Page::default();
        for i in 0..n_pages {
            let page = pages.get(i).unwrap_or(&blank);
            let page_obj = first_page_obj + 2 * i;
            let content_obj = page_obj + 1;

            begin(&mut buf, &mut offsets, page_obj);
            buf.extend_from_slice(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >>");
            if has_image {
                buf.extend_from_slice(b" /XObject << /Im0 ");
                buf.extend_from_slice(OBJ_IMAGE.to_string().as_bytes());
                buf.extend_from_slice(b" 0 R >>");
            }
            buf.extend_from_slice(b" >> /Contents ");
            buf.extend_from_slice(content_obj.to_string().as_bytes());
            buf.extend_from_slice(b" 0 R >>\nendobj\n");

            let content = self.content_stream(page, image, i + 1, n_pages);
            begin(&mut buf, &mut offsets, content_obj);
            buf.extend_from_slice(b"<< /Length ");
            buf.extend_from_slice(content.len().to_string().as_bytes());
            buf.extend_from_slice(b" >>\nstream\n");
            buf.extend_from_slice(&content);
            buf.extend_from_slice(b"\nendstream\nendobj\n");
        }

        let xref_at = buf.len();
        buf.extend_from_slice(b"xref\n0 ");
        buf.extend_from_slice((n_objs + 1).to_string().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(b"0000000000 65535 f\r\n");
        for off in &offsets {
            buf.extend_from_slice(format!("{off:010} 00000 n\r\n").as_bytes());
        }

        let id = doc_id.to_hex();
        buf.extend_from_slice(b"trailer\n<< /Size ");
        buf.extend_from_slice((n_objs + 1).to_string().as_bytes());
        buf.extend_from_slice(b" /Root 1 0 R /Info ");
        buf.extend_from_slice(OBJ_INFO.to_string().as_bytes());
        buf.extend_from_slice(b" 0 R /ID [<");
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(b"> <");
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(b">] >>\nstartxref\n");
        buf.extend_from_slice(xref_at.to_string().as_bytes());
        buf.extend_from_slice(b"\n%%EOF\n");
        buf
    }

    fn content_stream(
        &self,
        page: &Page,
        image: Option<(i64, i64)>,
        page_no: usize,
        total: usize,
    ) -> Vec<u8> {
        let mut s: Vec<u8> = Vec::new();

        if let Some((w, h)) = image {
            s.extend_from_slice(b"q\n");
            s.extend_from_slice(mp(w).as_bytes());
            s.extend_from_slice(b" 0 0 ");
            s.extend_from_slice(mp(h).as_bytes());
            s.push(b' ');
            s.extend_from_slice(mp(MARGIN_MP).as_bytes());
            s.push(b' ');
            s.extend_from_slice(mp(FOOTER_IMAGE_Y_MP).as_bytes());
            s.extend_from_slice(b" cm\n/Im0 Do\nQ\n");
        }

        for op in &page.ops {
            match op {
                Op::Text { x, y, font, size, bytes } => {
                    if bytes.is_empty() {
                        continue;
                    }
                    emit_text(&mut s, *x, *y, *font, *size, bytes);
                }
                Op::HLine { x0, x1, y } => {
                    s.extend_from_slice(b"0.6 w 0.6 G\n");
                    s.extend_from_slice(mp(*x0).as_bytes());
                    s.push(b' ');
                    s.extend_from_slice(mp(*y).as_bytes());
                    s.extend_from_slice(b" m ");
                    s.extend_from_slice(mp(*x1).as_bytes());
                    s.push(b' ');
                    s.extend_from_slice(mp(*y).as_bytes());
                    s.extend_from_slice(b" l S\n");
                }
            }
        }

        // Footer, on every page.
        let note_x = match image {
            Some((w, _)) => MARGIN_MP + w + GUTTER_MP,
            None => MARGIN_MP,
        };
        let (pageno, _) = encode_winansi(&format!("Page {page_no} of {total}"));
        let pageno_w = run_width_mp(Font::Regular, FOOTER_SIZE, &pageno);
        let pageno_x = PAGE_W_MP - MARGIN_MP - pageno_w;
        let note_w = (pageno_x - GUTTER_MP - note_x).max(0);
        let note = truncate_to_width(&self.footer_note, Font::Regular, FOOTER_SIZE, note_w);
        if !note.is_empty() {
            emit_text(&mut s, note_x, FOOTER_TEXT_Y_MP, Font::Regular, FOOTER_SIZE, &note);
        }
        emit_text(&mut s, pageno_x, FOOTER_TEXT_Y_MP, Font::Regular, FOOTER_SIZE, &pageno);
        s
    }
}

/// One positioned text run. `Td` inside a fresh `BT` is an absolute placement, and it
/// is also the token our own reader treats as a line break — writer and reader agree
/// on where lines are because they agree on this operator.
fn emit_text(s: &mut Vec<u8>, x: i64, y: i64, font: Font, size: i64, bytes: &[u8]) {
    s.extend_from_slice(b"BT ");
    s.extend_from_slice(font.resource().as_bytes());
    s.push(b' ');
    s.extend_from_slice(size.to_string().as_bytes());
    s.extend_from_slice(b" Tf ");
    s.extend_from_slice(mp(x).as_bytes());
    s.push(b' ');
    s.extend_from_slice(mp(y).as_bytes());
    s.extend_from_slice(b" Td (");
    escape_pdf_string(bytes, s);
    s.extend_from_slice(b") Tj ET\n");
}

/// Longest prefix of `bytes` that fits in `max_mp`.
fn truncate_to_width(bytes: &[u8], font: Font, size: i64, max_mp: i64) -> Vec<u8> {
    let mut acc: i64 = 0;
    let mut take = 0usize;
    for (i, c) in bytes.iter().enumerate() {
        let w = width_mp(font, size, *c);
        if acc.saturating_add(w) > max_mp {
            break;
        }
        acc = acc.saturating_add(w);
        take = i + 1;
    }
    bytes[..take].to_vec()
}

/// Column widths for a table: natural widths when they fit, proportionally scaled
/// when they do not, and equal widths as the fallback that always fits.
fn column_widths(headers: &[Vec<u8>], rows: &[Vec<Vec<u8>>]) -> Vec<i64> {
    let ncols = headers.len();
    let gutters = GUTTER_MP.saturating_mul(ncols.saturating_sub(1) as i64);
    let avail = (TEXT_W_MP - gutters).max(ncols as i64);

    let mut natural = vec![0i64; ncols];
    for (c, h) in headers.iter().enumerate() {
        natural[c] = run_width_mp(Font::Bold, SIZE_BODY, h).saturating_add(4_000);
    }
    for row in rows {
        for (c, cell) in row.iter().enumerate().take(ncols) {
            let w = run_width_mp(Font::Regular, SIZE_BODY, cell).saturating_add(4_000);
            if w > natural[c] {
                natural[c] = w;
            }
        }
    }

    let total: i64 = natural.iter().fold(0i64, |a, b| a.saturating_add(*b));
    let mut w = if total <= avail && total > 0 {
        natural
    } else if total > 0 {
        natural.iter().map(|n| n.saturating_mul(avail) / total).collect()
    } else {
        vec![avail / ncols as i64; ncols]
    };
    let sum: i64 = w.iter().fold(0i64, |a, b| a.saturating_add(*b));
    if sum > avail || w.iter().any(|x| *x < MIN_COLUMN_MP) {
        let equal = (avail / ncols as i64).max(1);
        w = vec![equal; ncols];
    }
    w
}

fn layout_table(lay: &mut Layout, headers: &[Vec<u8>], rows: &[Vec<Vec<u8>>]) {
    let ncols = headers.len();
    if ncols == 0 {
        return;
    }
    let widths = column_widths(headers, rows);
    let mut xs = Vec::with_capacity(ncols);
    let mut x = MARGIN_MP;
    for w in &widths {
        xs.push(x);
        x = x.saturating_add(*w).saturating_add(GUTTER_MP);
    }
    let lh = SIZE_BODY * LEADING;
    let max_lines = (((CONTENT_TOP_MP - CONTENT_BOTTOM_MP) / lh) as usize).max(1);

    // A row taller than one page cannot be broken by this writer, so cells are
    // capped at a page of lines rather than allowed to run off the bottom.
    let row_lines = |cells: &[Vec<u8>], font: Font| -> (Vec<Vec<Vec<u8>>>, usize) {
        let mut per_cell = Vec::with_capacity(ncols);
        let mut n = 1usize;
        for c in 0..ncols {
            let empty = Vec::new();
            let cell = cells.get(c).unwrap_or(&empty);
            let mut lines = wrap(cell, font, SIZE_BODY, widths[c]);
            lines.truncate(max_lines);
            n = n.max(lines.len());
            per_cell.push(lines);
        }
        (per_cell, n)
    };

    let (header_lines, header_n) = row_lines(headers, Font::Bold);
    let header_h = (header_n as i64) * lh + 5_000;

    let draw_header = |lay: &mut Layout| {
        for i in 0..header_n {
            let y = lay.y - SIZE_BODY * BASELINE_DROP;
            for c in 0..ncols {
                if let Some(line) = header_lines[c].get(i) {
                    if line.is_empty() {
                        continue;
                    }
                    lay.ops.push(Op::Text {
                        x: xs[c],
                        y,
                        font: Font::Bold,
                        size: SIZE_BODY,
                        bytes: line.clone(),
                    });
                }
            }
            lay.y -= lh;
        }
        let y = lay.y - 1_500;
        lay.ops.push(Op::HLine { x0: MARGIN_MP, x1: PAGE_W_MP - MARGIN_MP, y });
        lay.y -= 5_000;
    };

    lay.ensure(header_h + lh);
    draw_header(lay);

    for row in rows {
        if lay.full {
            return;
        }
        let (cell_lines, n) = row_lines(row, Font::Regular);
        let row_h = (n as i64) * lh;
        if lay.y - row_h < CONTENT_BOTTOM_MP && !lay.at_page_top() {
            lay.new_page();
            if lay.full {
                return;
            }
            draw_header(lay);
        }
        for i in 0..n {
            let y = lay.y - SIZE_BODY * BASELINE_DROP;
            for c in 0..ncols {
                if let Some(line) = cell_lines[c].get(i) {
                    if line.is_empty() {
                        continue;
                    }
                    lay.ops.push(Op::Text {
                        x: xs[c],
                        y,
                        font: Font::Regular,
                        size: SIZE_BODY,
                        bytes: line.clone(),
                    });
                }
            }
            lay.y -= lh;
        }
    }
    lay.y -= 4_000;
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// One `stream` object located in the file: its dictionary text and its raw data.
struct RawStream<'a> {
    dict: &'a [u8],
    data: &'a [u8],
}

/// How far back from a `stream` keyword the enclosing `obj` may be.
const DICT_LOOKBACK: usize = 4096;

fn is_ws(c: u8) -> bool {
    matches!(c, 0x00 | 0x09 | 0x0A | 0x0C | 0x0D | 0x20)
}

fn is_delimiter(c: u8) -> bool {
    matches!(c, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%')
}

fn is_regular(c: u8) -> bool {
    !is_ws(c) && !is_delimiter(c)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|i| &hay[*i..*i + needle.len()] == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).rev().find(|i| &hay[*i..*i + needle.len()] == needle)
}

/// Reject anything that is not plausibly one of our own PDFs before scanning it.
fn check_envelope(pdf: &[u8], limits: &Limits) -> ClResult<()> {
    if pdf.len() as u64 > limits.config_bytes {
        return Err(ClError::LimitExceeded {
            limit: "config_bytes",
            value: pdf.len() as u64,
            max: limits.config_bytes,
        });
    }
    if !pdf.starts_with(b"%PDF-") {
        return Err(ClError::malformed("pdf", 0, "missing %PDF- header"));
    }
    Ok(())
}

/// Locate every stream object, bounded.
///
/// The scan walks forward and skips over each stream's data once consumed, which is
/// what stops the bytes of an uncompressed image — or the word "upstream" in a
/// content stream — from being mistaken for another `stream` keyword. A candidate
/// whose dictionary does not look like a dictionary, or whose `/Length` runs past the
/// end of the file, is a hard error rather than a shortened read.
fn scan_streams<'a>(pdf: &'a [u8], limits: &Limits) -> ClResult<Vec<RawStream<'a>>> {
    let mut out: Vec<RawStream<'a>> = Vec::new();
    let mut i = 0usize;

    while i < pdf.len() {
        let rel = match find(&pdf[i..], b"stream") {
            Some(r) => r,
            None => break,
        };
        let p = i + rel;
        let after = p + 6;

        let lo = p.saturating_sub(DICT_LOOKBACK);
        let dict = match rfind(&pdf[lo..p], b"obj") {
            Some(k) => &pdf[lo + k + 3..p],
            None => {
                i = after;
                continue;
            }
        };
        // A real dictionary contains no `stream` keyword; requiring that is what
        // prevents the `stream` inside `endstream` from re-opening a consumed object.
        if !dict_is_plausible(dict) {
            i = after;
            continue;
        }

        let mut ds = after;
        if pdf.get(ds) == Some(&b'\r') {
            ds += 1;
        }
        if pdf.get(ds) == Some(&b'\n') {
            ds += 1;
        } else {
            i = after;
            continue;
        }

        let len = match dict_uint(dict, b"/Length") {
            Some(v) => v,
            None => {
                i = after;
                continue;
            }
        };
        let len = usize::try_from(len)
            .map_err(|_| ClError::malformed("pdf", p, "stream /Length out of range"))?;
        let end = ds
            .checked_add(len)
            .ok_or_else(|| ClError::malformed("pdf", p, "stream /Length overflows"))?;
        if end > pdf.len() {
            return Err(ClError::malformed("pdf", p, "stream extends past end of file"));
        }

        if out.len() >= limits.json_max_object_keys {
            return Err(ClError::LimitExceeded {
                limit: "pdf_streams",
                value: out.len() as u64 + 1,
                max: limits.json_max_object_keys as u64,
            });
        }
        out.push(RawStream { dict, data: &pdf[ds..end] });

        i = end;
        while i < pdf.len() && is_ws(pdf[i]) {
            i += 1;
        }
        if pdf[i..].starts_with(b"endstream") {
            i += 9;
        }
    }
    Ok(out)
}

/// A dictionary starts with `<<`, ends with `>>` and holds no `stream` keyword.
fn dict_is_plausible(dict: &[u8]) -> bool {
    let start = dict.iter().position(|c| !is_ws(*c));
    let s = match start {
        Some(s) => s,
        None => return false,
    };
    if !dict[s..].starts_with(b"<<") {
        return false;
    }
    let e = match dict.iter().rposition(|c| !is_ws(*c)) {
        Some(e) => e,
        None => return false,
    };
    if e < 1 || &dict[e - 1..=e] != b">>" {
        return false;
    }
    find(dict, b"stream").is_none()
}

/// Value of an unsigned integer key written as a direct object.
fn dict_uint(dict: &[u8], key: &[u8]) -> Option<u64> {
    let at = find(dict, key)?;
    let mut i = at + key.len();
    while i < dict.len() && is_ws(dict[i]) {
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    while i < dict.len() && dict[i].is_ascii_digit() {
        v = v.checked_mul(10)?.checked_add((dict[i] - b'0') as u64)?;
        i += 1;
    }
    if i == start {
        None
    } else {
        Some(v)
    }
}

/// Token following `key`, as raw bytes. Used for name and boolean values.
fn dict_token<'a>(dict: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let at = find(dict, key)?;
    let mut i = at + key.len();
    while i < dict.len() && is_ws(dict[i]) {
        i += 1;
    }
    let start = i;
    if i < dict.len() && dict[i] == b'/' {
        i += 1;
    }
    while i < dict.len() && is_regular(dict[i]) {
        i += 1;
    }
    if i == start {
        None
    } else {
        Some(&dict[start..i])
    }
}

fn is_image(dict: &[u8]) -> bool {
    dict_token(dict, b"/Subtype") == Some(b"/Image")
}

/// Read the strings a PDF shows, as a reader would see them.
///
/// This is not a renderer: it recovers `Tj` and `TJ` operands and treats every
/// `Td`, `TD` or `T*` as a line break, which is exactly the granularity the
/// forbidden-language guard needs. Because this writer places each run with its own
/// `Td`, each run — including each table cell — lands on its own line.
///
/// Errors rather than returning a partial result on a truncated or hostile file: a
/// language check that silently saw half the document would be worse than none.
pub fn extract_text(pdf: &[u8]) -> ClResult<String> {
    let limits = Limits::default();
    check_envelope(pdf, &limits)?;

    let streams = scan_streams(pdf, &limits)?;
    let mut out = String::new();
    let mut saw_content = false;
    for s in &streams {
        if is_image(s.dict) {
            continue;
        }
        saw_content = true;
        extract_content_text(s.data, &mut out, &limits)?;
    }
    if !saw_content {
        return Err(ClError::malformed("pdf", 0, "no content stream"));
    }
    while out.starts_with('\n') {
        out.remove(0);
    }
    Ok(out)
}

/// Recover the footer tint carrier written by [`PdfBuilder::set_footer_raster`].
///
/// Returns `Ok(None)` when the document simply carries no marker — a report may
/// legitimately have none, and that is `marker_status = absent`, not a failure. An
/// image that *claims* the marker but whose declared geometry disagrees with its data
/// is an error, because a half-recovered carrier would be compared against the
/// expected digest and reported as an inconsistency the vendor did not cause.
pub fn extract_footer_raster(pdf: &[u8]) -> ClResult<Option<cl_core::raster::Raster>> {
    let limits = Limits::default();
    check_envelope(pdf, &limits)?;

    for s in scan_streams(pdf, &limits)? {
        if !is_image(s.dict) {
            continue;
        }
        if dict_token(s.dict, b"/TTMarker") != Some(b"true") {
            continue;
        }
        if dict_token(s.dict, b"/ColorSpace") != Some(b"/DeviceRGB") {
            return Err(ClError::malformed("pdf_marker", 0, "marker image is not DeviceRGB"));
        }
        if dict_uint(s.dict, b"/BitsPerComponent") != Some(8) {
            return Err(ClError::malformed("pdf_marker", 0, "marker image is not 8 bits"));
        }
        if find(s.dict, b"/Filter").is_some() {
            return Err(ClError::malformed("pdf_marker", 0, "marker image is filtered"));
        }
        let w = dict_uint(s.dict, b"/Width")
            .ok_or_else(|| ClError::malformed("pdf_marker", 0, "marker image has no /Width"))?;
        let h = dict_uint(s.dict, b"/Height")
            .ok_or_else(|| ClError::malformed("pdf_marker", 0, "marker image has no /Height"))?;
        let w = u32::try_from(w)
            .map_err(|_| ClError::malformed("pdf_marker", 0, "marker /Width out of range"))?;
        let h = u32::try_from(h)
            .map_err(|_| ClError::malformed("pdf_marker", 0, "marker /Height out of range"))?;
        let expect = (w as usize)
            .checked_mul(h as usize)
            .and_then(|n| n.checked_mul(3))
            .ok_or_else(|| ClError::malformed("pdf_marker", 0, "marker geometry overflows"))?;
        if expect != s.data.len() {
            return Err(ClError::malformed(
                "pdf_marker",
                0,
                format!("marker declares {w}x{h} but carries {} bytes", s.data.len()),
            ));
        }
        return Ok(Some(Raster::from_rgb(w, h, s.data.to_vec())?));
    }
    Ok(None)
}

/// Walk one content stream, appending shown text to `out`.
///
/// Every branch advances `i` by at least one byte, so the walk is bounded by the
/// stream length without needing a separate step counter.
fn extract_content_text(b: &[u8], out: &mut String, limits: &Limits) -> ClResult<()> {
    let max_out = limits.config_bytes as usize;
    let mut i = 0usize;
    let mut pending: Vec<u8> = Vec::new();

    while i < b.len() {
        let c = b[i];
        if is_ws(c) {
            i += 1;
            continue;
        }
        match c {
            b'(' => {
                let (s, next) = read_literal_string(b, i, limits)?;
                if pending.len().saturating_add(s.len()) <= limits.json_max_string_bytes {
                    pending.extend_from_slice(&s);
                }
                i = next;
            }
            b'<' => {
                if b.get(i + 1) == Some(&b'<') {
                    i += 2;
                } else {
                    let (s, next) = read_hex_string(b, i, limits)?;
                    if pending.len().saturating_add(s.len()) <= limits.json_max_string_bytes {
                        pending.extend_from_slice(&s);
                    }
                    i = next;
                }
            }
            b'/' => {
                i += 1;
                while i < b.len() && is_regular(b[i]) {
                    i += 1;
                }
            }
            b'%' => {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            }
            b')' | b'>' | b'[' | b']' | b'{' | b'}' => i += 1,
            _ => {
                let start = i;
                while i < b.len() && is_regular(b[i]) {
                    i += 1;
                }
                if i == start {
                    i += 1;
                    continue;
                }
                match &b[start..i] {
                    b"Tj" | b"TJ" => {
                        decode_winansi(&pending, out);
                        pending.clear();
                    }
                    b"'" | b"\"" => {
                        push_break(out);
                        decode_winansi(&pending, out);
                        pending.clear();
                    }
                    b"Td" | b"TD" | b"T*" => {
                        push_break(out);
                        pending.clear();
                    }
                    _ => {}
                }
                if out.len() > max_out {
                    return Err(ClError::LimitExceeded {
                        limit: "config_bytes",
                        value: out.len() as u64,
                        max: limits.config_bytes,
                    });
                }
            }
        }
    }
    Ok(())
}

fn push_break(out: &mut String) {
    if !out.ends_with('\n') {
        out.push('\n');
    }
}

/// Read a `( ... )` literal string, honouring nesting, escapes and octal codes.
fn read_literal_string(b: &[u8], at: usize, limits: &Limits) -> ClResult<(Vec<u8>, usize)> {
    let mut i = at + 1;
    let mut depth = 1usize;
    let mut out: Vec<u8> = Vec::new();
    while i < b.len() {
        if out.len() > limits.json_max_string_bytes {
            return Err(ClError::LimitExceeded {
                limit: "json_max_string_bytes",
                value: out.len() as u64,
                max: limits.json_max_string_bytes as u64,
            });
        }
        let c = b[i];
        match c {
            b'\\' => {
                i += 1;
                let e = match b.get(i) {
                    Some(e) => *e,
                    None => return Err(ClError::malformed("pdf_string", at, "escape at end")),
                };
                match e {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'(' | b')' | b'\\' => out.push(e),
                    b'\r' => {
                        if b.get(i + 1) == Some(&b'\n') {
                            i += 1;
                        }
                    }
                    b'\n' => {}
                    b'0'..=b'7' => {
                        let mut v: u32 = (e - b'0') as u32;
                        let mut k = 1;
                        while k < 3 {
                            match b.get(i + 1) {
                                Some(d @ b'0'..=b'7') => {
                                    v = v * 8 + (*d - b'0') as u32;
                                    i += 1;
                                    k += 1;
                                }
                                _ => break,
                            }
                        }
                        out.push((v & 0xFF) as u8);
                    }
                    other => out.push(other),
                }
                i += 1;
            }
            b'(' => {
                depth += 1;
                out.push(c);
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Ok((out, i));
                }
                out.push(c);
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Err(ClError::malformed("pdf_string", at, "unterminated literal string"))
}

/// Read a `< ... >` hex string. An odd final digit is padded with zero, per the spec.
fn read_hex_string(b: &[u8], at: usize, limits: &Limits) -> ClResult<(Vec<u8>, usize)> {
    let mut i = at + 1;
    let mut out: Vec<u8> = Vec::new();
    let mut hi: Option<u8> = None;
    while i < b.len() {
        if out.len() > limits.json_max_string_bytes {
            return Err(ClError::LimitExceeded {
                limit: "json_max_string_bytes",
                value: out.len() as u64,
                max: limits.json_max_string_bytes as u64,
            });
        }
        let c = b[i];
        if c == b'>' {
            if let Some(h) = hi {
                out.push(h << 4);
            }
            return Ok((out, i + 1));
        }
        if let Some(d) = hex_value(c) {
            match hi {
                None => hi = Some(d),
                Some(h) => {
                    out.push((h << 4) | d);
                    hi = None;
                }
            }
        } else if !is_ws(c) {
            return Err(ClError::malformed("pdf_string", i, "bad hex digit"));
        }
        i += 1;
    }
    Err(ClError::malformed("pdf_string", at, "unterminated hex string"))
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_core::hash::Digest;

    fn doc_id() -> Digest {
        Digest::of(b"cl-report::pdf test document")
    }

    fn sample(paras: usize) -> PdfBuilder {
        let mut b = PdfBuilder::new("Cladeon Screen Report", "case CL-0001");
        b.heading(1, "Scope of this screen");
        for i in 0..paras {
            b.paragraph(&format!(
                "Paragraph {i}: this Stage-1 report evaluates consistency within \
                 vendor-supplied evidence and records what the scanner could and \
                 could not observe in the supplied artifacts."
            ));
        }
        b
    }

    // ---------------------------------------------------------------- writer

    #[test]
    fn empty_document_is_one_page_and_parses() {
        let b = PdfBuilder::new("Empty", "note");
        assert_eq!(b.page_count(), 1);
        let pdf = b.build(&doc_id());
        assert!(pdf.starts_with(b"%PDF-1.7\n"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let text = extract_text(&pdf).unwrap();
        assert!(text.contains("Page 1 of 1"), "{text:?}");
        assert!(text.contains("note"));
    }

    #[test]
    fn two_builds_are_byte_identical() {
        let mut b = sample(12);
        b.set_footer_raster(Raster::new(240, 40, [7, 8, 9]));
        b.table(&["Artifact", "Digest"], &[vec!["a.safetensors".into(), "ab".repeat(32)]]);
        let one = b.build(&doc_id());
        let two = b.build(&doc_id());
        assert_eq!(one, two);
        assert!(one.len() > 1000);
    }

    #[test]
    fn a_different_doc_id_changes_only_the_id_array() {
        let b = sample(2);
        let one = b.build(&Digest::of(b"a"));
        let two = b.build(&Digest::of(b"b"));
        assert_ne!(one, two);
        assert_eq!(one.len(), two.len(), "the ID array is fixed width");
    }

    #[test]
    fn no_creation_date_is_emitted() {
        let pdf = sample(1).build(&doc_id());
        assert!(find(&pdf, b"CreationDate").is_none());
        assert!(find(&pdf, b"ModDate").is_none());
    }

    #[test]
    fn page_count_grows_with_content() {
        let one = sample(3).page_count();
        let many = sample(120).page_count();
        assert_eq!(one, 1);
        assert!(many > 3, "120 paragraphs should span several pages, got {many}");
        assert!(sample(240).page_count() > many);
    }

    #[test]
    fn page_break_forces_a_new_page() {
        let mut b = PdfBuilder::new("t", "f");
        b.paragraph("first");
        assert_eq!(b.page_count(), 1);
        b.page_break();
        b.paragraph("second");
        assert_eq!(b.page_count(), 2);
        // A break at the very top of a page must not manufacture a blank one.
        let mut c = PdfBuilder::new("t", "f");
        c.page_break();
        c.paragraph("only");
        assert_eq!(c.page_count(), 1);
    }

    #[test]
    fn every_run_stays_inside_the_right_margin() {
        let hash = "9f".repeat(32);
        assert_eq!(hash.len(), 64);
        let mut b = PdfBuilder::new("t", "f");
        b.heading(1, &hash);
        b.paragraph(&format!("digest {hash} of the adapter weights"));
        b.bullet(&hash);
        b.key_value("checkpoint digest", &hash);
        b.table(&["a", "b", "c"], &[vec![hash.clone(), hash.clone(), hash.clone()]]);
        for page in b.layout() {
            for op in page.ops {
                if let Op::Text { x, font, size, bytes, .. } = op {
                    let right = x + run_width_mp(font, size, &bytes);
                    assert!(
                        right <= PAGE_W_MP - MARGIN_MP,
                        "run overflows: right={right} bytes={:?}",
                        String::from_utf8_lossy(&bytes)
                    );
                    assert!(x >= MARGIN_MP);
                }
            }
        }
    }

    #[test]
    fn a_long_token_is_split_not_dropped() {
        let hash = "0123456789abcdef".repeat(4);
        let lines = wrap(hash.as_bytes(), Font::Regular, SIZE_BODY, 60_000);
        assert!(lines.len() > 1);
        let joined: Vec<u8> = lines.concat();
        assert_eq!(joined, hash.as_bytes(), "no character may be lost in a split");
    }

    #[test]
    fn wrap_terminates_on_an_absurdly_narrow_column() {
        let lines = wrap(b"aaaa bbbb", Font::Bold, SIZE_BODY, 1);
        assert!(lines.len() >= 8);
        assert!(lines.iter().all(|l| !l.is_empty()));
    }

    #[test]
    fn wrap_of_empty_text_still_occupies_one_line() {
        assert_eq!(wrap(b"", Font::Regular, SIZE_BODY, TEXT_W_MP), vec![Vec::<u8>::new()]);
        assert_eq!(wrap(b"    ", Font::Regular, SIZE_BODY, TEXT_W_MP), vec![Vec::<u8>::new()]);
    }

    // ------------------------------------------------------------- encoding

    #[test]
    fn parens_and_backslashes_survive_the_round_trip() {
        let mut b = PdfBuilder::new("t", "f");
        b.paragraph("weights(base) \\ adapter (merged) — see note");
        let text = extract_text(&b.build(&doc_id())).unwrap();
        assert!(text.contains("weights(base) \\ adapter (merged)"), "{text:?}");
    }

    #[test]
    fn unmapped_characters_become_question_marks_and_are_counted() {
        let mut b = PdfBuilder::new("t", "f");
        b.paragraph("tokens per step \u{4E2D}\u{6587} done");
        assert_eq!(b.unmapped_character_count(), 2);
        let text = extract_text(&b.build(&doc_id())).unwrap();
        assert!(text.contains("step ?? done"), "{text:?}");
    }

    #[test]
    fn winansi_high_range_round_trips() {
        let s = "\u{2014} \u{201C}base\u{201D} \u{00E9} \u{00DF} \u{20AC} \u{2022}";
        let (bytes, unmapped) = encode_winansi(s);
        assert_eq!(unmapped, 0);
        let mut back = String::new();
        decode_winansi(&bytes, &mut back);
        assert_eq!(back, s);
    }

    #[test]
    fn control_characters_become_spaces_not_substitutions() {
        let mut b = PdfBuilder::new("t", "f");
        b.paragraph("line one\nline two\ttabbed");
        assert_eq!(b.unmapped_character_count(), 0);
        let text = extract_text(&b.build(&doc_id())).unwrap();
        assert!(text.contains("line one line two tabbed"), "{text:?}");
    }

    #[test]
    fn over_long_text_is_truncated_and_marked() {
        let mut b = PdfBuilder::new("t", "f");
        b.paragraph(&"x".repeat(MAX_TEXT_BYTES + 10));
        assert_eq!(b.truncated_text_count(), 1);
        let text = extract_text(&b.build(&doc_id())).unwrap();
        assert!(text.contains("[truncated]"), "truncation must be visible");
    }

    #[test]
    fn millipoint_formatting() {
        assert_eq!(mp(0), "0");
        assert_eq!(mp(504_000), "504");
        assert_eq!(mp(30_500), "30.5");
        assert_eq!(mp(1), "0.001");
        assert_eq!(mp(-2_250), "-2.25");
    }

    #[test]
    fn helvetica_widths_match_known_afm_values() {
        // Spot checks against the published Core-14 metrics. A silent edit to the
        // table would move every wrap point in the product.
        assert_eq!(HELVETICA_W[b' ' as usize], 278);
        assert_eq!(HELVETICA_W[b'W' as usize], 944);
        assert_eq!(HELVETICA_W[b'i' as usize], 222);
        assert_eq!(HELVETICA_W[b'0' as usize], 556);
        assert_eq!(HELVETICA_BOLD_W[b'W' as usize], 944);
        assert_eq!(HELVETICA_BOLD_W[b'i' as usize], 278);
        assert_eq!(HELVETICA_BOLD_W[b'.' as usize], 278);
        // Accented forms carry the advance of their base glyph.
        assert_eq!(HELVETICA_W[0xC9], HELVETICA_W[b'E' as usize]);
        assert_eq!(HELVETICA_BOLD_W[0xF6], HELVETICA_BOLD_W[b'o' as usize]);
    }

    // ------------------------------------------------------------- raster

    #[test]
    fn footer_raster_round_trips_byte_for_byte() {
        let mut r = Raster::new(240, 40, [200, 201, 202]);
        for x in 0..240u32 {
            r.set(x, x % 40, [x as u8, 255 - (x as u8), 17]);
        }
        // Bytes that spell PDF keywords must survive: the reader must slice by
        // /Length, never scan for a terminator.
        for (i, c) in b"endstream endobj stream".iter().enumerate() {
            r.rgb[i] = *c;
        }
        let mut b = sample(40);
        b.set_footer_raster(r.clone());
        assert!(b.footer_raster_accepted());
        let pdf = b.build(&doc_id());
        let back = extract_footer_raster(&pdf).unwrap().expect("marker present");
        assert_eq!(back, r);
        assert_eq!(back.digest(), r.digest());
    }

    #[test]
    fn marker_image_is_uncompressed_and_tagged() {
        let mut b = PdfBuilder::new("t", "f");
        b.set_footer_raster(Raster::new(8, 4, [1, 2, 3]));
        let pdf = b.build(&doc_id());
        assert!(find(&pdf, b"/TTMarker true").is_some());
        assert!(find(&pdf, b"/ColorSpace /DeviceRGB").is_some());
        assert!(find(&pdf, b"/BitsPerComponent 8").is_some());
        assert!(find(&pdf, b"/Filter").is_none(), "no filter may be declared");
    }

    #[test]
    fn a_document_without_a_marker_reports_none() {
        let pdf = sample(2).build(&doc_id());
        assert_eq!(extract_footer_raster(&pdf).unwrap(), None);
    }

    #[test]
    fn an_inconsistent_raster_is_rejected_rather_than_drawn() {
        let mut b = PdfBuilder::new("t", "f");
        b.set_footer_raster(Raster { width: 4, height: 4, rgb: vec![0; 5] });
        assert!(!b.footer_raster_accepted());
        let pdf = b.build(&doc_id());
        assert!(find(&pdf, b"TTMarker").is_none());
        assert_eq!(extract_footer_raster(&pdf).unwrap(), None);
    }

    #[test]
    fn the_marker_is_shared_by_every_page() {
        let mut b = sample(120);
        b.set_footer_raster(Raster::new(240, 40, [1, 1, 1]));
        let pdf = b.build(&doc_id());
        let pages = b.page_count();
        assert!(pages > 2);
        // One XObject definition, referenced from every page.
        assert_eq!(count(&pdf, b"/TTMarker"), 1);
        assert_eq!(count(&pdf, b"/Im0 Do"), pages);
    }

    fn count(hay: &[u8], needle: &[u8]) -> usize {
        let mut n = 0;
        let mut i = 0;
        while let Some(k) = find(&hay[i..], needle) {
            n += 1;
            i += k + needle.len();
        }
        n
    }

    // ------------------------------------------------------------- reader

    #[test]
    fn multi_page_text_comes_back() {
        let mut b = sample(150);
        b.heading(2, "Coverage limitations");
        b.bullet("checkpoint index not supplied");
        b.key_value("assurance level", "vendor_self_scan");
        b.page_break();
        b.heading(2, "Closing marker paragraph");
        b.set_footer_raster(Raster::new(240, 40, [3, 3, 3]));
        let pages = b.page_count();
        assert!(pages >= 4);
        let pdf = b.build(&doc_id());
        let text = extract_text(&pdf).unwrap();
        assert!(text.contains("Scope of this screen"));
        assert!(text.contains("Paragraph 0:"));
        assert!(text.contains("Paragraph 149:"));
        assert!(text.contains("Coverage limitations"));
        assert!(text.contains("checkpoint index not supplied"));
        assert!(text.contains("assurance level"));
        assert!(text.contains("vendor_self_scan"));
        assert!(text.contains("Closing marker paragraph"));
        assert!(text.contains(&format!("Page {pages} of {pages}")));
    }

    #[test]
    fn table_cells_all_appear() {
        let mut b = PdfBuilder::new("t", "f");
        b.table(
            &["Rule", "Outcome", "Tier"],
            &[
                vec!["CL-FMT-002".into(), "coverage_limitation".into(), "E2".into()],
                vec!["CL-LORA-001".into(), "supporting_evidence".into(), "E1".into()],
            ],
        );
        let text = extract_text(&b.build(&doc_id())).unwrap();
        for want in [
            "Rule",
            "Outcome",
            "Tier",
            "CL-FMT-002",
            "coverage_limitation",
            "E2",
            "CL-LORA-001",
            "supporting_evidence",
            "E1",
        ] {
            assert!(text.contains(want), "missing {want} in {text:?}");
        }
    }

    #[test]
    fn a_table_header_repeats_after_a_page_break() {
        let rows: Vec<Vec<String>> =
            (0..200).map(|i| vec![format!("row {i}"), "value".into()]).collect();
        let mut b = PdfBuilder::new("t", "f");
        b.table(&["Key", "Value"], &rows);
        let pdf = b.build(&doc_id());
        let pages = b.page_count();
        assert!(pages > 1);
        let text = extract_text(&pdf).unwrap();
        // Count header *lines* rather than matching on "\nKey\n": `extract_text`
        // strips leading newlines, so the header on the first page has nothing
        // before it and a delimiter-based match silently loses one occurrence.
        let header_lines = text.lines().filter(|l| l.trim() == "Key").count();
        assert_eq!(header_lines, pages, "the header must repeat on every page");
        assert!(text.contains("row 199"));
    }

    #[test]
    fn empty_headers_produce_no_table() {
        let mut b = PdfBuilder::new("t", "f");
        b.table(&[], &[vec!["ignored".into()]]);
        assert_eq!(b.dropped_block_count(), 1);
        let text = extract_text(&b.build(&doc_id())).unwrap();
        assert!(!text.contains("ignored"));
    }

    #[test]
    fn a_short_row_is_padded_not_panicked() {
        let mut b = PdfBuilder::new("t", "f");
        b.table(&["a", "b", "c"], &[vec!["only".into()]]);
        let text = extract_text(&b.build(&doc_id())).unwrap();
        assert!(text.contains("only"));
    }

    #[test]
    fn tj_arrays_are_recovered() {
        let stream = b"BT /F1 10 Tf 54 700 Td [(Corrob) -180 (orated) 12 ( within)] TJ ET";
        let mut out = String::new();
        extract_content_text(stream, &mut out, &Limits::default()).unwrap();
        assert_eq!(out, "\nCorroborated within");
    }

    #[test]
    fn hex_strings_and_quote_operators_are_recovered() {
        let stream = b"BT /F1 10 Tf 54 700 Td <48656C6C6F> Tj 0 -12 TD (next) ' ET";
        let mut out = String::new();
        extract_content_text(stream, &mut out, &Limits::default()).unwrap();
        assert_eq!(out, "\nHello\nnext");
    }

    #[test]
    fn comments_and_nested_parens_do_not_confuse_the_scanner() {
        let stream = b"% a comment (with parens)\nBT /F1 10 Tf 1 1 Td (a (nested) b) Tj ET";
        let mut out = String::new();
        extract_content_text(stream, &mut out, &Limits::default()).unwrap();
        assert_eq!(out, "\na (nested) b");
    }

    #[test]
    fn octal_escapes_decode() {
        let stream = br"BT 1 1 Td (\251 \50 \\) Tj ET";
        let mut out = String::new();
        extract_content_text(stream, &mut out, &Limits::default()).unwrap();
        assert_eq!(out, "\n\u{00A9} ( \\");
    }

    #[test]
    fn an_unterminated_string_errors() {
        let stream = b"BT 1 1 Td (never closed Tj ET";
        let mut out = String::new();
        let e = extract_content_text(stream, &mut out, &Limits::default()).unwrap_err();
        assert_eq!(e.kind(), "malformed");
    }

    // -------------------------------------------------------- hostile input

    #[test]
    fn garbage_errors_rather_than_panicking() {
        for bad in [
            b"".to_vec(),
            b"not a pdf at all".to_vec(),
            vec![0xFF; 4096],
            b"%PDF".to_vec(),
        ] {
            assert!(extract_text(&bad).is_err(), "{bad:?}");
            assert!(extract_footer_raster(&bad).is_err() || bad.starts_with(b"%PDF-"));
        }
    }

    #[test]
    fn a_pdf_header_with_no_streams_errors_but_does_not_panic() {
        let bad = b"%PDF-1.7\nnothing else here at all\n".to_vec();
        assert_eq!(extract_text(&bad).unwrap_err().kind(), "malformed");
        assert_eq!(extract_footer_raster(&bad).unwrap(), None);
    }

    #[test]
    fn truncation_at_every_scale_never_panics() {
        let mut b = sample(30);
        b.set_footer_raster(Raster::new(64, 8, [9, 9, 9]));
        b.table(&["k", "v"], &[vec!["a".into(), "b".into()]]);
        let pdf = b.build(&doc_id());
        let mut errors = 0;
        for cut in (0..pdf.len()).step_by(97) {
            let part = &pdf[..cut];
            match extract_text(part) {
                Ok(_) => {}
                Err(_) => errors += 1,
            }
            let _ = extract_footer_raster(part);
        }
        assert!(errors > 0, "some truncation must be reported, not absorbed");
        // Cutting inside the image stream must be an error, never a short raster.
        let marker = find(&pdf, b"/TTMarker").expect("marker present");
        let e = extract_footer_raster(&pdf[..marker + 200]).unwrap_err();
        assert!(matches!(e.kind(), "malformed" | "limit_exceeded"), "{e}");
    }

    #[test]
    fn byte_flips_never_panic() {
        let pdf = sample(6).build(&doc_id());
        for i in (0..pdf.len()).step_by(53) {
            let mut m = pdf.clone();
            m[i] ^= 0xFF;
            let _ = extract_text(&m);
            let _ = extract_footer_raster(&m);
        }
    }

    #[test]
    fn an_oversized_input_is_a_limit_not_a_crash() {
        let limits = Limits::default();
        let mut big = b"%PDF-1.7\n".to_vec();
        big.resize(limits.config_bytes as usize + 1, b' ');
        let e = extract_text(&big).unwrap_err();
        assert_eq!(e.kind(), "limit_exceeded");
        assert!(e.is_coverage_limitation());
    }

    #[test]
    fn a_stream_claiming_more_bytes_than_the_file_holds_errors() {
        let bad = b"%PDF-1.7\n1 0 obj\n<< /Length 999999 >>\nstream\nshort\nendstream\n".to_vec();
        assert_eq!(extract_text(&bad).unwrap_err().kind(), "malformed");
    }

    #[test]
    fn a_marker_whose_geometry_lies_is_rejected() {
        let mut bad = b"%PDF-1.7\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 4 \
/Height 4 /ColorSpace /DeviceRGB /BitsPerComponent 8 /TTMarker true /Length 6 >>\nstream\n"
            .to_vec();
        bad.extend_from_slice(b"012345");
        bad.extend_from_slice(b"\nendstream\nendobj\n");
        let e = extract_footer_raster(&bad).unwrap_err();
        assert_eq!(e.kind(), "malformed");
    }

    #[test]
    fn deeply_nested_parens_do_not_recurse() {
        let mut stream = b"BT 1 1 Td (".to_vec();
        stream.extend(std::iter::repeat(b'(').take(100_000));
        stream.extend(std::iter::repeat(b')').take(100_001));
        stream.extend_from_slice(b" Tj ET");
        let mut out = String::new();
        // Either it parses or it hits the string limit; neither may overflow a stack.
        let _ = extract_content_text(&stream, &mut out, &Limits::default());
    }

    #[test]
    fn the_word_stream_inside_content_does_not_split_the_scan() {
        let mut b = PdfBuilder::new("t", "f");
        b.paragraph("the upstream endstream stream token appears three times here");
        let pdf = b.build(&doc_id());
        let text = extract_text(&pdf).unwrap();
        assert!(text.contains("upstream endstream stream token"), "{text:?}");
    }
}
