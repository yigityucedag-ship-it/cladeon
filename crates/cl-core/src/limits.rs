//! Every bound in one place, mirroring `docs/02-SCHEMAS.md` §8.
//!
//! Exceeding a limit is always a `coverage_limitation`: the scanner reports what it
//! could not see. It is never a contradiction, and a truncated parse is never
//! presented as a complete one.

/// Parser bounds applied to vendor-supplied files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub safetensors_header_bytes: u64,
    pub gguf_metadata_bytes: u64,
    pub onnx_prefix_bytes: u64,
    pub config_bytes: u64,
    pub json_max_depth: usize,
    pub json_max_object_keys: usize,
    pub json_max_array_elements: usize,
    pub json_max_string_bytes: usize,
    pub log_tail_bytes: u64,
    pub log_max_line_bytes: usize,
    pub per_file_hash_budget_bytes: u64,
    pub max_files_enumerated: u64,
    pub max_traversal_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            safetensors_header_bytes: 16 * 1024 * 1024,
            gguf_metadata_bytes: 16 * 1024 * 1024,
            onnx_prefix_bytes: 8 * 1024 * 1024,
            config_bytes: 8 * 1024 * 1024,
            json_max_depth: 64,
            json_max_object_keys: 65_536,
            json_max_array_elements: 1_048_576,
            json_max_string_bytes: 1024 * 1024,
            log_tail_bytes: 4 * 1024 * 1024,
            log_max_line_bytes: 64 * 1024,
            per_file_hash_budget_bytes: 8 * 1024 * 1024 * 1024,
            max_files_enumerated: 2_000_000,
            max_traversal_depth: 64,
        }
    }
}

impl Limits {
    /// A deliberately tiny profile used by fuzz and abuse tests so that limit
    /// behaviour is exercised without multi-megabyte fixtures.
    pub fn tiny() -> Self {
        Limits {
            safetensors_header_bytes: 4096,
            gguf_metadata_bytes: 4096,
            onnx_prefix_bytes: 4096,
            config_bytes: 4096,
            json_max_depth: 8,
            json_max_object_keys: 16,
            json_max_array_elements: 32,
            json_max_string_bytes: 256,
            log_tail_bytes: 4096,
            log_max_line_bytes: 256,
            per_file_hash_budget_bytes: 4096,
            max_files_enumerated: 64,
            max_traversal_depth: 4,
        }
    }
}

/// Bounds applied by the verifier when reading a `.clade`, which is treated as
/// hostile input from an untrusted party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleLimits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_name_bytes: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        BundleLimits {
            max_entries: 32,
            max_entry_bytes: 64 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_name_bytes: 64,
        }
    }
}
