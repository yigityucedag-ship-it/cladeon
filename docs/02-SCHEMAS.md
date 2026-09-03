# Cladeon — Bundle and Document Schemas (Phase 0)

`schema_version = 1`

## 0. Canonicalisation rules (normative)

All authoritative documents are serialised through `cl_core::canon`.

1. The canonical value model has exactly six kinds: `null`, `bool`, **integer**,
   `string`, `array`, `object`. **There is no float.** Attempting to place a float in
   an authoritative document is a compile-time impossibility (`CanonValue` has no
   float variant) and a runtime error in the JSON importer.
2. Object keys are sorted by their **UTF-16 code-unit sequence**, per RFC 8785.
3. No insignificant whitespace. Separators are `,` and `:`.
4. Strings use the shortest escape form required by RFC 8785 §3.2.2.2.
5. Integers serialise in base 10 with no leading `+`, no leading zeros, and `-0`
   normalised to `0`. Range is `i64`.
6. Duplicate object keys are rejected on both write and read.
7. Output is UTF-8 with no BOM.

Rationale: RFC 8785 exists because hashing and signing require an invariant
representation. Removing floats removes the single largest source of cross-platform
divergence, at the cost of storing tenths as integers (`score_tenths = 743` means
74.3).

### Digests

`sha256` values are lowercase hex, 64 characters. A digest of a canonical document is
the SHA-256 of its canonical UTF-8 bytes.

---

## 1. `challenge.json`

Issued by the buyer, signed with Ed25519. The scanner holds only the public key.

```
{
  "schema_version": 1,
  "case_id": "CL-2026-0F3A9C",
  "nonce": "<32 lowercase hex chars>",
  "vendor_label": "Acme Analytics Ltd",
  "exact_claim_text": "We trained our own large language model from scratch.",
  "declared_facets_requested": true,
  "issued_at": "2026-09-02T13:00:00Z",
  "expires_at": "2026-09-16T13:00:00Z",
  "expected_scanner_sha256": "<64 hex>",
  "ruleset_version": 1,
  "vocabulary_version": 1,
  "requested_evidence": ["adapter_config", "base_identity", "training_logs"],
  "issuer_public_key": "<64 hex, Ed25519>"
}
```

`challenge.sig` is the raw 64-byte Ed25519 signature, hex-encoded, over the canonical
bytes of `challenge.json`.

Timestamps are RFC 3339 UTC with a literal `Z` and second precision.

An **unsigned** challenge is permitted for pilots. Verify then reports
`challenge_status = "unsigned"` rather than failing.

---

## 2. `report.json`

The authoritative document. The PDF is a rendering of it.

```
{
  "schema_version": 1,
  "vocabulary_version": 1,
  "ruleset_version": 1,
  "rubric_version": 1,
  "scanner_name": "Cladeon Screen",
  "scanner_version": "0.1.0",
  "scanner_build_sha256": "<64 hex, self-hash of the running executable>",

  "case_id": "CL-2026-0F3A9C",
  "challenge_sha256": "<64 hex>",
  "vendor_label": "Acme Analytics Ltd",
  "exact_claim_text": "...",

  "assurance_level": "vendor_self_scan",
  "scan_mode": "offline_default",
  "network_enabled": false,

  "host": {
    "os": "Windows 11",
    "os_build": "26200",
    "arch": "x86_64",
    "scanner_started_at": "2026-09-02T13:14:00Z",
    "scanner_finished_at": "2026-09-02T13:16:42Z"
  },

  "declared_facets": {
    "weight_origin": "random_initialization_claimed",
    "parameter_update": "partial_or_dense_update",
    "training_stage": "continued_pretraining",
    "inference_augmentation": ["rag", "external_api_router"]
  },

  "scope": {
    "selected_roots": [{"alias": "ROOT1", "note": "vendor selection 1"}],
    "excluded_paths": [{"alias": "ROOT1/private", "reason": "excluded_by_submitter"}],
    "bytes_enumerated": 4831838208,
    "bytes_hashed": 4831838208,
    "files_enumerated": 1284,
    "files_hashed": 1284,
    "coverage_status": "complete"
  },

  "redaction_ledger": [
    {"rule": "CL-PRIV-002", "kind": "windows_username", "count": 31},
    {"rule": "CL-PRIV-005", "kind": "submitter_display_redaction",
     "count": 2, "fact_ids": ["F-0031", "F-0044"]}
  ],

  "observations": [
    {
      "fact_id": "F-0001",
      "kind": "adapter_config",
      "artifact_id": "A-0007",
      "fields": {"peft_type": "LORA", "r": 16, "lora_alpha": 32},
      "source_group": "dir::ROOT1/adapter"
    }
  ],

  "rule_outcomes": [
    {
      "rule_id": "CL-LORA-003",
      "ruleset_version": 1,
      "kind": "supporting_evidence",
      "facet": "parameter_update",
      "claim": "unmerged_lora",
      "anchor": "structure",
      "achievement": 100,
      "evidence_tier": "E2",
      "source_group": "dir::ROOT1/adapter",
      "fact_ids": ["F-0001", "F-0002"],
      "artifact_sha256": ["<64 hex>"],
      "text": "Adapter tensor shapes are consistent with the declared rank."
    }
  ],

  "conclusions": [
    {
      "facet": "parameter_update",
      "claim": "unmerged_lora",
      "band": "strongly_consistent",
      "score_tenths": 743,
      "rubric_divisor": 100,
      "anchor_scores": [{"anchor": "structure", "weight": 30, "achievement": 100}],
      "caps_applied": [{"cap_id": "CAP-NO-BASE", "max_tenths": 550,
                        "triggered_by": ["CL-BASE-003"]}],
      "abstentions": [],
      "best_evidence_tier": "E2",
      "method_label_emitted": true,
      "alternatives": [{"claim": "merged_adapter", "score_tenths": 410}]
    }
  ],

  "contradictions": ["CL-XFACET-002"],
  "limitations": ["CL-BIND-005", "CL-API-008"],
  "next_evidence_requests": ["CL-MERGE-006"],

  "required_statement": "This Stage-1 report evaluates consistency within ...",

  "artifact_manifest_sha256": "<64 hex>",
  "evidence_digest": "<64 hex>"
}
```

### `evidence_digest`

SHA-256 of the canonical serialisation of the **reproducible subset** of the report:
`declared_facets`, `observations`, `rule_outcomes`, `conclusions`,
`artifact_manifest_sha256`. It deliberately excludes timestamps, host details, the
nonce, and every rendering field, so that **two scans of unchanged evidence produce the
same `evidence_digest`.** This is an acceptance test, not an aspiration.

---

## 3. `artifact-manifest.json`

```
{
  "schema_version": 1,
  "artifacts": [
    {
      "artifact_id": "A-0007",
      "path_alias": "ROOT1/adapter/adapter_model.safetensors",
      "artifact_type": "safetensors",
      "size_bytes": 134217728,
      "sha256": "<64 hex>",
      "hash_scope": "full",
      "parser": "safetensors_header",
      "parser_version": 1,
      "read_status": "ok",
      "changed_during_scan": false
    }
  ]
}
```

`hash_scope` is `full`, `head_only` (first N bytes, N recorded) or `none`.
`read_status` is `ok`, `access_denied`, `too_large`, `changed`, `io_error`,
`skipped_reparse_point`, `skipped_by_submitter`.

---

## 4. `integrity-envelope.json`

```
{
  "schema_version": 1,
  "payloads": [
    {"name": "report.json", "sha256": "<64 hex>", "size_bytes": 41230},
    {"name": "artifact-manifest.json", "sha256": "<64 hex>", "size_bytes": 90112},
    {"name": "challenge.json", "sha256": "<64 hex>", "size_bytes": 812},
    {"name": "report.pdf", "sha256": "<64 hex>", "size_bytes": 148003},
    {"name": "forensic-markers.json", "sha256": "<64 hex>", "size_bytes": 640}
  ],
  "root_digest": "<64 hex>",
  "bundle_format": 1
}
```

`root_digest` = SHA-256 of the canonical JSON array of `[name, sha256]` pairs sorted by
`name`. Verify recomputes it. **This is self-consistency, not independent cryptographic
proof** — an offline scanner in hostile hands can recompute the same values.

---

## 5. `forensic-markers.json`

```
{
  "schema_version": 1,
  "marker_version": 1,
  "numeric_canary": {
    "carrier_fields": ["conclusions[0].display_score", "scope.bytes_hashed_display"],
    "expected_digit_sequence": "47",
    "derivation": "sha256(evidence_digest || case_id || nonce)",
    "note": "Non-analytical rendering-integrity digits. They never affect thresholds or conclusions."
  },
  "tint_marker": {
    "carrier": "footer_raster",
    "carrier_pages": "all",
    "carrier_width": 240,
    "carrier_height": 40,
    "expected_tag": "<32 hex>",
    "expected_carrier_sha256": "<64 hex>",
    "ecc": "repetition_x7_majority",
    "detector": "normalised_correlation",
    "detector_threshold_percent": 70
  }
}
```

---

## 6. `VERIFY.txt`

Plain ASCII, no active content. Contains the case ID, the bundle SHA-256, the exact
command to run Verify, and the sentence that the PDF is a rendering while `report.json`
is authoritative.

---

## 7. `.clade` container

- ZIP-compatible, custom extension, `bundle_format = 1`.
- Entry order is fixed and deterministic:
  `challenge.json`, `challenge.sig`, `report.json`, `artifact-manifest.json`,
  `forensic-markers.json`, `integrity-envelope.json`, `report.pdf`, `VERIFY.txt`.
- Stored timestamps are fixed to `1980-01-01T00:00:00` so the container is
  byte-reproducible.
- No executable content, no directories, no duplicate names.

### Reader limits (Verify treats the bundle as hostile)

| Limit | Value |
|---|---|
| Max entries | 32 |
| Max single uncompressed entry | 64 MiB |
| Max total uncompressed | 128 MiB |
| Max compression ratio per entry | 200:1 |
| Entry name charset | `[A-Za-z0-9._-]` only |
| Path separators in names | rejected |
| Absolute names, `..`, drive letters | rejected |
| Duplicate names | rejected |
| Unknown names | rejected |

File name: `CL-<case-id>-<first 12 hex of root_digest>.clade`

---

## 8. Parser limits (scanner side)

| Limit | Value |
|---|---|
| SafeTensors header | 16 MiB |
| GGUF metadata region | 16 MiB |
| ONNX metadata prefix scan | 8 MiB |
| JSON / YAML / TOML config | 8 MiB |
| Max JSON nesting depth | 64 |
| Max object keys per object | 65 536 |
| Max array elements | 1 048 576 |
| Max string length | 1 MiB |
| Log file tail read | 4 MiB |
| Log line length | 64 KiB |
| Hash buffer | 1 MiB |
| Default per-file full-hash budget | 8 GiB |
| Max files enumerated | 2 000 000 |
| Max traversal depth | 64 |

Exceeding any limit produces a `coverage_limitation`, never a contradiction, and never
a partial parse presented as complete.
