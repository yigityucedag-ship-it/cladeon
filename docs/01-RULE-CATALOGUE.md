# TrainTrace — Rule Catalogue (Phase 0)

`ruleset_version = 1`

Every rule is deterministic, versioned, and consumes only normalised **facts**.
Facts contain no verdict language; rules contain no parsing.

Columns:

- **Anchor** — the rubric anchor this rule feeds (`docs/00-FROZEN-VOCABULARY.md` §8).
  `—` means the rule contributes no score, only narrative.
- **Ach** — achievement contributed to that anchor, in `[0, 100]`. Multiple rules may
  feed one anchor; the anchor takes the **maximum** achievement across
  distinct `evidence_source_group`s, then the highest single value overall.
- **Tier** — the evidence tier this rule can confer.
- **Kind** — `S` supporting, `M` missing anchor, `X` contradiction, `A` ambiguity,
  `C` coverage limitation, `N` next-evidence request.
- **Anc** — `Y` if this rule satisfies the "method-specific anchor exists" gate
  (§6 of the vocabulary).

---

## 1. Inventory and coverage — `TT-INV-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-INV-001` | Selected root readable and enumerated | — | — | E1 | S | N |
| `TT-INV-002` | Access denied on a selected subtree | — | — | — | C | N |
| `TT-INV-003` | Reparse point not traversed (symlink / junction / mount) | — | — | — | C | N |
| `TT-INV-004` | File changed during scan; hash marked unstable | — | — | — | C | N |
| `TT-INV-005` | File exceeded configured hash budget; metadata only | — | — | — | C | N |
| `TT-INV-006` | Path length or encoding prevented access | — | — | — | C | N |
| `TT-INV-007` | No model-bearing artifact found in any selected root | — | — | — | C | N |
| `TT-INV-008` | Selected scope contains only documents and text | — | — | — | C | N |

`TT-INV-007` and `TT-INV-008` are the two rules that most often force
`artifact_not_supplied_or_out_of_scope`.

---

## 2. Parse status — `TT-FMT-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-FMT-001` | SafeTensors header parsed within limits | — | — | E2 | S | N |
| `TT-FMT-002` | SafeTensors header malformed, truncated or over limit | — | — | — | C | N |
| `TT-FMT-003` | GGUF header and key/value metadata parsed | — | — | E2 | S | N |
| `TT-FMT-004` | GGUF header malformed or over limit | — | — | — | C | N |
| `TT-FMT-005` | ONNX model metadata parsed without running operators | — | — | E2 | S | N |
| `TT-FMT-006` | Opaque serialisation present; hashed but never deserialised | — | — | E1 | C | N |
| `TT-FMT-007` | Shard index parsed and shard set complete | — | — | E2 | S | N |
| `TT-FMT-008` | Shard index references shards absent from scope | — | — | — | C | N |
| `TT-FMT-009` | Bounded JSON/YAML/TOML config parsed | — | — | E1 | S | N |
| `TT-FMT-010` | Config rejected: depth, key count, or size limit | — | — | — | C | N |
| `TT-FMT-011` | Duplicate keys in an authoritative config; parse refused | — | — | — | C | N |

`TT-FMT-006` covers `.pt`, `.pth`, `.bin`, pickle, joblib and NumPy object arrays.
Presence is recorded as evidence; the content is never read.

---

## 3. Base model identity — `TT-BASE-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-BASE-001` | Exact base revision or commit hash supplied | base / exact_base | 100 | E2 | S | Y |
| `TT-BASE-002` | Base named without revision or hash | base / exact_base | 30 | E1 | S | N |
| `TT-BASE-003` | No base identity of any kind supplied | base / exact_base | 0 | — | M | N |
| `TT-BASE-004` | Base referenced by adapter config differs from vendor declaration | — | — | E2 | X | N |
| `TT-BASE-005` | Architecture and hidden size consistent with declared base family | base_consistency | 60 | E2 | S | N |
| `TT-BASE-006` | Architecture inconsistent with declared base family | — | — | E2 | X | N |
| `TT-BASE-007` | Tokenizer identity matches declared base | base_consistency | 40 | E2 | S | N |
| `TT-BASE-008` | Tokenizer vocabulary size differs from declared base | — | — | E2 | A | N |
| `TT-BASE-009` | Base weights present in scope and hashed | base_consistency | 100 | E2 | S | N |

`TT-BASE-004` and `TT-BASE-006` are the only base-family contradictions. A base that
is merely *unnamed* produces `TT-BASE-003`, a missing anchor, never a contradiction.

---

## 4. Unmerged PEFT / LoRA — `TT-LORA-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-LORA-001` | PEFT adapter config declares a PEFT method | structure | 45 | E2 | S | Y |
| `TT-LORA-002` | Adapter tensor keys present and method-consistent | structure | 75 | E2 | S | Y |
| `TT-LORA-003` | Adapter tensor shapes consistent with declared rank | structure | 100 | E2 | S | Y |
| `TT-LORA-004` | Adapter target modules match tensor key set | structure | 90 | E2 | S | N |
| `TT-LORA-005` | Adapter size is a small fraction of base size | structure | 55 | E2 | S | N |
| `TT-LORA-006` | Declared rank contradicted by tensor shapes | — | — | E2 | X | N |
| `TT-LORA-007` | Adapter config present but adapter tensors absent from scope | — | — | — | M | N |
| `TT-LORA-008` | Adapter tensors present but no adapter config in scope | structure | 40 | E2 | A | N |
| `TT-LORA-009` | `modules_to_save` declares additional trained modules | structure | 60 | E2 | S | N |
| `TT-LORA-010` | DoRA / RS-LoRA variant declared; expected tensor set adjusted | — | — | E2 | S | N |
| `TT-LORA-011` | Multiple distinct adapters present in scope | — | — | E2 | A | N |
| `TT-LORA-012` | Adapter declares a base the scan cannot resolve | — | — | — | M | N |
| `TT-LORA-013` | Load or re-merge record observed in logs or serving config | load_or_remerge_record | 100 | E2 | S | N |
| `TT-LORA-014` | No load or re-merge record for the adapter | load_or_remerge_record | 0 | — | M | N |
| `TT-LORA-015` | Trainable / total parameter record consistent with rank and targets | base_consistency | 80 | E2 | S | N |
| `TT-LORA-016` | Trainable / total parameter record inconsistent with rank and targets | — | — | E2 | X | N |

**Hard limitation, always emitted with any LoRA conclusion:** absence of adapter files
never establishes that LoRA was not used, because an adapter may have been merged.

---

## 5. Merged adapter — `TT-MERGE-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-MERGE-001` | Full-size dense checkpoint present with declared base | exact_base | 60 | E2 | S | N |
| `TT-MERGE-002` | Merge log or merge configuration observed | pre_merge_adapter | 70 | E1 | S | N |
| `TT-MERGE-003` | Pre-merge adapter supplied alongside merged checkpoint | pre_merge_adapter | 100 | E2 | S | Y |
| `TT-MERGE-004` | Architecture, tokenizer and tensor layout compatible with declared base | exact_base | 80 | E2 | S | N |
| `TT-MERGE-005` | Stage-1 cannot establish low-rank delta structure | delta_pattern | 0 | — | M | N |
| `TT-MERGE-006` | Merge reproduction requires Stage 2 | merge_reproduction | 0 | — | N | N |
| `TT-MERGE-007` | Quantised or dtype-converted final weights prevent delta analysis | — | — | — | C | N |

`TT-MERGE-005` and `TT-MERGE-006` are **always** emitted when a merged-adapter claim is
declared. Stage 1 abstains on merged LoRA by construction: `delta_pattern` (25) and
`merge_reproduction` (30) can never be achieved here, so the ceiling is 45 before caps.

---

## 6. Dense or partial fine-tuning — `TT-DENSE-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-DENSE-001` | Both pre-training and final checkpoint identities supplied | pre_post | 100 | E2 | S | Y |
| `TT-DENSE-002` | Only final checkpoint identity supplied | pre_post | 20 | E2 | M | N |
| `TT-DENSE-003` | Optimizer parameter groups or trainability record observed | optimizer_trainability | 100 | E2 | S | Y |
| `TT-DENSE-004` | Intermediate checkpoints observed with increasing step numbers | progression | 100 | E2 | S | Y |
| `TT-DENSE-005` | Single checkpoint only; no progression observable | progression | 0 | — | M | N |
| `TT-DENSE-006` | Loss / learning-rate history observed and monotone-plausible | progression | 70 | E2 | S | N |
| `TT-DENSE-007` | Loss history present but internally inconsistent with step record | — | — | E2 | X | N |
| `TT-DENSE-008` | Broad tensor-level deltas require Stage 2 | broad_deltas | 0 | — | N | N |
| `TT-DENSE-009` | Full-size checkpoint does not establish that every parameter was trained | — | — | — | C | N |

---

## 7. Continued pretraining — `TT-CPT-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-CPT-001` | Causal-LM or declared training objective observed in config | objective_data_tokens | 45 | E2 | S | Y |
| `TT-CPT-002` | Corpus manifest with token counts observed | objective_data_tokens | 100 | E2 | S | Y |
| `TT-CPT-003` | Tokenizer version or vocabulary change recorded | objective_data_tokens | 55 | E2 | S | N |
| `TT-CPT-004` | Checkpoint and optimizer trajectory observed | optimizer | 100 | E2 | S | Y |
| `TT-CPT-005` | Loss-versus-token history observed | trajectory | 100 | E2 | S | N |
| `TT-CPT-006` | Final weights alone cannot distinguish CPT from dense SFT | — | — | — | C | N |
| `TT-CPT-007` | Objective, data and trajectory all absent | objective_data_tokens | 0 | — | M | N |

`TT-CPT-006` is unconditional whenever a CPT claim is declared, and it activates
`ABS-CPT-FINAL-ONLY` when `TT-CPT-001`, `-002`, `-004` and `-005` all fail.

---

## 8. Distillation — `TT-DIST-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-DIST-001` | Immutable teacher identity and revision supplied | teacher | 100 | E2 | S | Y |
| `TT-DIST-002` | Teacher named without revision | teacher | 30 | E1 | S | N |
| `TT-DIST-003` | Distillation objective observed (KL, soft targets, logits) | objective | 100 | E2 | S | Y |
| `TT-DIST-004` | Hashed teacher-output or logit cache observed | teacher_outputs | 100 | E2 | S | Y |
| `TT-DIST-005` | Paired teacher/student examples observed | teacher_outputs | 60 | E2 | S | N |
| `TT-DIST-006` | Student checkpoint trajectory observed | trajectory | 100 | E2 | S | N |
| `TT-DIST-007` | Size or behavioural similarity alone does not establish distillation | — | — | — | C | N |
| `TT-DIST-008` | Vendor definition of "distillation" not recorded | — | — | — | N | N |

---

## 9. Claimed random-initialisation training — `TT-SCRATCH-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-SCRATCH-001` | Step-zero / random-init checkpoint committed before training | step_zero | 100 | E2 | S | Y |
| `TT-SCRATCH-002` | Early and intermediate checkpoints observed | trajectory | 100 | E2 | S | Y |
| `TT-SCRATCH-003` | Optimizer, scheduler, seed and data-order state observed | optimizer_data_order | 100 | E2 | S | N |
| `TT-SCRATCH-004` | Training configuration observed | identity | 100 | E2 | S | N |
| `TT-SCRATCH-005` | Dataset manifest with hashes and token counts observed | data_tokenizer | 70 | E2 | S | N |
| `TT-SCRATCH-006` | Tokenizer-training artifacts observed | data_tokenizer | 100 | E2 | S | N |
| `TT-SCRATCH-007` | GPU job telemetry or hardware hours observed | compute_jobs | 100 | E2 | S | N |
| `TT-SCRATCH-008` | Storage / checkpoint chronology coherent | trajectory | 60 | E2 | S | N |
| `TT-SCRATCH-009` | No step-zero checkpoint in scope | step_zero | 0 | — | M | N |
| `TT-SCRATCH-010` | Failure to match a known base does not establish random initialisation | candidate_exclusion | 0 | — | C | N |
| `TT-SCRATCH-011` | Claim of original architecture recorded separately from original weights | — | — | — | S | N |
| `TT-SCRATCH-012` | Claim of original tokenizer recorded separately from original weights | — | — | — | S | N |
| `TT-SCRATCH-013` | Reused known architecture is compatible with a scratch weight claim | — | — | — | A | N |

`TT-SCRATCH-010` is unconditional on every scratch claim and activates
`ABS-SCRATCH-NOMATCH-ONLY` when it is the only negative-space evidence available.

---

## 10. RAG — `TT-RAG-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-RAG-001` | Request-level retrieval chain observed (query, chunks, scores, context) | retrieval_trace | 100 | E2 | S | Y |
| `TT-RAG-002` | Vector index or retrieval-store manifest observed | index | 100 | E2 | S | N |
| `TT-RAG-003` | Embedding model identity and revision observed | index | 70 | E2 | S | N |
| `TT-RAG-004` | Chunking and index-build configuration observed | prompt_assembly | 50 | E1 | S | N |
| `TT-RAG-005` | Prompt-assembly template observed | prompt_assembly | 100 | E2 | S | N |
| `TT-RAG-006` | RAG-on / RAG-off replay record observed | replay | 100 | E3 | S | N |
| `TT-RAG-007` | Vector store present in scope is not evidence of production use | — | — | — | C | N |
| `TT-RAG-008` | RAG coexists with any weight-training claim; facets scored independently | — | — | — | S | N |

---

## 11. External API / router — `TT-API-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-API-001` | Provider endpoint and model configuration observed | config | 100 | E2 | S | Y |
| `TT-API-002` | Provider SDK dependency observed in lockfile or manifest | config | 60 | E1 | S | N |
| `TT-API-003` | Request IDs, timings or outbound inference traces observed | observed_egress | 100 | E2 | S | Y |
| `TT-API-004` | Serving command line or router/fallback configuration observed | binding | 100 | E2 | S | N |
| `TT-API-005` | No local weights present in any selected root | — | — | E2 | S | N |
| `TT-API-006` | External endpoint observed; provider identity not independently bound | — | — | — | C | N |
| `TT-API-007` | A remote endpoint may still be vendor-owned | — | — | — | C | N |
| `TT-API-008` | Findings apply only to sampled requests; routing and caching may vary | — | — | — | C | N |
| `TT-API-009` | Upstream correlation requires provider-side records | upstream_correlation | 0 | — | N | N |
| `TT-API-010` | External endpoint observed while a local-training claim is declared | — | — | E2 | A | N |

`TT-API-006`, `-007` and `-008` are unconditional whenever any `TT-API-*` support rule
fires. `TT-API-010` is an **ambiguity**, not a contradiction: a vendor may legitimately
train weights and also call an external service.

---

## 12. Compute plausibility — `TT-COMPUTE-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-COMPUTE-001` | Declared compute falls within the order-of-magnitude band for `C ~ 6*N*D` | compute_jobs | 60 | E1 | S | N |
| `TT-COMPUTE-002` | Declared compute is below the band by more than one order of magnitude | — | — | E1 | A | N |
| `TT-COMPUTE-003` | Declared compute is above the band by more than two orders of magnitude | — | — | E1 | A | N |
| `TT-COMPUTE-004` | Parameter count or token count not supplied; no plausibility screen possible | — | — | — | M | N |
| `TT-COMPUTE-005` | Compute plausibility is an order-of-magnitude screen, never proof | — | — | — | C | N |

The band is deliberately wide: `[C/30, C*30]`. `TT-COMPUTE-002` and `-003` are
**ambiguities**, never contradictions, because efficiency, precision, MoE sparsity and
hardware utilisation legitimately move the figure by an order of magnitude.

---

## 13. Chronology — `TT-CHRONO-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-CHRONO-001` | Checkpoint modification times increase with step number | progression | 50 | E1 | S | N |
| `TT-CHRONO-002` | Checkpoint times decrease against step number | — | — | E1 | A | N |
| `TT-CHRONO-003` | All artifacts share one modification timestamp | — | — | E1 | A | N |
| `TT-CHRONO-004` | Training log records a start time later than a checkpoint it references | — | — | E2 | X | N |
| `TT-CHRONO-005` | Filesystem timestamps are trivially settable and are E1 at best | — | — | — | C | N |

`TT-CHRONO-003` (a whole tree copied at once) is an ambiguity, not a contradiction —
copying a directory is ordinary. Only `TT-CHRONO-004`, an internal conflict inside
vendor-supplied records, reaches contradiction.

---

## 14. Parameter accounting — `TT-PARAM-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-PARAM-001` | Parameter count derived from tensor headers | — | — | E2 | S | N |
| `TT-PARAM-002` | Derived parameter count matches vendor declaration within 2 percent | base_consistency | 70 | E2 | S | N |
| `TT-PARAM-003` | Derived parameter count differs from declaration by more than 2 percent | — | — | E2 | X | N |
| `TT-PARAM-004` | Quantised storage prevents exact parameter accounting | — | — | — | C | N |

---

## 15. Deployment binding — `TT-BIND-*`

| ID | Title | Anchor | Ach | Tier | Kind | Anc |
|---|---|---|---|---|---|---|
| `TT-BIND-001` | Serving configuration references an artifact inside the scanned scope | binding / deployment_binding | 100 | E2 | S | N |
| `TT-BIND-002` | Container or deployment manifest references a scanned artifact by digest | binding / deployment_binding | 100 | E2 | S | N |
| `TT-BIND-003` | Serving configuration references a path outside the scanned scope | binding / deployment_binding | 20 | E1 | C | N |
| `TT-BIND-004` | No serving or deployment configuration observed | binding / deployment_binding | 0 | — | M | N |
| `TT-BIND-005` | Scanned folder is not established to be the production deployment | — | — | — | C | N |

`TT-BIND-005` is unconditional on every report and is the source of `ABS-NO-BINDING`
when no `TT-BIND-001` or `-002` fires.

---

## 16. Privacy and redaction — `TT-PRIV-*`

| ID | Title | Kind |
|---|---|---|
| `TT-PRIV-001` | Candidate secret redacted before it entered the report | C |
| `TT-PRIV-002` | Windows username replaced by a scoped alias | C |
| `TT-PRIV-003` | Absolute path replaced by a scoped alias | C |
| `TT-PRIV-004` | Submitter excluded a source from the scan; recorded as excluded | C |
| `TT-PRIV-005` | Submitter redacted a displayed value; the fact itself is retained | C |

`TT-PRIV-004` and `TT-PRIV-005` exist because the vendor may hide *values* but may
never delete a negative *fact*. Both are always visible to the buyer.

---

## 17. Cross-facet consistency — `TT-XFACET-*`

| ID | Title | Kind |
|---|---|---|
| `TT-XFACET-001` | Declared facet set is internally coherent | S |
| `TT-XFACET-002` | `no_update_observed` declared while adapter artifacts are present | X |
| `TT-XFACET-003` | `random_initialization_claimed` declared while an adapter config names a base | X |
| `TT-XFACET-004` | `local_direct_inference` declared while an external endpoint is configured | A |
| `TT-XFACET-005` | Two mutually exclusive weight-origin facets declared | X |

---

## 18. Rule invariants (enforced by `tt-rules` unit tests)

1. Every rule ID is unique and matches `^TT-[A-Z]+-[0-9]{3}$`.
2. Every rule with `Kind = X` cites at least one artifact hash in its output.
3. No rule with `Kind = M` may reduce a score. Missing evidence caps; it never subtracts.
4. Every `Kind = C` rule renders text that names a limitation of the *scanner*, never a
   property of the vendor.
5. Every anchor named in a rule row exists in the rubric for the claim it feeds.
6. Rendering every rule's text and concatenating it must not contain any prohibited
   substring from §2 of the frozen vocabulary.
7. Every unconditional rule listed in this document fires on every applicable report.
