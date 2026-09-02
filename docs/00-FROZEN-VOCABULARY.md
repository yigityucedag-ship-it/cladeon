# TrainTrace — Frozen Vocabulary (Phase 0)

`vocabulary_version = 1`

This document is normative. Every identifier below appears verbatim as a serialised
enum value in `report.json`. Changing any string is a **breaking schema change** and
requires a `schema_version` bump.

---

## 1. Lineage facets

A result is a **stack**, never a single label. Four independent facets are always
emitted, even when the answer is `unknown`.

### 1.1 `weight_origin`

| Value | Meaning |
|---|---|
| `random_initialization_claimed` | Vendor claims weights began from random initialisation |
| `derivative_of_disclosed_base` | Weights derive from a base model the vendor disclosed |
| `distilled_from_teacher` | Weights were produced by distilling a teacher model |
| `unknown` | Not determinable within scope |

### 1.2 `parameter_update`

| Value | Meaning |
|---|---|
| `no_update_observed` | No evidence of any weight update |
| `unmerged_peft_observed` | Adapter artifacts present and structurally coherent |
| `merged_adapter_consistent` | Consistent with an adapter merged into dense weights |
| `partial_or_dense_update` | Broad or partial parameter update |
| `unknown` | Not determinable within scope |

### 1.3 `training_stage`

| Value | Meaning |
|---|---|
| `continued_pretraining` | Further pretraining on the base objective |
| `supervised_instruction_tuning` | SFT / instruction tuning |
| `preference_tuning` | RLHF / DPO / preference optimisation |
| `distillation` | Teacher-to-student objective |
| `other_or_unknown` | Not determinable within scope |

### 1.4 `inference_augmentation`

| Value | Meaning |
|---|---|
| `rag` | Retrieval-augmented generation |
| `external_api_router` | External inference endpoint or router |
| `tools_prompt_orchestration` | Tool calling / prompt orchestration layer |
| `local_direct_inference` | Local weights served directly |
| `none_observed_or_unknown` | Not determinable within scope |

**Facets are not mutually exclusive across the stack.** A valid result is:

> `derivative_of_disclosed_base` -> `continued_pretraining` + `supervised_instruction_tuning`
> -> `merged_adapter_consistent` -> `rag` + `external_api_router`

---

## 2. Support bands — the ONLY permitted conclusion wordings

| Enum value | Rendered text |
|---|---|
| `corroborated_within_supplied_evidence` | "Corroborated within vendor-supplied evidence" |
| `strongly_consistent` | "Strongly consistent" |
| `weakly_consistent` | "Weakly consistent" |
| `partially_supported` | "Partially supported" |
| `insufficient_evidence_abstained` | "Insufficient evidence / abstained" |
| `contradicted_within_observed_scope` | "Contradicted within the observed scope" |
| `artifact_not_supplied_or_out_of_scope` | "Artifact not supplied or outside scan scope" |

### Prohibited output substrings (enforced by test `forbidden_language`)

`lied`, `lying`, `liar`, `fraud`, `fraudulent`, `dishonest`, `deceptive`, `deceit`,
`faked`, `scam`, `certified`, `certification`, `proof that`, `guarantee`,
`guaranteed`, `authentic`, `verified true`, `lie detector`, `99%`, `100% accurate`.

A **contradiction is a conflict between an exact claim and an observed artifact.**
It is never a finding about intent.

---

## 3. Evidence tiers

| Tier | Meaning | Examples |
|---|---|---|
| `E0` | Claim only | Questionnaire answer, marketing sentence |
| `E1` | Mutable supporting record | README, screenshot, config text, invoice |
| `E2` | Direct structural artifact | Adapter tensors, SafeTensors header, checkpoint index |
| `E3` | Cross-corroborated technical trail | Exact base + checkpoints + logs + runtime binding |
| `E4` | Independently supervised evidence | Buyer-selected replay, attested run, neutral infra |

**Correlation grouping.** Evidence carries an `evidence_source_group`. Items sharing a
group contribute **once** — the highest single achievement in the group wins, the rest
are recorded but do not add. A README, a config and a generated model card from the same
directory default to one group (`dir::<alias>`), not three confirmations.

---

## 4. Score

The **Claim Support Score** is a rubric-based support score in `[0, 100]`.
It is **not** a truth probability and **not** calibrated confidence.

Authoritative storage is the integer `score_tenths` in `[0, 1000]`.
No floating-point number ever appears in authoritative JSON.

| `score_tenths` | Band |
|---|---|
| `0..=499` | `insufficient_evidence_abstained` |
| `500..=699` | `weakly_consistent` |
| `700..=849` | `strongly_consistent` |
| `850..=1000` | `corroborated_within_supplied_evidence` |

`partially_supported` and `contradicted_within_observed_scope` are assigned by rule
outcome, not by threshold, and override the band.

---

## 5. Evidence caps (hard maxima on `score_tenths`)

| Cap ID | Condition | Max |
|---|---|---|
| `CAP-QUESTIONNAIRE` | Questionnaire / config text only | 250 |
| `CAP-API-ONLY` | API behaviour only, for a weight-training claim | 350 |
| `CAP-NO-BASE` | Final weights without exact base or trajectory | 550 |
| `CAP-MERGE-UNREPRO` | Merged adapter without exact base or reproducible adapter | 600 |
| `CAP-CPT-NO-OBJ` | CPT or distillation without objective or teacher trajectory | 400 |
| `CAP-SCRATCH-NO-ZERO` | Scratch without step-zero and intermediate checkpoints | 450 |
| `CAP-SINGLE-SOURCE` | Every achieved anchor traces back to one source | 849 |

`CAP-SINGLE-SOURCE` was added during implementation and is not in the original
plan. The plan requires that correlated evidence not be counted repeatedly — a
README, a config and a generated model card from one directory are one source, not
three confirmations. Taking the maximum per anchor removes double-counting *within*
an anchor but not *across* anchors, so a single chatty config could otherwise fill
several anchors on its own and reach `corroborated_within_supplied_evidence`. This
cap states the requirement directly: **corroboration needs more than one independent
source.** A single source can still reach `strongly_consistent`.

Caps are applied after rubric scoring, lowest cap wins, and every applied cap is
listed in `report.json` with its ID and the fact that triggered it.

---

## 6. Method-label emission gate

A facet may emit a positive method label **only if all five hold**:

1. `score_tenths >= 800`
2. a method-specific anchor fact exists (see rule catalogue, `anchor: true`)
3. best contributing evidence tier is `E2` or stronger
4. no `contradiction` outcome on that facet
5. the best mutually-exclusive alternative is at least **150 tenths** lower

Otherwise the facet emits `insufficient_evidence_abstained`.

---

## 7. Mandatory abstention conditions

Any one of these forces `insufficient_evidence_abstained` on the affected facet,
regardless of score:

| ID | Condition |
|---|---|
| `ABS-BASE-UNKNOWN` | Exact base identity unknown |
| `ABS-QUANTIZED-ONLY` | Only quantised or dtype-converted weights available for comparison |
| `ABS-HASH-CONFLICT` | Important hashes conflict |
| `ABS-NO-BINDING` | No binding to the claimed deployment |
| `ABS-CPT-FINAL-ONLY` | CPT-versus-SFT rests only on final weights |
| `ABS-DISTILL-STYLE-ONLY` | Distillation rests only on style or size similarity |
| `ABS-SCRATCH-NOMATCH-ONLY` | Scratch rests only on "no known base matched" |
| `ABS-HYBRID-TOO-CLOSE` | Mutually exclusive hybrid methods within 150 tenths |
| `ABS-EVIDENCE-MUTABLE` | All contributing evidence is `E1` or weaker |

**Missing evidence is not contradiction.** No abstention condition may ever be
rendered as a negative finding about the vendor.

---

## 8. Rubric weights (starting values, `rubric_version = 1`)

Achieved fraction of each anchor is an integer in `[0, 100]`; the facet score in
tenths is `round(10 * sum(weight_i * achieved_i) / rubric_divisor)` where
`rubric_divisor = sum(weight_i)`.

| Claim | Anchors (weight) | Divisor |
|---|---|---|
| `unmerged_lora` | structure 30; base 20; base_consistency 20; load_or_remerge_record 20; deployment_binding 10 | 100 |
| `merged_adapter` | exact_base 15; delta_pattern 25; pre_merge_adapter 20; merge_reproduction 30; binding 10 | 100 |
| `dense_finetune` | pre_post 15; broad_deltas 20; optimizer_trainability 20; progression 20; replay 15; binding 10 | 100 |
| `continued_pretraining` | base 10; trajectory 15; objective_data_tokens 25; optimizer 20; replay 20; binding 10 | 100 |
| `distillation` | teacher 15; teacher_outputs 25; objective 20; trajectory 15; replay 15; binding 10 | 100 |
| `rag` | index 20; retrieval_trace 25; prompt_assembly 25; replay 15; binding 15 | 100 |
| `external_api` | binding 20; config 20; observed_egress 35; upstream_correlation 20; other 5 | 100 |
| `scratch` | identity 5; step_zero 20; trajectory 20; optimizer_data_order 15; data_tokenizer 10; compute_jobs 15; replay 10; candidate_exclusion 5 | 100 |

`rubric_divisor` is written into `report.json` for every scored claim so a verifier
can recompute the arithmetic without knowing the table.

---

## 9. Rule outcome kinds

| Kind | Meaning | May lower score |
|---|---|---|
| `supporting_evidence` | Fact supports the claim | no |
| `missing_anchor` | A required anchor is absent | no (caps instead) |
| `contradiction` | Exact claim conflicts with an observed artifact | yes |
| `ambiguity` | Fact is compatible with several mutually exclusive claims | no |
| `coverage_limitation` | Scanner could not observe something | no |
| `next_evidence_request` | Concrete artifact that would resolve uncertainty | no |

---

## 10. Assurance level

Stage 1 always emits `assurance_level = "vendor_self_scan"`. No other value is
reachable in this repository.

---

## 11. Required report statement (verbatim)

> This Stage-1 report evaluates consistency within vendor-supplied evidence. It does
> not establish intent, independently verify the production environment, or prove
> historical training events that cannot be reconstructed from the supplied artifacts.

---

## 12. Verify status axes — reported separately, never merged

| Axis | Values |
|---|---|
| `integrity_status` | `intact`, `modified`, `incomplete`, `unreadable` |
| `challenge_status` | `bound`, `unsigned`, `signature_invalid`, `expired`, `case_mismatch`, `absent` |
| `marker_status` | `present_consistent`, `present_inconsistent`, `absent`, `not_applicable` |
| `coverage_status` | `complete`, `partial`, `minimal` |
| `evidence_status` | one of the §2 support bands |

A bundle whose bytes are intact but whose evidence is thin reports
`integrity_status = intact` **and** `evidence_status = insufficient_evidence_abstained`.
The two are never combined into a single verdict.
