# TrainTrace — Acceptance Tests

`acceptance_version = 1`

Every row below names a test that exists and runs. Where a promise in this repository
is not yet enforced by a test, it is listed at the bottom as an open gap rather than
implied to be covered.

Run everything:

```bash
cargo test --workspace
```

**Current state: 647 tests, 0 failures, 0 compiler warnings.**

---

## 1. The stance — that the tool does not accuse

The failure mode that matters most is a screen that reports a conflict against an
honest vendor. These are the tests that protect against it.

| Promise | Test | Where |
|---|---|---|
| No case that should be quiet raises a contradiction | `no_case_that_should_be_quiet_raises_a_contradiction` | `tt-screen/corpus` |
| An ordinary ordered training log produces no contradiction | `an_ordinary_training_log_produces_no_contradiction` | `tt-contracts` |
| An absent ordering flag is not read as disorder | `an_absent_ordering_flag_is_not_read_as_disorder` | `tt-contracts` |
| Missing anchors never reduce a score | `missing_anchors_never_reduce_a_score` | `tt-contracts`, `tt-rules` |
| Every contradiction cites an artifact digest and a fact | `every_contradiction_cites_an_artifact_digest` | `tt-contracts` |
| A copied directory timestamp is an ambiguity, not a contradiction | `copied_timestamps` corpus case | `tt-screen/corpus` |
| A tidy loss curve is not evidence of fabrication | `fabricated_neat_logs` corpus case | `tt-screen/corpus` |

**But abstention is not silence.** A genuine conflict is still reported:

| Promise | Test |
|---|---|
| A declared rank of 32 against tensors implying 8 IS a contradiction | `a_real_conflict_is_still_reported_as_a_contradiction` |

---

## 2. Abstention — that the tool does not over-claim

| Promise | Test |
|---|---|
| Stage 1 cannot name a merged adapter, whatever the evidence | `stage_one_cannot_name_a_merged_adapter` (`tt-contracts`), `merged_adapter_is_unreachable_in_stage_one_even_with_perfect_evidence` (`tt-rules`) |
| Every case whose ground truth requires abstention abstains | `cases_that_must_abstain_do_abstain` |
| Required abstentions are recorded by id | `required_abstentions_are_recorded` |
| Configuration text alone cannot name a method | `a_tree_of_only_text_cannot_reach_a_method_label` |
| E1-only evidence cannot name a method | `e1_only_evidence_cannot_name_a_method` |
| A high score without a method anchor is `partially_supported`, not a label | `a_high_score_without_a_method_anchor_is_partially_supported_not_a_label` |
| Close rivals force abstention | `close_rivals_force_abstention` |
| One source cannot corroborate itself | `single_source_cannot_reach_corroborated` |
| Two independent sources can | `two_independent_sources_can_reach_corroborated` |
| No corpus case reaches `corroborated` on a self-scan | `the_corpus_never_reaches_corroborated_on_a_stage_one_self_scan` |
| Duplicate observations do not stack | `duplicate_observations_do_not_stack` |
| The lowest cap binds | `lowest_cap_wins` |

**And caps must not bind the claims they were never meant to:**

| Promise | Test |
|---|---|
| An API/RAG system is not capped for having no weights | `an_api_and_rag_system_is_not_capped_for_having_no_weights` |
| Weight-training claims ARE still capped by API-only evidence | `weight_training_claims_are_still_capped_by_api_only_evidence` |

---

## 3. Tamper evidence

| Promise | Test |
|---|---|
| An untouched bundle verifies on every axis | `an_untouched_bundle_verifies_on_every_axis` |
| **An edited verdict is caught even when every hash is recomputed** | `editing_a_score_is_caught_even_when_every_hash_is_recomputed` |
| One flipped byte breaks integrity | `flipping_one_byte_of_the_report_breaks_integrity` |
| A removed payload reports `incomplete`, not `intact` | `a_removed_payload_reports_incomplete_not_intact` |
| A reformatted report is detected as modified | `a_reformatted_report_is_detected_as_modified` |
| Facts round-trip through the report identically | `facts_round_trip_through_the_report` |
| A marker copied from another report is caught | `a_marker_copied_from_another_report_is_caught` |
| A PDF rebuilt without the marker is caught | `a_pdf_rebuilt_without_the_marker_is_caught` |
| A tampered challenge fails its signature | `signed_challenge_binds_and_tampering_breaks_it` |
| Soundness and challenge binding are separate | `an_unbound_but_unaltered_bundle_is_sound` |

---

## 4. Safety — that hostile input cannot hurt the host

| Promise | Test |
|---|---|
| Pickle and friends are never opened | `a_pickle_file_is_not_opened_even_with_valid_looking_content`, `an_opaque_checkpoint_is_counted_but_never_opened` |
| The ONNX graph is skipped, not walked | `the_graph_is_stepped_over_and_never_walked` |
| No `unsafe` anywhere; every crate forbids it | `no_unsafe_code_anywhere`, `every_library_crate_forbids_unsafe` |
| No socket is opened | `nothing_opens_a_network_socket` |
| No process is spawned | `nothing_spawns_a_process` |
| No dependency outside the allow-list | `no_dependency_outside_the_allow_list` |
| Truncation at every boundary never panics | `truncation_at_every_boundary_never_panics`, `truncation_at_every_scale_never_panics` |
| Declared lengths beyond the buffer are refused before allocating | `a_length_field_larger_than_the_buffer_is_refused_before_allocating` |
| Depth, width and string limits bind | `depth_limit_stops_recursion`, `width_limits`, `bounds_are_enforced` |
| Zip-slip, duplicates, deflate, CRC and header disagreement are all refused | `tt-bundle/zip` rejection suite |
| Malformed input yields a coverage note, never silence | `hostile_files_produce_coverage_notes_rather_than_silence` |
| Reparse points are not traversed | `tt-inventory` traversal suite |

---

## 5. Privacy

| Promise | Test |
|---|---|
| Nothing from the privacy bait reaches the report | `nothing_from_the_privacy_bait_reaches_the_report` |
| An API key in a config does not reach the report | `a_secret_in_a_config_does_not_reach_the_report` |
| A credential value never leaves the deployment parser | `an_api_key_never_leaves_this_module` |
| A URL loses its query string and userinfo | `a_url_is_stripped_of_credentials_and_query` |
| No secret survives a mixed document | `no_secret_survives_a_mixed_document` |
| Scrubbing is idempotent | `scrubbing_is_idempotent` |
| Paths outside scope become a placeholder, not a partial path | `windows_path_outside_scope_becomes_placeholder` |
| A short user name does not blank ordinary words | `two_character_usernames_are_ignored` |

---

## 6. Determinism and reproducibility

| Promise | Test |
|---|---|
| Two scans of an unchanged tree agree | `scanning_twice_gives_the_same_evidence_digest`, `the_whole_corpus_is_reproducible` |
| The evidence digest ignores the clock | `evidence_digest_ignores_the_clock` |
| ...but moves when a conclusion moves | `evidence_digest_moves_when_a_conclusion_moves` |
| Canonical JSON is construction-order independent | `digest_is_stable_across_construction_order` |
| The bundle is byte-reproducible | `tt-bundle` determinism suite |
| The PDF is byte-identical across builds | `two_builds_are_byte_identical` |
| Judging is order-independent | `judging_is_order_independent` |
| Fixtures generate identically twice | `generating_twice_produces_identical_bytes` |

---

## 7. Language and contract

| Promise | Test |
|---|---|
| No authored text uses forbidden language | `no_authored_vocabulary_uses_forbidden_language`, `no_rule_text_uses_forbidden_language`, `rendered_text_uses_no_forbidden_language` |
| Quoting a vendor is not the tool adopting their words | `quoting_the_vendor_is_not_the_tool_adopting_their_words` |
| An editorialising rule fails the build | `prohibited_language_in_authored_text_fails_the_build` |
| Every vocabulary string is in the frozen document | `every_vocabulary_string_appears_in_the_frozen_document` |
| Every documented cap and abstention exists in code | `every_cap_in_the_document_exists_in_code` |
| Every emitted rule id is in the catalogue | `every_emitted_rule_id_is_in_the_catalogue` |
| The required statement appears verbatim | `the_required_statement_is_present_verbatim` |
| Assurance level is always `vendor_self_scan` | `assurance_level_is_always_vendor_self_scan` |
| Facts cannot express a verdict | `facts_carry_no_verdict_vocabulary` |

---

## 8. Definition of done — plan §27, honestly scored

| Criterion | State |
|---|---|
| Portable scanner and verifier, no install or admin | **Met** — 0.79 MB and 0.54 MB single binaries |
| Default mode opens no network connection | **Met**, enforced by test |
| Selected artifacts never executed or unsafely deserialised | **Met**, enforced by test |
| All parsers enforce resource and traversal limits | **Met** |
| Every conclusion cites evidence and a versioned rule | **Met** |
| Required anchors, caps and abstention work on the fixture matrix | **Met** — 15 cases |
| Missing evidence never becomes an accusation | **Met**, enforced by test |
| Outbound preview and redaction ledger complete | **Met** — `preflight` plus the published ledger |
| `.ttscan` verifies deterministically | **Met** |
| Markers survive ordinary transport | **Partially** — round-trip through the PDF is tested; survival through real e-mail systems is not |
| All deliberate report edits fail integrity checks | **Met**, including the recompute-every-hash case |
| Report labels vendor-host and production-binding limitations | **Met** — `TT-BIND-005` is unconditional |
| Code-signed releases and published hashes | **Not started** |
| Blind pilot metrics recorded | **Not started** — no detection rate is claimed anywhere |

---

## Open gaps — promises not yet enforced by a test

Listed so they cannot be mistaken for covered.

1. **No fuzzing.** Parsers are tested against hand-built adversarial inputs, not a
   fuzzer. Plan §22 Phase 4 asks for fuzzing; it has not been run.
2. **No clean-VM test.** Everything has run on one development machine. SmartScreen,
   antivirus behaviour and a genuinely fresh Windows install are untested.
3. **No calibration.** Score thresholds are the plan's starting values. No labelled
   corpus exists, so precision, recall, abstention rate and false-contradiction rate
   are unmeasured — and no percentage is claimed anywhere in the product.
4. **Marker transport is untested through real e-mail.** Only the in-process
   round-trip is covered.
5. **`supervised_instruction_tuning` has no scored claim**, so a pure SFT declaration
   abstains on training stage.
6. **No GUI**, so plan §22 Phase 3's "a nontechnical vendor completes the workflow
   from a one-page guide" is unevaluated.
