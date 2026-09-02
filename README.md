# TrainTrace

**Trace the evidence behind "we trained our own AI."**

TrainTrace checks whether the artifacts a vendor supplies are consistent with the way
they say their AI system was built. It is a *consistency screen*. It is not a lie
detector, not a certification, and not proof of production origin.

Its most common correct answer is "not enough evidence here", and it is built to say
that comfortably.

---

## Status

Stage-1 MVP, CLI-first, working end to end.

| | |
|---|---|
| Tests | **641**, all passing |
| Compiler warnings | **0** |
| Release binaries | `tt-screen` 0.79 MB, `tt-verify` 0.54 MB, `tt-fixtures` 0.35 MB |
| Third-party dependencies | **4** — `sha2`, `ed25519-dalek`, `getrandom`, `clap` |
| Golden fixture cases | 15, of which 5 require abstention |

The plan targeted a 10–30 MB scanner. It came in at **0.79 MB**, because nothing
third-party parses vendor bytes: every JSON, YAML, TOML, SafeTensors, GGUF, ONNX, ZIP
and PDF reader here is in-repo and bounded.

---

## Try it

```bash
cargo build --release
```

Generate a fixture, scan it, verify the result:

```bash
./target/release/tt-fixtures generate --out /tmp/fx --case obvious_unmerged_lora
```

```bash
./target/release/tt-screen scan --root /tmp/fx/obvious_unmerged_lora --out /tmp/out --case-id TT-2026-0F3A9C --vendor "Acme Ltd" --claim "We fine-tuned Qwen2.5 with a LoRA adapter." --parameter-update unmerged_peft_observed
```

```bash
./target/release/tt-verify check /tmp/out/*.ttscan
```

See what a scan would touch, before it touches anything:

```bash
./target/release/tt-screen preflight --root /tmp/fx/obvious_unmerged_lora
```

---

## The product family

| Name | Role |
|---|---|
| **TrainTrace Screen** (`tt-screen`) | Vendor-side portable scanner |
| **TrainTrace Verify** (`tt-verify`) | Buyer-side bundle verifier |
| **TrainTrace Fixtures** (`tt-fixtures`) | The golden corpus |
| **`.ttscan`** | The single emailed evidence bundle |
| *TrainTrace Forensics* | Stage 2, out of scope for this repo |

---

## What makes it worth running

**The verifier holds the ruleset.** Hashes only show that a file has not changed since
*somebody* computed them — and that somebody ran an offline scanner on their own
machine. So `tt-verify` parses the observations back out of `report.json`, re-runs the
rules over them, and compares against the conclusions the report states.

That catches the edit an attacker actually wants: leave the evidence alone, raise the
verdict, rebuild every hash. Demonstrated against a real bundle:

```
  integrity   intact                                    <- every hash agrees
  recomputed  DIVERGES from the report's own observations

  - parameter_update: report states `corroborated_within_supplied_evidence` at 960
    tenths; re-evaluating the report's own observations gives `weakly_consistent`
    at 620 tenths
```

**Four brakes stand between evidence and a named method.** A rubric ceiling, hard caps,
mandatory abstention, and an emission gate. Any one of them alone will stop a label.
Stage 1 *mathematically cannot* name a merged adapter — two of that rubric's anchors
need tensor analysis it does not do — and that is asserted by a test rather than left
to discipline.

**Missing evidence never subtracts.** Absent evidence caps a score; it never pushes one
down. A screen that punishes silence turns "we did not send you that file" into an
accusation.

**Five statuses, never merged.** A bundle can be byte-perfect and evidentially
worthless at once, so integrity, challenge binding, marker status, coverage and
evidence strength are reported separately and never collapsed into a verdict.

---

## What it will never say

Lie detection · certification · reconstruction of training history from final weights ·
proof that the scanned folder is the production deployment · proof that no merged
adapter was used · reliable CPT-versus-SFT classification from final weights · proof of
random initialisation merely because no known base matched.

A **contradiction** here means an exact claim conflicting with an observed artifact. It
is never a finding about intent. A test over the whole rendered vocabulary enforces the
wording.

---

## Hard guarantees

- No installation, no administrator rights, no Python, no GPU, no service.
- **No network socket is opened.** Enforced by a test that greps for `std::net`.
- Supplied artifacts are **never executed or deserialised**. Pickle, `.pt`, `.pth`,
  `.bin`, joblib and NumPy object arrays are hashed, counted, and never opened — they
  have no branch in the parser dispatch table at all.
- Reparse points are never traversed, so traversal loops are structurally impossible.
- Credentials, absolute paths and user names are removed before anything enters the
  report, and every removal is counted in a ledger the vendor cannot delete.
- Every conclusion cites versioned rule IDs and artifact hashes. Every contradiction
  cites a digest — enforced by test.

---

## Repository layout

    crates/
      tt-core/        canonical JSON (no float variant), bounded parsers, hashing, redaction
      tt-facts/       normalised evidence model - cannot express a score or a verdict
      tt-inventory/   safe traversal, file identity, streaming SHA-256
      tt-formats/     SafeTensors, GGUF, ONNX, PEFT, YAML, TOML, logs, deps, deploy, RAG
      tt-rules/       rule families, scoring, caps, abstention, emission gate
      tt-markers/     numerical canary + imperceptible tint marker
      tt-report/      report.json assembly, deterministic PDF writer and reader
      tt-bundle/      .ttscan container - STORED entries only
      tt-case/        challenge issuance and Ed25519 binding
      tt-screen/      vendor CLI            tt-verify/  buyer CLI
      tt-fixtures/    golden corpus         tt-contracts/  workspace-wide invariants
    docs/             frozen Phase-0 contracts

`docs/00-FROZEN-VOCABULARY.md` is the contract a buyer reads. A test fails the build if
the code drifts from it.

---

## Known gaps

- **Thresholds are uncalibrated.** The score is a rubric-based support score, not
  calibrated confidence, and the report says so. No blinded benchmark has been run, so
  no detection rate is claimed.
- **Marker verification is not wired end to end.** The tint marker is built, embedded
  in the PDF and recovered correctly (tested), but `tt-verify` reports
  `marker_status = not_applicable` rather than correlating it. The plumbing exists;
  the last connection does not.
- **`supervised_instruction_tuning` has no scored claim**, so a pure SFT declaration
  abstains on training stage. The plan's rubric table has no SFT row either.
- **No GUI.** Six-screen vendor app is Phase 3 of the plan and not started.
- **No Authenticode signing or reproducible-build process** yet.
