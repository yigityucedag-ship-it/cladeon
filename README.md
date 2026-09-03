# Cladeon

**Which branch is your model actually on?**

Cladeon traces the evidence behind "we trained our own AI." The name is from
*clade* — a group descended from one common ancestor. The question it answers is
whether a model is its own root, or a branch off somebody else's base.

Cladeon checks whether the artifacts a vendor supplies are consistent with the way
they say their AI system was built. It is a *consistency screen*. It is not a lie
detector, not a certification, and not proof of production origin.

Its most common correct answer is "not enough evidence here", and it is built to say
that comfortably.

---

## Status

Stage-1 MVP, CLI-first, working end to end.

| | |
|---|---|
| Tests | **648**, all passing |
| Compiler warnings | **0** |
| Release binaries | `cladeon-screen` 0.79 MB, `cladeon-verify` 0.54 MB, `cladeon-fixtures` 0.35 MB |
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
./target/release/cladeon-fixtures generate --out /tmp/fx --case obvious_unmerged_lora
```

```bash
./target/release/cladeon-screen scan --root /tmp/fx/obvious_unmerged_lora --out /tmp/out --case-id CL-2026-0F3A9C --vendor "Acme Ltd" --claim "We fine-tuned Qwen2.5 with a LoRA adapter." --parameter-update unmerged_peft_observed
```

```bash
./target/release/cladeon-verify check /tmp/out/*.clade
```

See what a scan would touch, before it touches anything:

```bash
./target/release/cladeon-screen preflight --root /tmp/fx/obvious_unmerged_lora
```

---

## The product family

| Name | Role |
|---|---|
| **Cladeon Screen** (`cladeon-screen`) | Vendor-side portable scanner |
| **Cladeon Verify** (`cladeon-verify`) | Buyer-side bundle verifier |
| **Cladeon Fixtures** (`cladeon-fixtures`) | The golden corpus |
| **`.clade`** | The single emailed evidence bundle |
| *Cladeon Forensics* | Stage 2, out of scope for this repo |

---

## What makes it worth running

**The verifier holds the ruleset.** Hashes only show that a file has not changed since
*somebody* computed them — and that somebody ran an offline scanner on their own
machine. So `cladeon-verify` parses the observations back out of `report.json`, re-runs the
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
      cl-core/        canonical JSON (no float variant), bounded parsers, hashing, redaction
      cl-facts/       normalised evidence model - cannot express a score or a verdict
      cl-inventory/   safe traversal, file identity, streaming SHA-256
      cl-formats/     SafeTensors, GGUF, ONNX, PEFT, YAML, TOML, logs, deps, deploy, RAG
      cl-rules/       rule families, scoring, caps, abstention, emission gate
      cl-markers/     numerical canary + imperceptible tint marker
      cl-report/      report.json assembly, deterministic PDF writer and reader
      cl-bundle/      .clade container - STORED entries only
      cl-case/        challenge issuance and Ed25519 binding
      cl-screen/      vendor CLI            cl-verify/  buyer CLI
                      (binaries: cladeon-screen, cladeon-verify, cladeon-fixtures)
      cl-fixtures/    golden corpus         cl-contracts/  workspace-wide invariants
    docs/             frozen Phase-0 contracts

`docs/00-FROZEN-VOCABULARY.md` is the contract a buyer reads, `03-THREAT-MODEL.md` says
what the design does and does not defend against, and `04-ACCEPTANCE-TESTS.md` maps
every promise to the test that enforces it. Tests fail the build if the code drifts
from any of them - including one that checks every test the acceptance document names
actually exists.

---

## Known gaps

- **Thresholds are uncalibrated.** The score is a rubric-based support score, not
  calibrated confidence, and the report says so. No blinded benchmark has been run, so
  no detection rate is claimed.
- **`supervised_instruction_tuning` has no scored claim**, so a pure SFT declaration
  abstains on training stage. The plan's rubric table has no SFT row either.
- **No GUI.** Six-screen vendor app is Phase 3 of the plan and not started.
- **No Authenticode signing or reproducible-build process** yet.

---

## Licence

**[Functional Source License 1.1](LICENSE.md), Apache 2.0 future licence.**
Copyright 2026 Yigit Yucedag.

In plain terms:

- **Use it freely.** Internally, at work, on your own vendors, for research or
  teaching, and in consulting you do for someone else. That is all a Permitted
  Purpose and costs nothing.
- **Fork it, change it, redistribute it.** Also fine, as long as the licence travels
  with it.
- **You may not sell it.** Putting Cladeon — or something built from its code that
  does substantially the same job — behind a paywall, a subscription or a hosted
  service is a *Competing Use* and is not licensed. Ask me first.
- **It becomes Apache-2.0 anyway.** Two years after each release, that version is
  automatically relicensed under Apache 2.0. Nothing here can become abandonware, and
  you are never locked out long-term.

FSL is *source available*, not OSI-approved open source, and calling it "open source"
would be inaccurate. It exists to keep the software free for the people who actually
need it while stopping free-riding.

Rebuilding the same idea from scratch is not a licence question — the design is
described openly in `docs/`, and you are welcome to it. What is licensed here is this
implementation.
