# Cladeon — Threat Model

`threat_model_version = 1`

## The situation

A buyer asks a vendor how their AI system was built. The vendor runs Cladeon on
their own machine, on folders they choose, and emails back a `.clade`.

Every part of that sentence is a problem, and the design is mostly a response to it:

- The scanner runs on **the vendor's hardware**, under their control.
- It reads **only what they point it at**.
- It is an **offline binary they hold**, so they can disassemble it.
- Nobody watches it run.

A tool in that position cannot establish truth. It can establish **consistency within
what it was shown**, and it can make certain kinds of after-the-fact editing
detectable. Anything stronger requires a witnessed run, which is Stage 2.

---

## Adversaries

### A1 — The optimistic vendor

Not hostile. Believes their own summary, supplies what they have, and would be
embarrassed to be wrong. **This is the common case, and the one the design protects
hardest.** The failure that matters is a false contradiction: a screen that reports a
conflict against an honest vendor is worse than one that says nothing.

*Mitigations:* missing evidence never subtracts, only caps. Contradictions require an
exact claim conflicting with an observed artifact, and must cite a digest.
Filesystem-timestamp coincidences and tidy logs are ambiguities, never contradictions.
Five corpus cases assert that no contradiction is raised.

### A2 — The vendor who overstates

Says "we trained our own model" about a fine-tune, or about an API wrapper. Not
forging anything — just describing generously.

*Mitigations:* this is what the product is for. Facets are scored independently, so an
API wrapper's retrieval evidence scores while its weight facets report
`artifact_not_supplied_or_out_of_scope`. Caps stop configuration text from reaching a
method label.

### A3 — The vendor who curates the scan

Points the scanner at a folder that flatters them, or excludes what does not.

*Mitigations:* **not solvable at Stage 1, and the report says so.** `CL-BIND-005` is
printed unconditionally: the scanned folder is not established to be the production
deployment. Exclusions are recorded in the manifest with
`skipped_by_submitter`; the vendor may withhold a source, but not the fact that they
did. Coverage status is reported separately from evidence.

### A4 — The vendor who edits the report

Receives a result they dislike and improves it before forwarding.

*Mitigations:* this is the one the design fights hardest.

| Attack | Detection |
|---|---|
| Edit the PDF | `report.json` is authoritative; the PDF is a rendering, and `VERIFY.txt` says so |
| Edit `report.json` | Envelope digests disagree → `integrity: modified` |
| Reformat `report.json` | Non-canonical form is rejected → `integrity: modified` |
| Edit and recompute every hash | **`recomputation: diverges`** — the verifier holds the ruleset and re-derives the conclusions from the report's own observations |
| Copy a marker from another report | Correlates with its own tag, not the declared one → `marker: present_inconsistent` |
| Re-export the PDF | Marker raster lost → `marker: present_inconsistent` |
| Replay an old bundle | Challenge nonce and expiry → `challenge: expired` |
| Answer a different question | Case id mismatch → `challenge: case_mismatch` |

The recomputation check is the load-bearing one. Everything above it can be defeated
by a vendor who recomputes hashes; recomputation cannot, because the vendor's edited
numbers have to survive a ruleset they do not hold.

### A5 — The vendor who reverse-engineers the scanner

Extracts the marker scheme and the canary derivation from the binary.

*Mitigations:* **partial, and stated as such.** The markers are tripwires for casual
editing, not a root of trust; `docs/02-SCHEMAS.md` and the verifier's own output say
so in those words. The only defence that survives A5 is a key the vendor never holds:
the buyer's signed challenge, or the optional Stage-1.5 server seal. Security must not
depend on the secrecy of anything shipped in the binary.

### A6 — The hostile file

A crafted artifact aimed at the scanner itself, or a crafted `.clade` aimed at the
verifier. This adversary does not care about the report; they want code execution or a
crash on the *buyer's* machine.

*Mitigations:* see below — this is the largest single block of engineering in the
repository.

---

## The hostile-input surface

Everything the scanner reads was chosen by the party under scrutiny.

**No third-party crate parses vendor bytes.** JSON, YAML, TOML, SafeTensors, GGUF,
ONNX, ZIP and PDF readers are all in-repo and bounded. The workspace has four external
dependencies — `sha2`, `ed25519-dalek`, `getrandom`, `clap` — and a test fails the
build if a fifth appears.

| Surface | Defence |
|---|---|
| Code-executing formats (pickle, `.pt`, `.pth`, `.bin`, joblib, `.npy`) | Hashed and counted; **no branch in the dispatch table at all** |
| ONNX graph (field 7) | Stepped over by length, never descended into |
| Declared lengths | Checked against bytes present *before* any allocation |
| Nesting | Depth-capped in every parser; recursion bounded before descent |
| Traversal loops | Reparse points are never followed, so loops are unrepresentable |
| Long paths, access denied, files changing mid-scan | Recorded as coverage, never fatal |
| Decompression bombs in `.clade` | **Structurally impossible**: only STORED entries are accepted |
| Zip-slip, duplicate names, drive letters | Entry names come from a closed set of eight |
| Central-directory / local-header disagreement | Rejected — that mismatch is how one tool is made to see a different file from another |
| Integer overflow | `checked_`/`saturating_` throughout; one real overflow was found and fixed by its own test |
| Memory safety | `#![forbid(unsafe_code)]` in every crate, enforced by test |

---

## The privacy surface

The scanner sees model weights, datasets, source code, prompts and credentials. Almost
none of that may leave the machine.

- Absolute paths are replaced by scoped aliases (`ROOT1/...`) before they can reach a
  fact. A path outside every selected root becomes `[OUT-OF-SCOPE-PATH]`, never a
  partial real path.
- Credential values are removed **in the parser**, not downstream. A `.env` yields the
  *names* of variables that were set; knowing `OPENAI_API_KEY` is configured is the
  evidence, and the key itself is only a leak. A defence that works only when a second
  component remembers to run is not a defence.
- URLs are stripped of userinfo and query strings.
- Redaction is **allow-list on key names and shape-matching on values**: a field whose
  key looks like a credential is redacted wholesale regardless of what its value looks
  like, because an unrecognised token shape is exactly where shape matching fails.
- Every redaction is counted in a ledger published in the report. The vendor may hide a
  value; the fact that something was hidden is not removable.
- `preflight` shows the vendor what would leave the machine **before anything does**.

The `privacy_bait` corpus case plants an API key, a Hugging Face token, an AWS key, an
absolute Windows user path, an e-mail address and a private-key block, then asserts
that none of them — nor the account name — appears in `report.json` or the manifest.

---

## What is explicitly out of scope

- An administrator presenting a decoy environment.
- Establishing that the scanned folder is the production deployment.
- Proving a merged adapter, or distinguishing CPT from SFT, from final weights.
- Any claim about intent.
- Defeating a vendor who fabricates internally consistent evidence across every
  artifact. Stage 1 checks consistency; consistent fiction passes a consistency check,
  and that is what Stage 2 and witnessed runs are for.

---

## The honest summary

Cladeon raises the cost of overstating a training claim from "say a sentence" to
"fabricate a coherent artifact set, and either avoid the verifier's recomputation or
reverse-engineer the scanner". That is a real increase and a useful one.

It is not proof, and no part of the output says it is.
