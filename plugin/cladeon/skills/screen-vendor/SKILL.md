---
name: screen-vendor
description: Screen an AI vendor's supplied artifacts (model folders, adapters, configs, deployment files) with Cladeon to see whether they are consistent with how the vendor says the system was built, or verify a .clade bundle a vendor sent back. Use when the user is doing AI procurement or due diligence, asks "did they really train their own model", mentions a LoRA/fine-tune/wrapper claim, or has a .clade file.
---

# Screen a vendor's AI claim with Cladeon

Cladeon is a local, offline consistency screen. It reads folders, never executes or
deserialises what it finds, opens no network connection, and writes one `.clade`
evidence bundle. Your job is to run it and relay what it says **without making it
say more**.

## 1. Make sure you are on the user's own computer

Cladeon must run where the vendor's files already are. If you are in claude.ai chat, a
cloud sandbox, or anywhere else that is not the user's own machine, do not run it there
and **never ask the user to upload the vendor's files**: that would move confidential
material off their machine, which is exactly what Cladeon exists to avoid. Instead,
explain that Cladeon runs locally, and suggest Claude Code or a Cowork session on
their computer, or the Cladeon desktop apps.

## 2. Check the tools are installed

Run `cladeon-screen-cli --help` and `cladeon-verify --help`. If either is missing, stop
and tell the user to download the Cladeon command-line tools from the Releases page
linked in this plugin's README and put them on their PATH. The release builds are for
Windows; on macOS or Linux they can build from source with `cargo build --release`.
Do not try to build or download them yourself.

## 3. Screening a folder

1. **Get the claim, verbatim.** Ask for the vendor's exact words, such as "We trained
   our own 7B model from scratch". Never paraphrase it: it is quoted into the report.
2. **Preflight first, always.** Run
   `cladeon-screen-cli preflight --root <folder>` (repeat `--root` for each folder) and
   show the user what will be read before scanning anything.
3. **Declared method flags are optional.** Pass `--weight-origin`,
   `--parameter-update`, `--training-stage` or `--augmentation` only when the claim
   states that facet plainly. If you are unsure, leave the flag out rather than guess.
   The allowed values are fixed:
   - `--weight-origin`: `random_initialization_claimed`, `derivative_of_disclosed_base`, `distilled_from_teacher`, `unknown`
   - `--parameter-update`: `no_update_observed`, `unmerged_peft_observed`, `merged_adapter_consistent`, `partial_or_dense_update`, `unknown`
   - `--training-stage`: `continued_pretraining`, `supervised_instruction_tuning`, `preference_tuning`, `distillation`, `other_or_unknown`
   - `--augmentation` (repeatable): `rag`, `external_api_router`, `tools_prompt_orchestration`, `local_direct_inference`, `none_observed_or_unknown`

   Never run a scan just to look up values or test the tool.
4. **Scan:**
   `cladeon-screen-cli scan --root <folder> --out <dir> --case-id <id> --vendor "<name>" --claim "<exact claim>"`.
   If the buyer issued a `challenge.json`, pass `--challenge` and `--challenge-sig`
   instead of `--case-id`.
5. **Verify the bundle you just wrote:** `cladeon-verify check <file>.clade`.

## 4. Verifying a bundle someone sent

Run `cladeon-verify check <file>.clade`, adding `--case-id <id>` when the user knows
which case it should answer. The exit code matters:

| Exit | Meaning |
|---|---|
| 0 | Sound, and bound to the buyer's challenge |
| 1 | **Not sound.** The bundle was altered, or its verdict does not follow from its own observations. Say so first. |
| 2 | Could not read the file, or an argument was malformed |
| 3 | Sound, but not bound to any challenge, so it answers no recorded question. This is not tampering. |

Any exit other than 0 makes your shell tool report the command as failed. For 1 and 3
that is expected: the report is already in the output, so read it. **Do not re-run the
command** or try another shell to get a "clean" exit.

## 5. How to report the result

- Report the five statuses and every per-facet result **separately, in Cladeon's own
  words**. Never merge them into one verdict. A bundle can be perfectly intact and
  evidentially worthless at once. What each status means, and nothing more:
  - **integrity**: the bundle's files are unchanged since it was written
  - **challenge**: whether it answers a question the buyer issued in advance
  - **markers**: the rendering was not rebuilt. Not evidence about the contents, never a root of trust
  - **coverage**: how much of the selected folders the scanner could actually read
  - **evidence**: the overall strength of evidence for the claim
- Draw conclusions only from Cladeon's output. A folder or file name is not evidence,
  even when it looks like it names the answer. Do not add your own reading of what the
  vendor "really" built, such as "consistent with an API wrapper", unless Cladeon itself
  reports it.
- **"Insufficient evidence / abstained" is the most common correct answer.** It means
  the supplied files cannot settle the question. It is not a sign the vendor is lying,
  and it is not a pass.
- Never strengthen a label. "Weakly consistent" is not "confirmed"; "consistent" is not
  "proven".
- A contradiction means an exact claim conflicts with an observed artifact. It is never
  a finding about intent. Do not call the vendor dishonest.
- Cladeon has **no measured detection rate**: its thresholds are uncalibrated and no
  blinded benchmark has run. If asked how accurate it is, say exactly that.
- Suggest only next steps that exist today: ask the vendor for the specific artifacts
  that were missing, or have the buyer issue a challenge by starting a new check in the
  Cladeon desktop app, so the next bundle is bound to their question. There is no
  "Stage 2" review, forensic service or certification to offer.
- Always pass on Cladeon's own caveat: it evaluates consistency within the supplied
  evidence and cannot prove what runs in production or reconstruct training history.

## Never

- Open, load, unpickle or execute the vendor's model files with any other tool.
- Edit, re-zip or re-export a `.clade` bundle. `report.json` inside it is
  authoritative, and any change breaks verification.
- Present a screenshot or summary as the report.
