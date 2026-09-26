---
name: screen-vendor
description: Screen an AI vendor's supplied artifacts (model folders, adapters, configs, deployment files) with Cladeon to see whether they are consistent with how the vendor says the system was built, or verify a .clade bundle a vendor sent back. Use when the user is doing AI procurement or due diligence, asks "did they really train their own model", mentions a LoRA/fine-tune/wrapper claim, or has a .clade file.
---

# Screen a vendor's AI claim with Cladeon

Cladeon is a local, offline consistency screen. It reads folders, never executes or
deserialises what it finds, opens no network connection, and writes one `.clade`
evidence bundle. Your job is to run it and relay what it says **without making it
say more**.

## 1. Check the tools are installed

Run `cladeon-screen-cli --help` and `cladeon-verify --help`. If either is missing, stop
and tell the user to download the Cladeon command-line tools from the Releases page
linked in this plugin's README and put them on their PATH. Do not try to build or
download them yourself.

## 2. Screening a folder

1. **Get the claim, verbatim.** Ask for the vendor's exact words, such as "We trained
   our own 7B model from scratch". Never paraphrase it: it is quoted into the report.
2. **Preflight first, always.** Run
   `cladeon-screen-cli preflight --root <folder>` (repeat `--root` for each folder) and
   show the user what will be read before scanning anything.
3. **Declared method flags are optional.** Pass `--weight-origin`,
   `--parameter-update`, `--training-stage` or `--augmentation` only when the claim
   states that facet plainly. If you are unsure, leave the flag out rather than guess.
   To see the allowed values, pass `?` as the value: the error message lists them.
4. **Scan:**
   `cladeon-screen-cli scan --root <folder> --out <dir> --case-id <id> --vendor "<name>" --claim "<exact claim>"`.
   If the buyer issued a `challenge.json`, pass `--challenge` and `--challenge-sig`
   instead of `--case-id`.
5. **Verify the bundle you just wrote:** `cladeon-verify check <file>.clade`.

## 3. Verifying a bundle someone sent

Run `cladeon-verify check <file>.clade`, adding `--case-id <id>` when the user knows
which case it should answer. The exit code matters:

| Exit | Meaning |
|---|---|
| 0 | Sound, and bound to the buyer's challenge |
| 1 | **Not sound.** The bundle was altered, or its verdict does not follow from its own observations. Say so first. |
| 2 | Could not read the file, or an argument was malformed |
| 3 | Sound, but not bound to any challenge, so it answers no recorded question. This is not tampering. |

## 4. How to report the result

- Report the five statuses (integrity, challenge, markers, coverage, evidence) and
  every per-facet result **separately, in Cladeon's own words**. Never merge them into
  one verdict. A bundle can be perfectly intact and evidentially worthless at once.
- **"Insufficient evidence / abstained" is the most common correct answer.** It means
  the supplied files cannot settle the question. It is not a sign the vendor is lying,
  and it is not a pass.
- Never strengthen a label. "Weakly consistent" is not "confirmed"; "consistent" is not
  "proven".
- A contradiction means an exact claim conflicts with an observed artifact. It is never
  a finding about intent. Do not call the vendor dishonest.
- Cladeon has **no measured detection rate**: its thresholds are uncalibrated and no
  blinded benchmark has run. If asked how accurate it is, say exactly that.
- Always pass on Cladeon's own caveat: it evaluates consistency within the supplied
  evidence and cannot prove what runs in production or reconstruct training history.

## Never

- Open, load, unpickle or execute the vendor's model files with any other tool.
- Edit, re-zip or re-export a `.clade` bundle. `report.json` inside it is
  authoritative, and any change breaks verification.
- Present a screenshot or summary as the report.
