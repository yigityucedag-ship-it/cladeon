# TrainTrace

**Trace the evidence behind "we trained our own AI."**

TrainTrace checks whether the artifacts a vendor supplies are consistent with the way
they say their AI system was built. It is a *consistency screen*, not a lie detector,
not a certification, and not a proof of production origin.

## Product family

| Name | Role |
|---|---|
| **TrainTrace Screen** (`tt-screen`) | Vendor-side portable scanner |
| **TrainTrace Verify** (`tt-verify`) | Buyer-side bundle verifier |
| **TrainTrace Case** (`tt-case`) | Buyer-side one-time challenge issuer |
| **`.ttscan`** | The single emailed evidence bundle |
| *TrainTrace Forensics* | Stage-2, out of scope for this repo |

## Hard guarantees of Stage 1

- No installation, no administrator rights, no Python, no GPU, no service.
- **No network sockets are opened in the default mode.**
- Supplied artifacts are **never executed** and **never unsafely deserialized**
  (no pickle, no `torch.load`, no joblib, no NumPy object arrays).
- Only explicitly selected folders are read, read-only.
- Reparse points (symlinks / junctions / mount points) are **not traversed** by default.
- Every conclusion cites versioned rule IDs and artifact hashes.
- Missing evidence is never converted into an accusation.

## What it must never claim

Lie detection - certification - reconstruction of training history from final weights -
proof that the scanned folder is the production deployment - proof that no merged adapter
was used - reliable CPT-versus-SFT classification from final weights - proof of random
initialisation merely because no known base matched.

## Repository layout

    crates/
      tt-core/          data types, canonicalisation (RFC 8785), hashing, redaction
      tt-facts/         normalised evidence model (no verdict language)
      tt-inventory/     safe Windows traversal, file identity, streaming SHA-256
      tt-formats/       SafeTensors, PEFT, Transformers, GGUF, ONNX, log parsers
      tt-rules/         deterministic rules, rubrics, caps, mandatory abstention
      tt-report/        report.json + PDF rendering
      tt-markers/       numerical canary + imperceptible tint marker
      tt-bundle/        .ttscan writer / hostile-input reader
      tt-case/          challenge issuance and Ed25519 verification
      tt-screen/        vendor CLI (Stage-1 scanner)
      tt-verify/        buyer CLI (verifier)
      tt-fixtures/      development-only fixture generator
    docs/               frozen Phase-0 contracts
    fixtures/           checked-in golden fixture descriptors

## Status

Stage-1 MVP, CLI-first. See `docs/` for the frozen vocabulary, rule catalogue,
schemas, threat model and acceptance tests. Built against
`TRAINTRACE_BUILD_PLAN.md` (2026-09-02).
