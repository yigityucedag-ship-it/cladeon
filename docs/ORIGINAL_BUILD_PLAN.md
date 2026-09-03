> **Historical document.** This is the original build plan, kept verbatim.
> It uses *TrainTrace*, the working name during planning; the product shipped
> as **Cladeon**. Section 3 discusses the name choice, so renaming it here would
> make that discussion nonsense. Everything else in `docs/` uses the final name.

# TrainTrace: detailed build plan

Status: planning specification only  
Date: 2026-09-02

Working product family:

- **TrainTrace Screen** — small Stage-1 vendor self-scan
- **TrainTrace Verify** — buyer-side verifier
- **TrainTrace Forensics** — optional Stage-2 deep analysis
- **.ttscan** — emailed evidence bundle

## 1. Executive decision

Build the first release as a small, portable Windows program that a vendor can run without installation or administrator access. It scans only folders the vendor explicitly selects, executes no supplied code, sends nothing over the network by default, and produces one .ttscan bundle that the vendor emails back.

Stage 1 is a consistency screen. Its purpose is to identify obvious adapters, wrappers, RAG systems, incoherent training stories, and unsupported “trained from scratch” claims. It must not call a vendor dishonest merely because evidence is missing.

The scanner should be deterministic and contain no LLM. A fact extractor plus versioned rules is smaller, safer, reproducible, and easier to defend.

The offline MVP can make casual report editing conspicuous through canonical data, bundle hashes, a hidden numerical check digit, and an imperceptible PDF tint marker. It cannot be cryptographically foolproof when a hostile party controls the machine and can reverse-engineer the scanner. Strong server-held signing is deliberately deferred to an optional Stage 1.5.

## 2. Product promise and language

Recommended promise:

> TrainTrace checks whether the artifacts a vendor supplies are consistent with the way they say their AI system was built.

It must never promise:

- lie detection
- certification
- reconstruction of training history from final weights alone
- proof that the selected folder is the production deployment
- proof that no merged adapter was used
- reliable CPT-versus-SFT classification from final weights
- proof of random initialization merely because no known base matched

Permitted conclusions:

- **Corroborated within vendor-supplied evidence**
- **Strongly consistent**
- **Weakly consistent**
- **Partially supported**
- **Insufficient evidence / abstained**
- **Contradicted within the observed scope**
- **Artifact not supplied or outside scan scope**

Never output “the vendor lied.” A contradiction is a conflict between an exact claim and an observed artifact, not a finding about intent.

## 3. Proposed names

### Recommended

1. **TrainTrace**
   - Direct connection to training history.
   - Extensible family: Screen, Verify, and Forensics.
   - Suggested extension: .ttscan.
   - Suggested line: “Trace the evidence behind the training claim.”

### Alternatives

2. **ModelTrail** — broad and approachable, but less distinctive.
3. **Provenance Gate** — strong for procurement and enterprise use.
4. **Checkpoint Trail** — technically credible, but narrow for API/RAG cases.
5. **Model Lineage Screen** — accurate and formal, but descriptive.
6. **AdapterTrace** — memorable for LoRA, but too narrow for the full product.

### Internal or campaign names

- **Did You Train It?** — good tagline.
- **AI BS Filter** — useful internal codename, unsuitable for neutral reports.
- **VibeCheck: Model Edition** — memorable but too casual for procurement.

### Avoid

- Names containing **Certified**, **Proof**, **Authentic**, or **Lie Detector**.
- **ModelClaim**, **OriginCheck AI**, **WeightTrace**, **LineageLens**, and **ClaimLens**. Preliminary web screening found existing technical terms or products using these. Conduct formal trademark and domain clearance before choosing any name.

## 4. Stage-1 goals

- One portable Windows 10/11 x64 executable.
- No installation, administrator rights, Python, GPU, driver, or background service.
- Offline by default and no network sockets in the default mode.
- Read only explicitly selected folders.
- Inventory and hash model artifacts without loading the model.
- Parse safe metadata from common formats.
- Detect direct structural evidence for unmerged PEFT/LoRA.
- Screen evidence for API/prompt-only systems, RAG, dense tuning, CPT, distillation, merged adapters, and scratch claims.
- Check consistency among the claim, artifacts, logs, chronology, parameter counts, and approximate compute.
- Let the vendor preview and redact exactly what leaves the machine.
- Produce an emailed .ttscan bundle plus an optional PDF copy.
- Provide a separate buyer-side verifier.

## 5. Stage-1 non-goals

- No model inference or benchmark prompting.
- No base-model downloads.
- No tensor-by-tensor comparison of large checkpoints.
- No dequantization.
- No cloud-account access.
- No automatic email sending.
- No collection of weights, datasets, source code, raw prompts, credentials, or personal files.
- No execution of scripts, notebooks, libraries, model custom code, or plugins.
- No unsafe Python/PyTorch deserialization.
- No attempt to defeat an administrator intentionally presenting a decoy environment.

## 6. Components

### TrainTrace Screen

The vendor-facing scanner: safe inventory, metadata extraction, deterministic rules, privacy preview, report rendering, and bundle creation.

### TrainTrace Verify

The buyer-facing verifier: safe bundle parsing, hash recomputation, rule-result recomputation, marker extraction, and separate integrity/coverage/trust/evidence statuses.

### Case Builder

A buyer-side mode inside Verify that creates a challenge containing:

- case ID and random nonce
- vendor label
- vendor’s exact claim text
- issued and expiry times
- expected scanner build hash
- ruleset and schema versions
- requested evidence categories

The buyer signs the challenge. The scanner contains only the public verification key.

### Optional Stage-1.5 Seal Service

Not an MVP dependency. It would receive only the case ID and canonical report/manifest hashes, mark the nonce used, and return a server-held digital signature. It must never receive proprietary artifacts.

### TrainTrace Forensics

A separate heavy tool for tensor differences, adapter reconstruction, checkpoint replay, quantization-aware analysis, runtime binding, and witnessed audits.

## 7. End-to-end workflow

1. Buyer records the exact claim.
2. Case Builder creates a one-time challenge.
3. Buyer emails Screen.exe, the challenge, and a one-page instruction sheet.
4. Vendor verifies the published SHA-256 and Windows publisher signature.
5. Vendor launches the portable scanner.
6. Scanner displays the exact claim and vendor-self-scan limitation.
7. Vendor selects its claimed lineage facets.
8. Vendor selects only folders it is willing to expose.
9. Scanner shows a preflight privacy and coverage preview.
10. Scanner inventories, hashes, parses safe metadata, and runs rules.
11. Vendor reviews every outbound fact and may redact usernames, absolute paths, and commercially sensitive filenames. Redactions remain recorded.
12. Scanner produces one .ttscan bundle and optional extracted PDF.
13. Vendor emails the exact bundle back. Screenshots, Word conversions, and re-exported PDFs are non-authoritative.
14. Buyer opens it with TrainTrace Verify.
15. Verify separates file integrity from evidence strength.
16. If important uncertainty remains, buyer requests only missing anchors or escalates to Stage 2.

## 8. Architecture and trust boundary

~~~mermaid
flowchart LR
    A[Buyer creates one-time challenge] --> B[Vendor runs portable scanner]
    B --> C[Read-only inventory and safe parsers]
    C --> D[Normalized facts]
    D --> E[Deterministic rules and abstention]
    E --> F[Vendor privacy preview]
    F --> G[PDF plus canonical JSON plus manifest]
    G --> H[Sealed .ttscan email attachment]
    H --> I[Buyer-side verifier]
    I --> J{Evidence sufficient?}
    J -->|Yes| K[Stage-1 screening conclusion]
    J -->|No| L[Targeted request or Stage 2]
    G -. optional digest only .-> S[Stage-1.5 signing endpoint]
~~~

Trust boundaries:

- Vendor-host observations remain vendor-supplied evidence.
- Hashes bind the report to bytes observed during the run; they do not prove production origin.
- Hidden markers detect casual reconstruction; they do not establish truth.
- An optional server signature proves the digest was sealed and not later changed; it still does not prove genuine inputs.
- Only witnessed or independently controlled Stage 2 raises assurance beyond self-scan.

## 9. Classify a lineage stack, not one label

Real systems combine methods. Use four independent facets.

### Weight origin

- random initialization claimed
- derivative of disclosed base
- distilled from teacher
- unknown

### Parameter update

- no update observed
- unmerged PEFT/LoRA observed
- merged-adapter-consistent
- partial/dense update
- unknown

### Training stage or objective

- continued pretraining
- supervised/instruction tuning
- preference tuning
- distillation
- other/unknown

### Inference augmentation

- RAG
- external API/router
- tools/prompt orchestration
- local direct inference
- none observed/unknown

A valid result could be:

> Qwen-derived weights → continued pretraining → LoRA instruction tuning → adapter merged → RAG plus an external routing layer.

This is more accurate than forcing “LoRA or scratch.”

## 10. Evidence tiers

| Tier | Meaning | Examples |
|---|---|---|
| E0 | Claim only | Questionnaire answer, marketing sentence |
| E1 | Mutable supporting record | README, screenshot, config text, invoice |
| E2 | Direct structural artifact | Adapter tensors, SafeTensors header, checkpoint index |
| E3 | Cross-corroborated technical trail | Exact base plus checkpoints, logs, and runtime binding |
| E4 | Independently supervised evidence | Buyer-selected replay, attested run, neutral infrastructure |

Do not count correlated evidence repeatedly. A README, config, and generated model card from one directory may be one source rather than three confirmations.

## 11. Evidence by claimed method

### External API, prompting, or tool wrapper

Inspect:

- provider/endpoint/model configuration
- provider SDK dependencies
- request IDs, timings, and outbound inference traces
- serving command line and router/fallback configuration
- local-weight presence/absence

Rules:

- Say “external inference endpoint observed” unless provider/model identity is independently bound.
- A remote endpoint might still be vendor-owned.
- Findings apply only to sampled requests because routing and caching can vary.

### RAG

Inspect:

- vector-index/retrieval-store manifests
- embedding-model identity and revision
- source, chunking, and index-build configuration
- query → retrieved chunks/scores → assembled context → output traces
- RAG-on/RAG-off replay records

Rules:

- RAG can coexist with LoRA, dense fine-tuning, or API usage.
- A vector database sitting in a project is not proof of production use.
- Strong evidence needs a request-level retrieval chain.

### Unmerged PEFT/LoRA

Inspect:

- adapter_config.json
- adapter_model.safetensors or adapter_model.bin
- peft_type, base reference/revision, rank, alpha, target modules, DoRA/RS-LoRA, modules_to_save
- LoRA A/B or method-specific adapter tensor keys
- tensor shapes consistent with rank and targets
- adapter-versus-base size
- exact base hash and deployment association

Strongest Stage-1 combination:

1. Valid adapter configuration.
2. Matching adapter tensors and shapes.
3. Exact base revision/hash.
4. Consistent trainable/total parameter records.
5. Evidence binding that pair to the deployed artifact.

Limitations:

- Configurations and filenames are mutable.
- Formats vary.
- DoRA, saved modules, biases, and multiple adapters change expected tensors.
- Missing adapter files never proves LoRA was not used; the adapter may be merged.

Official PEFT documentation describes the ordinary adapter configuration, adapter weights, and LoRA A/B tensor structure: https://huggingface.co/docs/peft/developer_guides/checkpoint

### Merged adapter

Stage 1 may inspect:

- full-sized dense checkpoint
- exact declared base revision
- merge logs/configuration
- any supplied pre-merge adapter
- architecture/tokenizer/layout compatibility

Stage 1 should normally abstain from proving merged LoRA. Stage 2 can check whether non-target tensors remain unchanged, target deltas have low effective rank, and a supplied adapter re-merges to the final checkpoint.

Quantization, dtype conversion, model soups, multiple adapters, DoRA, and later dense training can erase or imitate those patterns.

### Partial or full fine-tuning

Inspect:

- exact pre-training and final identities
- optimizer parameter groups and trainability records
- intermediate checkpoints
- loss, learning-rate, scheduler, and token histories
- trusted pre/post delta summaries

Limitations:

- A full-sized checkpoint does not prove every parameter was trained.
- Conversion/quantization can make every serialized tensor differ.
- Final weights do not prove optimizer history.

### Continued pretraining

Inspect:

- exact starting base
- causal-LM or declared objective configuration
- corpus manifest and token counts
- tokenizer version/vocabulary changes
- checkpoint and optimizer trajectory
- loss-versus-token history
- replay of a buyer-selected historical step

Hard rule: final weights alone cannot reliably distinguish CPT from dense SFT. Without objective, data, and trajectory evidence, abstain.

### Distillation

Inspect:

- immutable teacher identity/revision
- soft-target, KL, logits, or response-distillation objective
- hashed teacher-output/logit cache
- paired teacher/student examples
- student checkpoint trajectory
- replay against teacher records

Limitations:

- Model size, style, and behavioral similarity do not prove distillation.
- Shared training data can produce similarity.
- Record exactly what the vendor means by “distillation.”

### Claimed random-initialization training

Required anchors:

- step-zero/random-initialization checkpoint committed before training
- early and intermediate checkpoints
- optimizer, scheduler, seed, and data-order state
- training configuration
- dataset manifest, hashes, and token counts
- tokenizer-training artifacts when an original tokenizer is claimed
- GPU job telemetry and hardware count/type/hours
- storage/checkpoint chronology
- compute plausibility
- buyer-selected continuation or loss replay

Separate these claims:

- original/randomly initialized weights
- original architecture
- original tokenizer

A scratch model may reuse a known architecture or tokenizer. Failure to match known bases does not prove scratch training.

For a broad plausibility screen, dense-transformer compute may be approximated as C ≈ 6 × parameters × training tokens. Treat it as an order-of-magnitude check, never proof.

## 12. Safe format support

Initial parsers:

- Hugging Face/Transformers configuration and shard indexes
- PEFT adapter configuration
- SafeTensors header: names, shapes, dtypes, offsets, and metadata
- GGUF header and key/value metadata
- ONNX model metadata without running operators
- trainer_state.json and bounded training configuration
- DeepSpeed/Accelerate configuration
- bounded JSON, JSONL, YAML, TOML, CSV, and text logs
- container/deployment manifests and dependency lockfiles
- dedicated TensorBoard/experiment summary parsers later

SafeTensors allows efficient metadata inspection without loading all tensor data: https://huggingface.co/docs/safetensors/metadata_parsing

Hash but do not deserialize:

- Python pickle
- PyTorch .pt, .pth, and .bin through torch.load
- joblib
- NumPy object arrays
- scripts, notebooks, DLLs, plugins, or custom model code

PyTorch notes that a general resumable checkpoint may contain more than a model state dictionary, which is why mere file presence is evidence rather than proof: https://docs.pytorch.org/tutorials/beginner/saving_loading_models.html

Parser limits:

- format-specific maximum metadata sizes
- maximum nesting depth, keys, strings, and arrays
- strict offset/length bounds
- duplicate-key rejection where ambiguity matters
- no symlink, junction, mount-point, or reparse-point traversal by default
- stable file identity to detect loops
- explicit coverage gaps for access-denied or changing files
- streaming hashes with bounded buffers
- no artifact copying into the report

Windows reparse points can cause non-ordinary traversal behavior and must be explicitly handled: https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points

## 13. Facts and deterministic rules

Keep extraction separate from judgment.

Parsers emit normalized facts:

- artifact type, size, hash, and redacted path
- tensor name, shape, dtype, and parameter count
- adapter type/rank/targets/base reference
- architecture/tokenizer identity
- checkpoint step, loss, learning rate, and chronology
- trainable/total parameter claims
- teacher/provider/retriever references
- GPU count/type/hours and token claims

Facts contain no verdict language.

Rules consume facts and emit:

- supporting evidence
- missing anchor
- contradiction
- ambiguity
- coverage limitation
- next-evidence request

Example rule IDs:

- TT-LORA-001 — PEFT config declares LORA
- TT-LORA-002 — adapter keys/shapes match rank
- TT-BASE-001 — exact base revision/hash supplied
- TT-RAG-001 — request-level retrieval chain observed
- TT-API-001 — sampled request correlates with external call
- TT-SCRATCH-001 — step-zero plus early trajectory supplied
- TT-COMPUTE-001 — compute story falls within stated range

Every conclusion cites rule IDs and artifact hashes.

## 14. Scoring and abstention

### Score meaning

Use a 0–100 **Claim Support Score**, not a “truth probability.” Thresholds remain provisional until calibrated.

| Score | Band |
|---:|---|
| 0–49 | Insufficient evidence |
| 50–69 | Weakly consistent |
| 70–84 | Strongly consistent |
| 85–100 | Corroborated within supplied evidence |

Emit a method label only when:

- score is at least 80
- a method-specific anchor exists
- best evidence is E2 or stronger
- no hard contradiction exists
- mutually exclusive alternatives differ by at least 15 points

Otherwise abstain.

### Evidence caps

- Questionnaire/config only: 25
- API behavior only for a weight-training claim: 35
- Final weights without exact base/trajectory: 55
- Merged-LoRA without exact base or reproducible adapter: 60
- CPT/distillation without objective or teacher trajectory: 40
- Scratch without step-zero and intermediate checkpoints: 45

### Starting rubrics

| Claim | Weighted anchors |
|---|---|
| Unmerged LoRA | structure 30; base 20; base consistency 20; load/remerge record 20; deployment binding 10 |
| Merged adapter | exact base 15; delta pattern 25; pre-merge adapter 20; merge reproduction 30; binding 10 |
| Dense fine-tune | pre/post 15; broad deltas 20; optimizer/trainability 20; progression 20; replay 15; binding 10 |
| CPT | base 10; trajectory 15; objective/data/tokens 25; optimizer 20; replay 20; binding 10 |
| Distillation | teacher 15; teacher outputs 25; objective 20; trajectory 15; replay 15; binding 10 |
| RAG | index 20; retrieval trace 25; prompt assembly 25; replay 15; binding 15 |
| External API | binding 20; config 20; observed egress 35; upstream correlation 20; other 5 |
| Scratch | identity 5; step-zero 20; trajectory 20; optimizer/data order 15; data/tokenizer 10; compute/jobs 15; replay 10; candidate exclusion 5 |

Mandatory abstention:

- exact base unknown
- only quantized/converted weights available for comparison
- important hashes conflict
- no binding to claimed deployment
- CPT versus SFT rests only on final weights
- distillation rests only on style
- scratch rests only on “no match”
- hybrid methods are too close
- evidence is too mutable or incomplete

Missing evidence is not contradiction.

## 15. Bundle format

File name:

    TT-<case-id>-<short-digest>.ttscan

Use a ZIP-compatible container with a custom extension, deterministic file order, no executable content, and strict verifier limits.

Contents:

    challenge.json
    challenge.sig
    report.json
    report.pdf
    artifact-manifest.json
    integrity-envelope.json
    forensic-markers.json
    VERIFY.txt

### challenge.json

- schema_version
- case_id
- nonce
- vendor_label
- exact_claim_text
- issued_at and expires_at
- expected_scanner_sha256
- ruleset_version
- requested_evidence

### report.json

- scanner/build/rules/schema versions
- challenge identity
- host and scan mode
- declared lineage facets
- selected and excluded scope
- redaction ledger
- normalized observations
- conclusions by facet
- scores, caps, evidence tiers, and abstentions
- evidence and contradiction references
- limitations and suggested Stage-2 requests
- artifact-manifest hash

### artifact-manifest.json

For every inspected artifact:

- stable internal artifact ID
- redacted relative path
- type
- size
- SHA-256
- metadata parser/version
- read status
- changed-during-scan flag

### Canonicalization

Canonicalize report and manifest data before hashing. RFC 8785 explains why cryptographic hashing/signing needs invariant JSON representation: https://www.rfc-editor.org/rfc/rfc8785.html

Prefer integer units and strings over floating-point fields in authoritative JSON; for example, store score_tenths = 743 rather than an ambiguous binary float.

## 16. Report design

The PDF is a readable view. report.json is authoritative.

Page 1:

- case/vendor/claim
- scanner/ruleset/build
- assurance level: vendor self-scan
- headline lineage stack
- per-facet support band
- integrity status placeholder
- unavoidable limitation statement

Following pages:

- vendor-declared facts
- directly observed artifacts
- software inferences
- missing evidence
- contradictions
- excluded alternatives
- coverage and redactions
- recommended next evidence
- methodology and score meaning

Required statement:

> This Stage-1 report evaluates consistency within vendor-supplied evidence. It does not establish intent, independently verify the production environment, or prove historical training events that cannot be reconstructed from the supplied artifacts.

## 17. Offline tamper-evidence

### 17.1 Manifest and deterministic hash

Hash every bundle payload and create one root digest. TrainTrace Verify recomputes it. Because a determined vendor can reverse-engineer an offline scanner and regenerate hashes, call this self-consistency, not independent cryptographic proof.

### 17.2 Hidden numerical canary

Preserve the analytical score separately. Example:

- canonical score_tenths = 743, meaning 74.3
- display may show 74.32%, where the final digit is a per-case integrity digit

The last digit:

- never affects thresholds or conclusions
- derives from the complete canonical report and case marker seed
- is distributed across several displayed values
- is checked by Verify
- is documented generally as a non-analytical rendering-integrity digit so numerical precision is not misrepresented

Do not encode day/month directly; that is predictable. Two digits alone provide only 100 combinations.

### 17.3 Invisible tint marker

- Render a small footer/logo raster on every page.
- Change low-order RGB values by ±1 at many pseudorandom locations.
- Encode a report-bound tag with redundancy/error correction.
- Record marker version, carrier location, and expected tag digest.
- Verify by correlation rather than checking a handful of pixels.

For the intended emailed-original-PDF workflow, this should survive ordinary attachment transport. Editing, re-exporting, optimizing, or reconstructing the PDF will usually change or remove it.

### 17.4 What these markers establish

They catch casual PDF editing and reconstruction. They are not the root of trust. Their method may eventually be discovered, and security must not depend solely on secrecy.

### 17.5 Optional strong seal

Stage 1.5 adds one brief online action after the scan:

1. Scanner sends case ID, report digest, manifest digest, build version, and no proprietary artifacts.
2. Service rejects expired/reused cases.
3. Service signs a canonical envelope using a server-held Ed25519 key, or ECDSA P-256 where compliance requires it.
4. Bundle receives seal.json and seal.sig.
5. Verify uses the public key.

Digital signatures are designed to detect unauthorized changes and authenticate the signer: https://csrc.nist.gov/pubs/fips/186-5/final

Even this seal proves only that the bundle has not changed since sealing. It does not prove the vendor selected genuine production inputs.

## 18. Closed-box strategy

The realistic objective is **difficult to inspect**, not “impossible to dissect.”

MVP controls:

- Compile to native code.
- Strip symbols and debug information from releases.
- Obfuscate rule/resource names where practical.
- Split marker generation across modules.
- Encrypt or compress embedded rule resources.
- Add executable self-hash checks.
- Authenticode-sign the release.
- Publish its SHA-256 separately.
- Make every release/ruleset version explicit.
- Use a per-case nonce and short validity period.
- Never store a master signing key in the executable.

Microsoft describes Authenticode as providing publisher identity and code-integrity verification: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode

Limits:

- Native binaries can still be disassembled.
- Decrypted rules can be observed in memory.
- Calls can be hooked and results patched.
- Containers, packing, WebAssembly, or obfuscation do not make client code secret.
- Legal no-reverse-engineering terms are a deterrent, not a technical control.

## 19. Privacy and safety

- Read-only access.
- Default-deny file selection.
- No admin rights.
- No network by default.
- No raw weights/data/source/prompts in output.
- Secret-pattern scanner redacts API keys, tokens, passwords, email addresses, and Windows usernames.
- Absolute paths replaced by scoped aliases.
- Vendor sees a complete outbound-data preview.
- Redactions are explicit facts in the report.
- Writes occur only in chosen output location.
- Temporary material uses a case-specific directory and is deleted on normal completion.
- Crash logs contain parser/rule IDs, not proprietary values.
- Scanner never evaluates macros, HTML/JS, model code, or documents.
- Verifier treats the .ttscan bundle as hostile: path traversal, symlink, duplicate-name, decompression-ratio, file-count, and total-size limits.

## 20. Recommended implementation stack

### Language

Use **Rust** for the production scanner and verifier:

- single native binary
- no bundled interpreter
- good bounded-memory and safe-parsing options
- strong Windows API access
- reusable core for later Linux support

The first command-line prototype could also be Rust so no rewrite is required.

### UI

Use a lightweight native Rust UI. Avoid Electron. Keep the interface to six screens:

1. Open challenge.
2. Confirm claim and assurance notice.
3. Select evidence folders.
4. Review privacy/coverage preflight.
5. Run scan with progress/cancel.
6. Review findings/redactions and export.

### Internal modules

    crates/
      tt-core/          data types, canonicalization, hashing
      tt-inventory/     safe Windows traversal and file identity
      tt-formats/       SafeTensors, PEFT, GGUF, ONNX, log parsers
      tt-facts/         normalized evidence model
      tt-rules/         deterministic scoring, caps, abstention
      tt-report/        JSON/PDF rendering
      tt-markers/       numerical and tint tripwires
      tt-bundle/        .ttscan writer/reader
      tt-scanner-ui/    vendor application
      tt-verifier-ui/   buyer application
      tt-case-builder/  challenge issuance
      tt-fixtures/      development-only fixture generator

### Performance targets

- Scanner release target: approximately 10–30 MB, validated after stack selection.
- Verifier release target: similar or smaller.
- Metadata-mode memory: under 256 MB.
- Streaming hash buffer: bounded and configurable.
- Report excluding large manifest: normally under 1 MB.
- Responsive cancellation during every long read.
- Progress based on discovered bytes, not invented percentages.

## 21. UX details

### Preflight

Show:

- selected roots
- recognized evidence categories
- estimated bytes to hash
- unsupported files
- secrets/redaction policy
- exact fields that may leave the machine

### Scan

Show current phase, bytes processed, artifacts recognized, warnings, and Cancel. Do not expose sensitive filenames in screenshots by default.

### Review

Separate:

- declared facts
- observed facts
- inferences
- missing evidence
- contradictions
- limitations

Allow safe display redaction but never permit deletion of a negative fact. If a source is excluded, record “excluded by submitter.”

### Export

Create the bundle atomically:

1. Write to a new temporary file in the chosen output folder.
2. Flush and close.
3. Reopen and verify every payload hash.
4. Rename to final .ttscan only after self-verification.
5. Display final filename and SHA-256.

## 22. Development phases

The parser is easy; credible conclusions and adversarial testing are the real work.

### Phase 0 — specification, 3–5 working days

- Freeze taxonomy, evidence tiers, rule IDs, score meaning, and permitted wording.
- Freeze privacy/redaction policy.
- Define challenge, report, manifest, and bundle schemas.
- Write threat model and acceptance tests first.

Exit gate: every possible conclusion has required evidence, caps, abstention conditions, and allowed wording.

### Phase 1 — command-line core, 7–10 working days

- Safe traversal and streaming SHA-256.
- Canonical facts and JSON.
- PEFT, SafeTensors, Transformers, and basic training-log parsers.
- Initial deterministic rules.
- Synthetic fixtures.

Exit gate: CLI classifies obvious fixtures without executing supplied content.

### Phase 2 — evidence breadth, 7–10 working days

- GGUF and ONNX metadata.
- RAG/API/deployment evidence parsers.
- compute plausibility.
- multi-label lineage output.
- evidence deduplication, caps, and mandatory abstention.

Exit gate: all primary claim classes produce correctly qualified results.

### Phase 3 — Windows product and reporting, 7–10 working days

- scanner GUI
- Case Builder and Verify
- privacy preview/redaction ledger
- PDF renderer and .ttscan bundle
- hidden numerical and pixel markers
- cancellation and atomic output

Exit gate: a nontechnical vendor completes the workflow from a one-page guide.

### Phase 4 — hardening and blind pilot, 10–15 working days

- parser fuzzing
- malicious filesystem/bundle cases
- clean Windows 10/11 VM tests
- antivirus/SmartScreen and code-signing checks
- false-positive calibration
- legitimate and deceptive fixture pilot
- documentation and recovery paths

Exit gate: no unsafe execution, bounded resource use, stable reports, and qualified conclusions.

### Practical estimates

- Demonstration prototype: 1–2 weeks.
- Controlled pilot MVP: 4–6 weeks.
- Hardened Stage 1: 7–10 weeks for one strong engineer plus domain review.
- Stage 2: an additional 6–12 weeks depending on formats and comparison scale.

Do not promise “catches 99%” until a blinded benchmark measures it.

## 23. Test programme

### Golden evidence fixtures

- obvious unmerged PEFT LoRA
- renamed but structurally valid adapter
- malformed adapter/config mismatch
- LoRA merged into full weights: Stage 1 must abstain
- dense fine-tune with coherent logs
- partial fine-tune
- CPT and SFT with indistinguishable final-only evidence
- distilled student with teacher trail
- “scratch” claim with final weights only
- genuine scratch trail with step-zero/intermediates
- API plus RAG with no owned local weights
- RAG plus LoRA
- multi-provider router/cache

### Hard negatives

- same tokenizer/architecture but unrelated lineage
- quantized/dtype-converted siblings
- dense update with low-rank-looking deltas
- multiple merged LoRAs
- DoRA
- LoRA followed by dense training
- model soups/weight merging
- fabricated but internally neat logs
- timestamps copied or rewritten

### Parser and filesystem abuse

- malformed/truncated SafeTensors and GGUF headers
- giant JSON and extreme nesting
- duplicate keys
- Unicode and very long Windows paths
- access-denied files
- files changing during scan
- symlinks, junctions, reparse loops
- sparse files
- named streams where relevant
- zip-slip and duplicate entries in .ttscan
- decompression bombs

### Tamper tests

- modify one PDF word
- alter one score
- replace report.json
- remove one manifest item
- rezip in different order
- strip metadata
- modify/recompress tint carrier
- copy markers between reports
- reuse an old challenge
- change case ID/vendor/claim
- use wrong scanner build/ruleset

Expected outcome: integrity and marker statuses fail separately and explain why.

### Privacy tests

- API tokens and cloud credentials
- Windows usernames and absolute paths
- personal email addresses
- dataset sample text
- raw prompts
- proprietary source fragments

Expected outcome: none leaks into the bundle unless explicitly allowlisted and previewed.

### Reproducibility

Two scans of unchanged evidence should produce the same canonical facts and evidence digest. Timestamps, nonce, and rendering-specific fields must be isolated from analytical facts.

## 24. Evaluation metrics

Measure per class:

- precision
- recall
- confusion matrix
- abstention rate
- coverage rate
- false contradiction rate
- percentage of conclusions with an E2+ anchor
- runtime and peak memory by corpus size
- crash/fuzz failure rate
- privacy leakage count

Primary optimization target: high precision and safe abstention. In vendor diligence, a false accusation is more damaging than an inconclusive result.

Before marketing a percentage as calibrated confidence, collect enough labeled examples to test calibration. Until then, call it a rubric-based support score.

## 25. Pilot protocol

1. Start with synthetic fixtures and public model packages.
2. Recruit 3–5 cooperative technical users who know the true construction history.
3. Ask each to submit one honest complete case and one intentionally incomplete/misleading case.
4. Freeze rules before opening the blind cases.
5. Record expected lineage, scanner result, abstention, false positives, privacy concerns, and usability issues.
6. Change rules only with a documented reason and new version.
7. Repeat against a held-out set.
8. Publish limitations and measured coverage, not only successes.

The first external use should remain synthetic or read-only and should not require access to production mailboxes, CRM/ERP, financial information, or unrelated proprietary material.

## 26. Stage-2 upgrade

Keep the same schemas, report vocabulary, and verifier. Add optional evidence modules:

- exact base/final tensor-name alignment
- canonical dtype/layout conversion
- per-layer delta statistics
- randomized SVD/effective-rank analysis
- target-versus-non-target comparisons
- pre-merge adapter reapplication
- checkpoint trajectory and optimizer continuity
- buyer-selected replay
- quantization-aware refusal/tolerance rules
- black-box behavioral lineage only as supporting evidence
- running process/container image/storage binding
- cloud job/control-plane receipts
- witnessed challenge after target selection
- TPM/measured-boot evidence where appropriate
- auditor-controlled VM or boot media with read-only production storage

Stage-2 output should still say “consistent with merged LoRA” unless exact adapter reproduction or trustworthy history supports a stronger statement.

## 27. Definition of done for Stage 1

Stage 1 is ready for controlled vendor pilots only when:

- portable scanner and verifier run on clean supported Windows systems
- no admin rights or installation are required
- default mode opens no network connection
- selected artifacts are never executed or unsafely deserialized
- all parsers enforce resource and traversal limits
- every conclusion cites evidence and a versioned rule
- required anchors/caps/abstention work on the fixture matrix
- missing evidence never becomes an automatic accusation
- outbound preview and redaction ledger are complete
- .ttscan verifies deterministically
- numerical and tint markers survive ordinary email attachment transport
- all deliberate report edits fail integrity checks
- the report clearly labels vendor-host and production-binding limitations
- code-signed releases and published hashes are documented
- blind pilot metrics are recorded

## 28. First implementation backlog

### Must have

- schemas and vocabulary
- Case Builder
- safe inventory and SHA-256
- PEFT/Transformers/SafeTensors parsers
- basic training-log parser
- facts/rules/caps/abstention
- privacy preview
- report.json and PDF
- .ttscan container
- Verify
- numerical/tint marker prototype
- fixture and tamper tests

### Should have

- GGUF and ONNX
- RAG/API/deployment evidence
- compute plausibility
- process/container binding where permitted
- Authenticode release process
- fuzzing and reproducible-build work

### Later

- optional digest-only signing endpoint
- Linux scanner
- experiment-tracker integrations
- heavy tensor forensics
- remote attestation

## 29. Open decisions before coding

1. Final public name after trademark/domain clearance.
2. Exact first-release formats: recommended PEFT, SafeTensors, Transformers, GGUF, and bounded logs.
3. Whether PDF or HTML is the human-readable primary view; PDF better matches email workflow.
4. Whether full large-file hashing is mandatory or user-selectable. Recommended: full hashing for selected model artifacts, metadata-only mode clearly capped.
5. Whether the hidden score digit remains in production. Recommended: prototype it, disclose that the final digit is non-analytical, and remove it if users interpret it as scientific precision.
6. Whether Stage 1.5 signing is worth a tiny online dependency after the offline pilot.
7. Who owns the buyer-side issuance/signing keys and recovery procedure.
8. Which evidence can be bound to the actual serving process without admin rights.
9. Minimum acceptable precision and maximum false-contradiction rate before external marketing.

## 30. Recommended final product structure

- Public brand: **TrainTrace**
- Entry product: **TrainTrace Screen**
- Buyer utility: **TrainTrace Verify**
- Deep service: **TrainTrace Forensics**
- Bundle: **.ttscan**
- Formal document name: **Model Provenance Screening Report**
- Tagline: **“Trace the evidence behind ‘we trained our own AI.’”**
- Internal codename: **Bullshit Filter**

This keeps the external product serious while preserving the sharp internal purpose.

