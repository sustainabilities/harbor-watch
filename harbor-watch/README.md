# harbor-watch — CoE tool #2

**Fitness-for-duty attestation for model weights.** The third essay's
argument, made executable: the model was never verified by buying it — it
proves it is still the same weights, every shift, every day.

Built because of Lazarus (Microsoft Research, Nov 10 2026): fewer than ten
dormant neurons, edited in place, turn a capable agent model into a sleeper
that passes every evaluation. The defense is not scanning — it is
**attestation against an enrolled reference, at every load**.

## Status: v1 — built and tested on estate weights

- Zero dependencies (pure std). sha512 is the verified Waterfront
  implementation; the JSON parser is the Waterfront's.
- 17 tests green: chain tamper-evidence, safetensors roundtrip,
  tensor-localized detection.
- **Live demonstration on estate weights**: enrolled the OGB gauntlet delta
  (`gauntlet-rung1-20261022.safetensors`, 2 tensors) — fit; flipped ONE byte
  — **UNFIT FOR DUTY, the diff localized the change to the `lora_b` tensor**
  (the tensor containing the flipped offset); chain verified intact.
- GGUF models enroll in opaque mode (whole-file); nova-1.5b enrolled and
  checked fit. GGUF per-tensor parsing is roadmap.

## Commands

```bash
harbor-watch enroll <file> --name <model> [--publisher P] [--note N]  # the hire
harbor-watch check <file> [--name <model>]   # the shift: fit/unfit + tensor diff
harbor-watch log <model>                     # the shift history
harbor-watch verify <model>                  # the chain's tamper evidence
harbor-watch report <model>                  # the fitness summary
# store: <root>/enrollments/*.json + <root>/shifts/*.jsonl (default ./harbor-watch-store)
```

## Honesty class

**fit-vs-enrollment.** The tool attests that the weights match the enrolled
baseline. It cannot attest that the enrollment itself was clean — that is
the publisher's receipt (Microsoft's own caveat: a signature proves a file
is what its signer released, not that the weights weren't edited before
signing). Nothing blurred.

## Build law

The source lives on the NAS; **builds happen off-mount** (SMB mounts do not
support cargo's lock files — the tiptoe-v2 rule):

```bash
CARGO_TARGET_DIR=/tmp/hw-target cargo build --release \
  --manifest-path ~/BigBlueSea/NAS/Registry/proa-coe/tools/harbor-watch/Cargo.toml
```

## Roadmap (sourced from the provenance research, Nov 2026)

| Version | What | Source of the design |
|---|---|---|
| v1.1 | Trait seams (`Ledger`, `Attestor`) — the AirlockLedger trait-extraction pattern: logic tested against a stand-in, the same tests against the production impl; makes the engine embeddable into the portal, the airlock, the OGB gauntlet | estate session record (lararas) |
| v2 | OpenSSF Model Signing interop: in-toto statement → DSSE envelope → Sigstore bundle; verify against the MAKER's signed manifest (Rekor as the append-only ledger); TUF for the trust root | sigstore/model-transparency; the provenance research |
| v2.5 | Sketch fingerprints: per-tensor spectral top-k singular values, layer-wise moment statistics, CountSketch/MinHash — the seconds-not-minutes lineage screen for 7B-70B models | the provenance research (the cheap non-topological sketches) |
| v3 | Per-layer persistent-homology signatures as ADDITIONAL SIGNED PREDICATES in the same in-toto statement — the topological diff: coarse, cheap, and receipted. PH is triage, not proof (robust to perturbation by design — the opposite of tamper detection); it rides inside the cryptographic receipt, never instead of it | neural persistence literature; the provenance research |
| Product | The Proa shift-board: a local, zero-JS Proa dashboard over the shift logs — enrollments, fitness verdicts, drift events — dual representation (HTML + md twins), llms.txt discovery | the CoE's own site discipline |

## The design justification, in the vendor's own words

"Benign modifications change many weights slightly; a Lazarus implant
changes a few weights drastically. Diffing is the reliable check — but it
requires knowing the reference, which is why provenance comes first."
— the provenance research record, from Microsoft's Lazarus guidance.

harbor-watch v1 IS that sentence: enroll (the reference), check (the diff),
the shift log (the provenance over time).
