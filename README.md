# welcome-wagon

**The SafeHarbors open-weight attestation bench.** This repo holds the
working results of the model-supply-chain work: the harbor-watch tool, its
kernel-checked proofs, and the composition that ties it to the standard
SBOM ecosystem for model weights.

## Why

The Lazarus paper (Microsoft Research, November 10, 2026) demonstrated that
editing fewer than ten dormant neurons turns a capable agent model into a
sleeper that passes every evaluation. The defense is not scanning — it is
**attestation against an enrolled reference, at every load**: fitness for
duty, checked every shift, every day.

## What's here

| Path | What |
|---|---|
| [`harbor-watch/`](harbor-watch/) | CoE tool #2 — zero-dependency Rust: enroll the hire, check every shift (whole-file + per-tensor sha512, tensor-localized diff), hash-chained shift log with tamper evidence. 17 tests. Demonstrated on real estate weights: one flipped byte → UNFIT, localized to the changed tensor. |
| [`verification/HarborWatchChain.lean`](verification/HarborWatchChain.lean) | The chain and diff theorems, kernel-checked (Lean 4.35.0, no Mathlib): tamper detection, link-break detection, tensor-edit detection — given collision resistance, stated as axioms. Localization + tamper-anywhere owed to the next rung. |
| [`verification/LEAN-002.yaml`](verification/LEAN-002.yaml) | The Proof Forest leaf record. |
| [`verification/receipts/`](verification/receipts/) | The kernel run receipt. |

## How the standard SBOM-for-weights stack composes

The ecosystem gives every layer except the one that matters most — what
happens AFTER the download:

| Layer | Tool | Vouches |
|---|---|---|
| Inventory | **cdxgen / CycloneDX ML-BOM** | the model as a component: model card, parameters, datasets, file hashes |
| Attestation | **in-toto** | the signed statement: subject (the weights' digests) + predicate (how it was built, from what base) |
| Signature | **Sigstore / Rekor** (via OpenSSF Model Signing) | the maker's signature, publicly witnessed in an append-only log |
| Distribution | **go-tuf / TUF** | the trust root and the manifests, compromise-resilient (rotation, expiry, snapshots) |
| Query | **GUAC** | the graph: which model traces to which publisher, base, and attestations |
| **After the download** | **harbor-watch** | **every shift**: the weights on disk are the ones enrolled — diffed, receipted, tamper-evident |

Everything else vouches at a moment: build time, listing time, distribution
time. harbor-watch vouches every shift — the layer the ecosystem lacks, and
the layer the fitness-for-duty argument says is the only one that matters
after day one.

The composition: enroll FROM the maker's signed manifest (provenance first),
check every shift (the diff — benign modifications change many weights
slightly; an implant changes a few drastically), emit the shift log as
attestations, and feed the graph. The shift log is an attestation stream.

## The essays behind it

The argument in full, on the SafeHarbors site:
[We need a safe harbor.](https://www.safeharborsai.com/critique-of-ai) ·
[State of AI custody after Slaughter](https://www.safeharborsai.com/state-of-ai-custody) ·
[Fitness for duty](https://www.safeharborsai.com/fitness-for-duty)

## License

LicenseRef-Proprietary — the estate's code, published for review and use by
arrangement. The proofs are the receipts; check them.
