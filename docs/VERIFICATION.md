# Release verification

The SEARPC release contains the full vehicle grids, canonical and budget-matched participant-selection results, message evaluation, process measurements, and manuscript figure sources. Machine-readable verification results are recorded in `results/VALIDATION.json`.

| Evaluation | Verified result |
| --- | --- |
| Registered vehicle inputs | Input hashes and complete event alignment |
| Role authorization and cold start | 160 cells; 20 paired seeds |
| Certified-domain aggregation | 320 cells; manuscript aggregates and intervals |
| BRS/TWSL source comparison | 320 cells; source-influence increments and reported precision |
| Message evidence | 813,602 predictions; 2,038 receiver/source clusters; 2,000 bootstrap resamples |
| Pooled BRS authorization | 120 paired cells; 10,920 count rows; common benign-coverage denominator |
| Security–coverage reporting | Five reports from 21,840 authorization-count rows |
| SEARPC threshold replay | 10,920 count rows; agreement with registered counts |
| Vehicle-derived risk stream | 6,000 byte-identical rows |
| Canonical participation | Four byte-identical reference CSVs |
| Shared-seven participant selection | Ten byte-identical reference CSVs; paired inputs and audit budgets |
| Audit-resource attribution | 90,000 block-method rows and reference summary |
| Adjudication delivery | 36 cases; canonical consumption timing |
| Lifecycle sensitivity | Nine parameter cells; ten paired traces each |
| Process measurements | 30,000 committed blocks; final quorum 11/27; raw-to-launch summary correspondence |
| Manuscript tables | Tables XI–XXI checked at reported precision |
| Experimental figures | Figures 4–11 generated; indexed panels and manuscript assets checked |

## Functional and integrity checks

```bash
python run.py check
python run.py paper-check
```

The functional suite covers evidence authority, deterministic delivery, replay protection, selection projections, registry commitments, baseline adapters, vehicle entry-point safeguards, signature ranges, duplicate signers, candidate membership, and trusted local certificate thresholds. Integrity checks cover all distributed files in `MANIFEST.sha256`.

## Process measurements

The included measurement records use five independent launches, five warm-up blocks, 500 measured blocks per configuration, 16/40 processes, 16 KiB payloads, persistent TCP connections, and Ed25519 signatures. The publication reports the median of launch-level p95 latencies and launch-level mean byte volumes. Cached and Fetch configurations retain the same final quorum.

Block integrity, availability, locally configured certificate thresholds, verified final signatures, and standard-path handoff are checked by the executable prototype. Evidence delivery and the RSU lifecycle are checked by the canonical trajectory experiments. The full measurement records and source checksums are in `artifact/results/final_reproduction/system-full/`.

## Source correspondence

Result manifests retain measured-source checksums. `results/SOURCE_PROVENANCE.json` maps them to the distributed source files after module and path naming was standardized. Registered experimental values and manuscript assets are preserved.
