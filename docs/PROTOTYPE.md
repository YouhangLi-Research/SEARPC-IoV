# Process prototype scope and certificate validation

## Purpose

The 16/40-process localhost prototype measures candidate selection,
reconfiguration, block availability, Ed25519 verification, and fixed-quorum
certificate handoff. The complete canonical-audit, delivered-evidence, and
Active/Quarantine/Probation mechanism is executed by the 40-RSU protocol
trajectory runner. The process prototype has no locking or view-change state
machine and is not a complete PBFT or HotStuff implementation.

## Deterministic process selectors

For a block identifier b, the size-fixed selector chooses
`[(b * 7 + offset) % N for offset in range(min(13, N))]`.
Thus `Fixed k=13` fixes size while rotating members at each block.

The conditioned selector generates
`{i for i in range(N) if (i + b // 4) % 17 == 0}` as its warning set.
If that set intersects the primary candidate, the selector replaces the
candidate with an equal-sized set from the remaining processes. This
synthetic schedule isolates reconfiguration cost. Its frequency is independent
of the audit-driven frequency in the protocol trajectories; a higher frequency
does not establish an upper bound on full evidence-processing cost.

## Local validation policy

Before each measured block, the local experiment controller provisions the
block digest, allowed certificate signers, and expected threshold through
parent-owned multiprocessing shared state. The network handlers read that
configuration. A request's `quorum` field is checked for consistency; it does
not set the threshold or final quorum. Requests cannot override membership.

| Certificate context | Allowed signers | Required threshold |
| --- | --- | --- |
| 13-member fast candidate | Locally installed candidate members | 9 |
| Full 16-process path | Registered 16 processes | 11 |
| Full 40-process path | Registered 40 processes | 27 |

Signing identifiers must be integers in the registered range, distinct, and
eligible for the installed candidate certificate. Signatures are verified
cryptographically. Invalid encodings, negative aliases, duplicates, out-of-set
signers, missing thresholds, and request-selected lower thresholds are refused.
Standard-path handoff is provisioned locally with full registered membership.
The final collector still requires Q=11/27 distinct verified signatures.

This configuration channel is trusted local experiment provisioning, not a
network consensus mechanism. A production integration obtains candidate state
from the replicated participation layer and delegates finality to its base BFT.

## Timing and results

Execution timing begins after deterministic candidate selection and local policy
installation. Block distribution, certificate exchanges, and fixed-quorum
completion are measured; selector time is recorded separately. The signature
messages and network payload schema were retained during validation hardening.

The paper's Figure 11 and Table XXI now use the full five-launch, 500-block
rerun of the maintained certificate-validation implementation completed on
2026-10-06. Raw block records, per-launch statistics, source hashes and
validity checks are retained under `artifact/results/final_reproduction/system-full/`.
`python run.py system-full` executes this same measurement configuration
on the local host. `python run.py paper-check` recomputes the publication
statistics from the distributed block records.
