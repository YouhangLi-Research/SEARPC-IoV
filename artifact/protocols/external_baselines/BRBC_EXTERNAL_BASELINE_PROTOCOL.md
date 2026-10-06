# BRBC External Baseline Protocol external baseline

## Scope

This protocol adapts only the reputation-threshold eligibility mechanism of
Blockchain Reputation-Based Consensus to the shared SEARPC fixed-finality
harness. It is not a claim to reproduce the full BRBC mining, access-control,
Bloom-filter jury, or round-robin protocol.

## Frozen comparison

- Network: N=40, fast committee k=13, fast quorum qk=9, final quorum Q=27.
- Runs: the existing ten paired 600-block traces.
- Observation budget: seven shared exogenous validator audits per block.
- Delivery: the existing ten-block delay and label-error process.
- Inputs: only canonical delivered audit records; no latent Byzantine label,
  future record, risk level, event digest, or content score enters eligibility.
- Audit provenance: the four existing registered audit domains act as the
  adapted judge classes.
- Reputation: a separate score R[g,i] in [0,10] for audit domain g and
  validator i.
- Initialization: suspicious initialization R0=T=7.
- Update: a delivered success adds one and a delivered failure subtracts one,
  clipped to [0,10]. Unit delta is the pre-specified normalization for the
  binary audit outcome.
- Eligibility: a validator remains eligible unless a strict majority of the
  four judge classes has R[g,i] < T.
- Committee adapter: when at least 13 validators remain eligible, the same
  typed-seed DIVERSE_UNIFORM selector and immutable finalizer used by the SEARPC
  core are applied. When fewer than 13 remain, execution takes the standard
  full path. This common adapter isolates eligibility control and must be
  disclosed.
- Finality: Q, locking, view change, proposal inheritance, and final
  verification are unchanged.

The publication label is `BRBC-derived reputation-threshold eligibility under
shared fixed-finality`, never `full BRBC`.

## Primary metrics

Report risk-weighted latent fault-budget exceedance, unweighted exceedance,
actual hint handoff, direct-standard rate, total expensive-full-path rate,
active pool size, mean malicious seats, audit and wire cost, final Q, legal
commit rate, and illegal acceptance. Pair inference by launch/trace.

## Retention

The protocol is frozen before execution. No threshold, update size, judge
majority, or selection rule may be changed in response to the observed result.

