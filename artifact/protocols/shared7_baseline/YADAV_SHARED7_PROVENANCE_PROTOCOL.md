# Yadav Shared-7 Result-Provenance Protocol shared-seven baseline

## Purpose

This deterministic closure run reconstructs the manuscript's selection-stage
comparison between the Yadav et al. direct-history trust rule and SEARPC.  It
does not tune or expand the method.  Its sole purpose is to make every reported
shared-7 value traceable to block-level records, per-trace statistics, code,
and a hash manifest.

## Fixed comparison

- Reference: Yadav et al., IEEE TVT 2025, DOI 10.1109/TVT.2025.3575775.
- Scope: direct-history trust and highest-trust miner selection; this is not a
  claim to reproduce the paper's complete recommendation graph or blockchain.
- Network: `N=40`, fast committee `k=13`, fast quorum `q_k=9`, and immutable
  final quorum `Q=27`.
- Traces: the same ten 600-block frozen RQ4 traces.
- Observation budget: exactly seven exogenous validator audits per block.
- Pairing: Yadav and SEARPC receive identical target IDs, behavior-derived
  binary outcomes, audit domains, and ten-block delivery heights at every
  block.
- Causality: only canonical records delivered before the current decision are
  applied.  Latent Byzantine labels generate behavior and offline exposure
  diagnostics but never enter online selection or handoff decisions.
- Trust: each validator starts with one pseudo-success and one pseudo-failure;
  direct trust is `successes/(successes+failures)`.
- Selection: the 13 highest-trust validators are selected.  Equal scores use
  the frozen adapter seed and a canonical repeat/height context generated
  inside the selector; callers cannot supply an event label.  The common
  execution shell still receives the typed committee capability.
- Execution shell: both methods retain the same committee size, observable
  transcript decision, locking/finality logic, and `Q=27`.
- Inference: the paired unit is one 600-block trace.  The release reports a
  20,000-draw paired bootstrap and an exact two-sided sign-flip test.

## Required outputs

The run must retain the combined block-level file, method summary, twenty
method-by-trace rows, paired inference, explicit parity/validity checks, the
exact risk stream, and a SHA-256 manifest.  A valid run has zero mismatches in
targets, outcomes, audit counts, seed projections, and evidence roots; exactly
seven audits per method/block; `Q=27`; 100% legal commits; and zero illegal
acceptance.

## Interpretation boundary

The output supports a fair stage-matched claim about trust-ranked participation
under a common observation and finality budget.  It does not establish
universal dominance over the full Yadav system.
