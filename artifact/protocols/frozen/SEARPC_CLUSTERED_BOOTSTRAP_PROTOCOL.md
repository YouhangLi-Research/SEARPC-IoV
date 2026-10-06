# DURAC clustered bootstrap: Receiver-clustered external-test uncertainty

Status: frozen before inspecting clustered confidence intervals

Date: 2026-08-26

## Question

matched external baselines contains 813,602 urban Test messages, but messages received by the
same vehicle are not independent experimental units.  clustered bootstrap quantifies the
uncertainty of the frozen matched external baselines comparison without changing a feature,
model, calibrator, threshold, split, or prediction rule.

## Frozen analysis

- The data, three learned methods, highway Train fitting, highway Validation
  calibration/threshold selection, and urban Test evaluation are exactly those
  registered in matched external baselines.
- The cluster is one official receiver/source JSON file.  Cluster identifiers
  are used only for statistical resampling and never as model features.
- Data-replay and time-delay clusters are sampled independently with
  replacement, preserving the original number of receiver files per attack.
- The same sampled cluster multiplicities are applied to RF, single HGBDT, and
  DURAC in every replicate, yielding paired method differences.
- The random seed is 260826 and the number of bootstrap replicates is 2,000.
- ECE uses the frozen 15 equal-width bins on [0, 1].

## Outcomes

For pooled urban Test, data replay, and time delay, report percentile 95%
confidence intervals for Macro-F1, malicious recall, FPR, PR-AUC, Brier score,
and ECE-15.  Also report paired DURAC-versus-RF and DURAC-versus-HGBDT
differences.  Positive oriented differences always mean that DURAC is better;
the sign is reversed for FPR, Brier, and ECE.

matched external baselines point estimates must be reproduced before bootstrap output is
accepted.  A confidence interval that includes zero is retained and narrows
the claim; it does not authorize Test-set tuning.
