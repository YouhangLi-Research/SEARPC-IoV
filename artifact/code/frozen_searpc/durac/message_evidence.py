"""Leakage-controlled message-evidence metrics and calibration helpers."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Sequence

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    log_loss,
    roc_auc_score,
)


def _probabilities(values: Sequence[float]) -> np.ndarray:
    output = np.asarray(values, dtype=float)
    if output.ndim != 1 or output.size == 0:
        raise ValueError("probabilities must be a non-empty vector")
    if not np.isfinite(output).all() or np.any((output < 0.0) | (output > 1.0)):
        raise ValueError("probabilities must be finite and in [0, 1]")
    return output


def _labels(values: Sequence[int]) -> np.ndarray:
    output = np.asarray(values, dtype=int)
    if output.ndim != 1 or output.size == 0:
        raise ValueError("labels must be a non-empty vector")
    if not np.isin(output, (0, 1)).all():
        raise ValueError("labels must be binary")
    return output


def expected_calibration_error(
    labels: Sequence[int], probabilities: Sequence[float], *, bins: int = 15
) -> float:
    y = _labels(labels)
    p = _probabilities(probabilities)
    if len(y) != len(p):
        raise ValueError("labels and probabilities must have equal length")
    if bins < 2:
        raise ValueError("bins must be at least two")
    edges = np.linspace(0.0, 1.0, bins + 1)
    indices = np.minimum(np.digitize(p, edges[1:-1], right=False), bins - 1)
    error = 0.0
    for index in range(bins):
        mask = indices == index
        if not mask.any():
            continue
        error += mask.mean() * abs(float(p[mask].mean() - y[mask].mean()))
    return float(error)


def select_fpr_constrained_threshold(
    labels: Sequence[int],
    probabilities: Sequence[float],
    *,
    maximum_fpr: float = 0.05,
) -> float:
    """Maximize malicious F1 under an FPR cap; exact ties use higher t."""

    y = _labels(labels)
    p = _probabilities(probabilities)
    if len(y) != len(p):
        raise ValueError("labels and probabilities must have equal length")
    if not 0.0 <= maximum_fpr <= 1.0:
        raise ValueError("maximum_fpr must be in [0, 1]")
    order = np.argsort(-p, kind="stable")
    sorted_p = p[order]
    sorted_y = y[order]
    cumulative_tp = np.cumsum(sorted_y == 1)
    cumulative_fp = np.cumsum(sorted_y == 0)
    ends = np.flatnonzero(
        np.concatenate((sorted_p[:-1] != sorted_p[1:], [True]))
    )
    thresholds = sorted_p[ends]
    tp = cumulative_tp[ends].astype(float)
    fp = cumulative_fp[ends].astype(float)
    total_positive = float(np.sum(y == 1))
    total_negative = float(np.sum(y == 0))
    fn = total_positive - tp
    fpr = fp / total_negative if total_negative else np.zeros_like(fp)
    precision = np.divide(tp, tp + fp, out=np.zeros_like(tp), where=(tp + fp) > 0)
    recall = tp / total_positive if total_positive else np.zeros_like(tp)
    f1 = np.divide(
        2.0 * precision * recall,
        precision + recall,
        out=np.zeros_like(precision),
        where=(precision + recall) > 0,
    )
    allowed = fpr <= maximum_fpr
    if not allowed.any():
        return 1.0
    best_f1 = float(np.max(f1[allowed]))
    tied_thresholds = thresholds[allowed & np.isclose(f1, best_f1)]
    return float(np.max(tied_thresholds))


@dataclass(frozen=True)
class MessageEvidenceMetrics:
    threshold: float
    true_positive: int
    false_negative: int
    false_positive: int
    true_negative: int
    malicious_precision: float
    malicious_recall: float
    false_negative_rate: float
    false_positive_rate: float
    malicious_f1: float
    macro_f1: float
    pr_auc: float
    roc_auc: float
    brier_score: float
    negative_log_loss: float
    ece_15: float


def message_evidence_metrics(
    labels: Sequence[int],
    probabilities: Sequence[float],
    *,
    threshold: float,
) -> MessageEvidenceMetrics:
    y = _labels(labels)
    p = _probabilities(probabilities)
    if len(y) != len(p):
        raise ValueError("labels and probabilities must have equal length")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be in [0, 1]")
    predicted = p >= threshold
    positive = y == 1
    negative = ~positive
    tp = int(np.sum(predicted & positive))
    fn = int(np.sum(~predicted & positive))
    fp = int(np.sum(predicted & negative))
    tn = int(np.sum(~predicted & negative))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1_positive = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    negative_precision = tn / (tn + fn) if tn + fn else 0.0
    negative_recall = tn / (tn + fp) if tn + fp else 0.0
    f1_negative = (
        2.0
        * negative_precision
        * negative_recall
        / (negative_precision + negative_recall)
        if negative_precision + negative_recall
        else 0.0
    )
    clipped = np.clip(p, 1e-15, 1.0 - 1e-15)
    return MessageEvidenceMetrics(
        threshold=float(threshold),
        true_positive=tp,
        false_negative=fn,
        false_positive=fp,
        true_negative=tn,
        malicious_precision=precision,
        malicious_recall=recall,
        false_negative_rate=1.0 - recall,
        false_positive_rate=fpr,
        malicious_f1=f1_positive,
        macro_f1=(f1_positive + f1_negative) / 2.0,
        pr_auc=float(average_precision_score(y, p)),
        roc_auc=float(roc_auc_score(y, p)),
        brier_score=float(np.mean((p - y) ** 2)),
        negative_log_loss=float(log_loss(y, clipped, labels=[0, 1])),
        ece_15=expected_calibration_error(y, p, bins=15),
    )


class PlattProbabilityCalibrator:
    def __init__(self) -> None:
        self._model = LogisticRegression(C=1.0, max_iter=1000, random_state=260825)

    @staticmethod
    def _logit(probabilities: Sequence[float]) -> np.ndarray:
        p = np.clip(_probabilities(probabilities), 1e-6, 1.0 - 1e-6)
        return np.log(p / (1.0 - p)).reshape(-1, 1)

    def fit(
        self, probabilities: Sequence[float], labels: Sequence[int]
    ) -> "PlattProbabilityCalibrator":
        y = _labels(labels)
        x = self._logit(probabilities)
        if len(x) != len(y):
            raise ValueError("labels and probabilities must have equal length")
        self._model.fit(x, y)
        return self

    def predict(self, probabilities: Sequence[float]) -> np.ndarray:
        return self._model.predict_proba(self._logit(probabilities))[:, 1]


class IsotonicProbabilityCalibrator:
    def __init__(self) -> None:
        self._model = IsotonicRegression(
            y_min=0.0, y_max=1.0, out_of_bounds="clip"
        )

    def fit(
        self, probabilities: Sequence[float], labels: Sequence[int]
    ) -> "IsotonicProbabilityCalibrator":
        p = _probabilities(probabilities)
        y = _labels(labels)
        if len(p) != len(y):
            raise ValueError("labels and probabilities must have equal length")
        self._model.fit(p, y)
        return self

    def predict(self, probabilities: Sequence[float]) -> np.ndarray:
        return np.asarray(self._model.predict(_probabilities(probabilities)))


def uncertainty_diagnostics(
    labels: Sequence[int],
    probabilities: Sequence[float],
    uncertainty: Sequence[float],
    *,
    threshold: float,
) -> dict[str, float]:
    y = _labels(labels)
    p = _probabilities(probabilities)
    u = np.asarray(uncertainty, dtype=float)
    if u.ndim != 1 or len(u) != len(y) or len(p) != len(y):
        raise ValueError("uncertainty, labels and probabilities must align")
    if not np.isfinite(u).all() or np.any(u < 0.0):
        raise ValueError("uncertainty must be finite and non-negative")
    errors = ((p >= threshold).astype(int) != y).astype(int)
    order = np.argsort(u, kind="stable")
    quintile = max(1, len(order) // 5)
    bottom = errors[order[:quintile]]
    top = errors[order[-quintile:]]
    if len(np.unique(errors)) == 2:
        error_auc = float(roc_auc_score(errors, u))
    else:
        error_auc = float("nan")
    return {
        "uncertainty_error_roc_auc": error_auc,
        "bottom_uncertainty_error_rate": float(bottom.mean()),
        "top_uncertainty_error_rate": float(top.mean()),
        "top_to_bottom_error_ratio": (
            float(top.mean() / bottom.mean())
            if bottom.mean() > 0.0
            else float("inf") if top.mean() > 0.0 else 1.0
        ),
        "mean_uncertainty": float(u.mean()),
    }
