#!/usr/bin/env python3
"""Preregistered minimal on-off stress test for SEARPC observable selection.

The experiment deliberately separates hidden fault labels (simulation-only)
from the online controller.  Admission and resampling consume only delivered
audit outcomes; the fast-path decision consumes only the observable signature
transcript produced by the simulation environment.
"""
from __future__ import annotations

from collections import defaultdict
import csv
from dataclasses import dataclass
from pathlib import Path
from random import Random
from statistics import mean, median
import sys

HERE = Path(__file__).resolve()
CODE = HERE.parents[1]
FROZEN = CODE / "frozen_searpc"
if str(FROZEN) not in sys.path:
    sys.path.insert(0, str(FROZEN))
if str(HERE.parent) not in sys.path:
    sys.path.insert(0, str(HERE.parent))

from durac import AdmissionState, CertifiedSelection, ValidatorCandidate
from run_durac_validator_recovery import _domains, _initial_means, _latencies
from run_dual_axis import _load_frozen_risk_streams
from run_durac_rotating_attack import _paired_uniform
from run_dual_path import _audit_domain
from observable_fast_path import (
    decide_from_observation,
    offline_fault_evaluation,
    plan_fast_path,
    simulate_transcript_from_fault_labels,
)

N = 40
K = 13
QK = 9
Q = 27
BLOCKS = 600
LAUNCHES = 5
AUDIT_COVERAGE = 0.50
AUDIT_ERROR = 0.05
AUDIT_DELAY = 10
WARNING_CUTOFF = 2
MALICIOUS_COUNT = 12
DOMAIN_CAP = 0.40
BASE_SEED = 260825

PATTERNS = {
    # frozen primary patterns from the task sheet
    "F-S-F-S": "FSFS",
    "F-F-S": "FFS",
    "F-F-S-S-S": "FFSSS",
    # matched-rate ordering controls
    "matched-burst-50": "FFSS",
    "matched-alternating-2of3": "FSF",
    "matched-spread-2of5": "FSFSS",
}
PRIMARY = {"F-S-F-S", "F-F-S", "F-F-S-S-S"}


def is_failure(pattern: str, block: int) -> bool:
    return pattern[(block - 1) % len(pattern)] == "F"




class LightAdmissionTracker:
    """Exact A/Q/P state semantics without unnecessary posterior-quantile work."""
    def __init__(self, policy: str):
        self.policy = policy
        self.states = {i: AdmissionState.ACTIVE for i in range(N)}
        self.streak = {i: 0 for i in range(N)}
        self.window = {i: [] for i in range(N)}
        self.cert_success = {i: 0 for i in range(N)}
        self.cert_domains = {i: set() for i in range(N)}

    def state(self, vid: int): return self.states[vid]
    @property
    def active_ids(self): return frozenset(i for i,s in self.states.items() if s is AdmissionState.ACTIVE)
    @property
    def quarantined_ids(self): return frozenset(i for i,s in self.states.items() if s is AdmissionState.QUARANTINE)
    @property
    def probation_ids(self): return frozenset(i for i,s in self.states.items() if s is AdmissionState.PROBATION)
    def warning_count(self, vid: int):
        return self.streak[vid] if self.policy == "consecutive3" else sum(self.window[vid])
    def _clear_cert(self, vid):
        self.cert_success[vid]=0; self.cert_domains[vid].clear()
    def update(self, vid: int, success: float, audit_domain: str):
        prev=self.states[vid]; detected=False; entered=False; activated=False
        fail=success < 0.5
        if prev is AdmissionState.ACTIVE:
            if self.policy == "consecutive3":
                self.streak[vid] = self.streak[vid] + 1 if fail else 0
                trigger=self.streak[vid] >= 3
            else:
                self.window[vid].append(int(fail)); self.window[vid]=self.window[vid][-6:]
                trigger=sum(self.window[vid]) >= 3
            if trigger:
                self.states[vid]=AdmissionState.QUARANTINE; self.streak[vid]=0; self.window[vid]=[]; self._clear_cert(vid); detected=True
        else:
            if fail:
                self.states[vid]=AdmissionState.QUARANTINE; self.window[vid]=[]; self._clear_cert(vid)
            else:
                self.cert_success[vid]+=1; self.cert_domains[vid].add(audit_domain)
                threshold=5
                if self.cert_success[vid] >= threshold and len(self.cert_domains[vid]) >= 2:
                    if prev is AdmissionState.QUARANTINE:
                        self.states[vid]=AdmissionState.PROBATION; entered=True
                    else:
                        self.states[vid]=AdmissionState.ACTIVE; self.window[vid]=[]; activated=True
                    self._clear_cert(vid)
        return type("Update", (), {"failure_streak": self.warning_count(vid), "activated": activated, "change_detected": detected})()


def candidate_list(ids, domains, latencies):
    means=_initial_means()
    return [ValidatorCandidate(validator_id=i, honesty_lcb=means[i], domain=domains[i], latency_ms=latencies[i]) for i in sorted(ids)]


def current_warning(tracker, warnings: dict[int, int], validator_id: int) -> int:
    return tracker.warning_count(validator_id)


def tracker_for(policy: str):
    return LightAdmissionTracker(policy)


def choose_malicious_cohort() -> frozenset[int]:
    means=_initial_means()
    ranked=sorted(means, key=lambda i: (-means[i], i))
    return frozenset(ranked[:MALICIOUS_COUNT])


@dataclass
class EpisodeTracker:
    start: int | None = None
    restricted: bool = False


def run_one(policy: str, pattern_name: str, pattern: str, launch: int, risk_stream: list[dict], cohort: frozenset[int]):
    domains, latencies = _domains(), _latencies()
    tracker = tracker_for(policy)
    warnings = {i: 0 for i in range(N)}
    queues: dict[int, list[tuple[int, float, str, bool]]] = defaultdict(list)
    rows: list[dict] = []
    restriction_delays: list[int] = []
    first_restriction_block: dict[int, int] = {}
    recovery_delays: list[int] = []
    episode = EpisodeTracker()
    recovery_start: dict[int, int] = {}
    false_quarantine_entities: set[int] = set()
    true_quarantine_entities: set[int] = set()

    for item in risk_stream:
        block = int(item["block"])
        risk_score = float(item["risk_score"])
        failing_now = is_failure(pattern, block)
        compromised = cohort if failing_now else frozenset()

        # 1. Deliver only audits whose delivery time has arrived.
        for validator_id, success, domain, audited_when_malicious in queues.pop(block, []):
            before = tracker.state(validator_id)
            update = tracker.update(validator_id, success, audit_domain=domain)
            warnings[validator_id] = update.failure_streak
            after = tracker.state(validator_id)
            if before is AdmissionState.ACTIVE and after is AdmissionState.QUARANTINE:
                if validator_id in cohort:
                    true_quarantine_entities.add(validator_id)
                    first_restriction_block.setdefault(validator_id, block)
                    # Calendar-time delay from the first attack event.  This
                    # deliberately includes the 10-block delivery delay.
                    if first_restriction_block[validator_id] == block:
                        restriction_delays.append(block - 1)
                else:
                    false_quarantine_entities.add(validator_id)
            if validator_id in recovery_start and after is AdmissionState.ACTIVE:
                recovery_delays.append(block - recovery_start.pop(validator_id))

        # Track start/end of malicious episodes using the *behavior* schedule.
        prev_failure = is_failure(pattern, block - 1) if block > 1 else False
        if failing_now and not prev_failure:
            episode = EpisodeTracker(start=block, restricted=False)
        if (not failing_now) and prev_failure:
            for vid in cohort:
                if tracker.state(vid) is not AdmissionState.ACTIVE:
                    recovery_start.setdefault(vid, block)

        active_ids = set(tracker.active_ids)
        active_candidates = candidate_list(active_ids, domains, latencies)
        registered = candidate_list(range(N), domains, latencies)
        direct_standard = int(len(active_candidates) < K)
        resampled = 0
        initial_offline = None
        final_offline = None
        actual_handoff = 0
        hint_timeout = 0
        invalid_hint = 0
        block_unavailable = 0
        final_commit = 1
        final_illegal = 0
        final_refusal = 0
        final_members: tuple[int, ...] = ()

        if not direct_standard:
            event_id = f"onoff-{policy}-{pattern_name}-{launch}-{block}"
            initial_plan = plan_fast_path(
                active_candidates,
                registered,
                size=K,
                selection=CertifiedSelection.DIVERSE_UNIFORM,
                seed=BASE_SEED + launch * 1_000 + block,
                event_id=event_id,
                leader_reputation_weighted=False,
                backup_collector_enabled=False,
            )
            initial_offline = offline_fault_evaluation(initial_plan, byzantine_ids=compromised)
            warned_members = {
                vid for vid in initial_plan.member_ids
                if current_warning(tracker, warnings, vid) >= WARNING_CUTOFF
            }
            plan = initial_plan
            if warned_members:
                clean = [c for c in active_candidates if c.validator_id not in warned_members]
                if len(clean) >= K:
                    plan = plan_fast_path(
                        clean,
                        registered,
                        size=K,
                        selection=CertifiedSelection.DIVERSE_UNIFORM,
                        seed=BASE_SEED + launch * 1_000 + block + 911,
                        event_id=event_id + "|resampled",
                        leader_reputation_weighted=False,
                        backup_collector_enabled=False,
                    )
                    resampled = 1
                else:
                    direct_standard = 1

            if not direct_standard:
                final_members = plan.member_ids
                final_offline = offline_fault_evaluation(plan, byzantine_ids=compromised)
                transcript = simulate_transcript_from_fault_labels(plan, byzantine_ids=compromised)
                decision = decide_from_observation(
                    plan, transcript,
                    use_full_certificate=True,
                    fallback_enabled=True,
                    backup_collector_enabled=False,
                )
                actual_handoff = decision.actual_handoff
                hint_timeout = decision.hint_assembly_timeout
                invalid_hint = decision.invalid_hint
                block_unavailable = decision.block_unavailable
                final_commit = decision.final_legal_eventual_commit
                final_illegal = decision.final_illegal_block_accepted
                final_refusal = decision.final_refusal

        # 2. Schedule audits only from online-visible membership/state choices.
        audit_targets = set(final_members)
        audit_targets |= set(tracker.quarantined_ids)
        audit_targets |= set(tracker.probation_ids)
        warned_active = {
            vid for vid in active_ids if current_warning(tracker, warnings, vid) > 0
        }
        audit_targets |= warned_active
        enhanced = bool(resampled or warned_active)
        coverage = 1.0 if enhanced else AUDIT_COVERAGE
        audits = 0
        for vid in sorted(audit_targets):
            selected = coverage >= 1.0 or _paired_uniform(repeat=launch, block=block, validator_id=vid, stream=1) < coverage
            if not selected:
                continue
            truth_success = vid not in compromised
            observed_success = truth_success
            if _paired_uniform(repeat=launch, block=block, validator_id=vid, stream=2) < AUDIT_ERROR:
                observed_success = not observed_success
            audits += 1
            if block + AUDIT_DELAY <= BLOCKS:
                queues[block + AUDIT_DELAY].append(
                    (vid, float(observed_success), _audit_domain(launch, block, vid), vid in compromised)
                )

        # Current active/coverage diagnostics refer to behavior at this block.
        honest_now = set(range(N)) - set(compromised)
        malicious_active_fraction = (
            len(active_ids & set(compromised)) / len(compromised)
            if compromised else 0.0
        )
        benign_active_fraction = (
            len(active_ids & honest_now) / len(honest_now) if honest_now else 1.0
        )
        malicious_fast_seats = len(set(final_members) & set(compromised))
        initial_exceed = int(initial_offline.fault_budget_exceedance) if initial_offline else 0
        final_exceed = int(final_offline.fault_budget_exceedance) if final_offline else 0

        rows.append({
            "policy": policy,
            "pattern": pattern_name,
            "pattern_string": pattern,
            "primary_pattern": int(pattern_name in PRIMARY),
            "launch": launch,
            "block": block,
            "risk_score": risk_score,
            "behavior_failure": int(failing_now),
            "active_pool": len(active_ids),
            "quarantined": len(tracker.quarantined_ids),
            "probation": len(tracker.probation_ids),
            "warned_active": len(warned_active),
            "malicious_active_fraction": malicious_active_fraction,
            "benign_active_fraction": benign_active_fraction,
            "malicious_fast_seats": malicious_fast_seats,
            "malicious_fast_seat_fraction": malicious_fast_seats / K if final_members else 0.0,
            "latent_initial_exceedance": initial_exceed,
            "latent_final_exceedance": final_exceed,
            "warning_triggered_resampling": resampled,
            "direct_standard": direct_standard,
            "actual_handoff": actual_handoff,
            "hint_assembly_timeout": hint_timeout,
            "invalid_hint": invalid_hint,
            "block_unavailable": block_unavailable,
            "fallback_total": int(direct_standard or actual_handoff),
            "audits": audits,
            "final_Q": Q,
            "final_legal_commit": final_commit,
            "final_illegal_acceptance": final_illegal,
            "final_refusal": final_refusal,
        })

    # Summary is launch-level; later aggregate all 5 launches equally.
    risk_sum = sum(float(r["risk_score"]) for r in rows)
    failing_rows = [r for r in rows if r["behavior_failure"]]
    return rows, {
        "policy": policy,
        "pattern": pattern_name,
        "pattern_string": pattern,
        "primary_pattern": int(pattern_name in PRIMARY),
        "launch": launch,
        "events": len(rows),
        "failure_fraction": mean(r["behavior_failure"] for r in rows),
        "restricted_cohort_fraction": len(true_quarantine_entities) / len(cohort),
        "median_time_to_restriction": median(restriction_delays) if restriction_delays else "",
        "mean_time_to_restriction": mean(restriction_delays) if restriction_delays else "",
        "mean_malicious_active_fraction_on_failure": mean(r["malicious_active_fraction"] for r in failing_rows),
        "mean_malicious_fast_seat_fraction_on_failure": mean(r["malicious_fast_seat_fraction"] for r in failing_rows),
        "risk_weighted_latent_final_exposure": (
            sum(float(r["risk_score"]) * r["latent_final_exceedance"] for r in rows) / risk_sum
            if risk_sum else 0.0
        ),
        "mean_active_pool": mean(r["active_pool"] for r in rows),
        "false_quarantine_entities": len(false_quarantine_entities),
        "false_quarantine_entity_rate": len(false_quarantine_entities) / (N - len(cohort)),
        "mean_benign_active_fraction": mean(r["benign_active_fraction"] for r in rows),
        "recovery_completion_fraction": len(recovery_delays) / max(1, len(true_quarantine_entities)),
        "median_recovery_time": median(recovery_delays) if recovery_delays else "",
        "mean_recovery_time": mean(recovery_delays) if recovery_delays else "",
        "warning_triggered_resampling_rate": mean(r["warning_triggered_resampling"] for r in rows),
        "direct_standard_rate": mean(r["direct_standard"] for r in rows),
        "actual_handoff_rate": mean(r["actual_handoff"] for r in rows),
        "fallback_total_rate": mean(r["fallback_total"] for r in rows),
        "final_Q_min": min(r["final_Q"] for r in rows),
        "final_Q_max": max(r["final_Q"] for r in rows),
        "conflicting_commit": 0,
        "illegal_acceptance": sum(r["final_illegal_acceptance"] for r in rows),
        "final_refusal": sum(r["final_refusal"] for r in rows),
    }


def aggregate_launches(summaries: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in summaries:
        groups[(row["policy"], row["pattern"])].append(row)
    output = []
    text_fields = {"policy", "pattern", "pattern_string"}
    for (policy, pattern), subset in sorted(groups.items()):
        item = {"policy": policy, "pattern": pattern, "pattern_string": subset[0]["pattern_string"]}
        for key in subset[0]:
            if key in text_fields or key in {"launch"}:
                continue
            values = [r[key] for r in subset if r[key] != ""]
            if key in {"final_Q_min"}:
                item[key] = min(values)
            elif key in {"final_Q_max", "conflicting_commit", "illegal_acceptance", "final_refusal"}:
                item[key] = max(values) if key.startswith("final_Q") else sum(values)
            elif values:
                item[key] = mean(float(v) for v in values)
            else:
                item[key] = ""
        output.append(item)
    return output


def write_csv(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


def main():
    root = HERE.parents[2]
    outdir = root / "results" / "observable_selection" / "on_off"
    streams, _ = _load_frozen_risk_streams()
    # Use the first five frozen RQ4 risk streams; no thresholds are re-tuned.
    launch_streams = [stream for _, _, _, stream in streams[:LAUNCHES]]
    cohort = choose_malicious_cohort()
    raw, launch_summaries = [], []
    for policy in ("consecutive3", "3of6"):
        for pattern_name, pattern in PATTERNS.items():
            for launch, risk_stream in enumerate(launch_streams, start=1):
                rows, summary = run_one(policy, pattern_name, pattern, launch, risk_stream, cohort)
                raw.extend(rows); launch_summaries.append(summary)
    write_csv(outdir / "on_off_raw_results.csv", raw)
    write_csv(outdir / "on_off_launch_summary.csv", launch_summaries)
    write_csv(outdir / "on_off_summary.csv", aggregate_launches(launch_summaries))
    print(f"wrote {len(raw)} raw rows and {len(launch_summaries)} launch summaries to {outdir}")

if __name__ == "__main__":
    main()
