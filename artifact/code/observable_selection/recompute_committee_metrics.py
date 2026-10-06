#!/usr/bin/env python3
"""Recompute observable selection committee metrics with separated latent and observable events."""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = ROOT / "results" / "observable_selection" / "rq4_observable"


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        raise ValueError("no rows")
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)


def _i(row, key): return int(float(row.get(key, 0) or 0))
def _f(row, key): return float(row.get(key, 0) or 0)


def augment(rows: list[dict]) -> list[dict]:
    out=[]
    for raw in rows:
        r=dict(raw)
        method=r["method"]
        resampled=_i(r,"resampled")
        pmax=_i(r,"primary_warning_max")
        content_high=r.get("content_level") == "high"
        fast_attempt=_i(r,"fast_attempt")
        direct=_i(r,"direct_full")
        handoff=_i(r,"fallback")  # legacy field now comes from observable controller
        warning_resample=0; content_resample=0
        if resampled:
            if method == "committee_dual_axis" and content_high and pmax == 1:
                content_resample=1
            else:
                warning_resample=1
        r.update({
            "latent_initial_exceedance": _i(r,"primary_fast_breach"),
            "latent_final_exceedance": _i(r,"selected_fast_breach"),
            "warning_triggered_resampling": warning_resample,
            "content_triggered_resampling": content_resample,
            # In the frozen observable selection simulation, collectors/blocks/hints are valid;
            # the only attempted-fast failure mode is insufficient legal shares
            # before the deadline. This is an observable timeout event.
            "hint_assembly_timeout": int(bool(handoff and fast_attempt)),
            "invalid_hint": 0,
            "block_unavailable": 0,
            "direct_standard": direct,
            "actual_handoff": int(bool(handoff and fast_attempt)),
            "fallback_total": direct + int(bool(handoff and fast_attempt)),
            "finalizer_rejection": _i(r,"final_refusal"),
        })
        out.append(r)
    return out


def summarize(rows: list[dict]) -> list[dict]:
    groups=defaultdict(list)
    for r in rows: groups[r["method"]].append(r)
    out=[]
    for method in sorted(groups):
        sub=groups[method]; n=len(sub)
        def avg(k): return sum(_f(r,k) for r in sub)/n
        latent=[r for r in sub if _i(r,"latent_initial_exceedance")]
        hand=[r for r in sub if _i(r,"actual_handoff")]
        both=sum(_i(r,"actual_handoff") and _i(r,"latent_initial_exceedance") for r in sub)
        risk=sum(_f(r,"risk_score") for r in sub)
        out.append({
            "method":method,
            "blocks":n,
            "latent_initial_exceedance_rate":avg("latent_initial_exceedance"),
            "latent_final_exceedance_rate":avg("latent_final_exceedance"),
            "warning_triggered_resampling_rate":avg("warning_triggered_resampling"),
            "content_triggered_resampling_rate":avg("content_triggered_resampling"),
            "hint_assembly_timeout_rate":avg("hint_assembly_timeout"),
            "invalid_hint_rate":avg("invalid_hint"),
            "block_unavailable_rate":avg("block_unavailable"),
            "direct_standard_rate":avg("direct_standard"),
            "actual_handoff_rate":avg("actual_handoff"),
            "fallback_total_rate":avg("fallback_total"),
            "p_handoff_given_latent_exceedance": both/len(latent) if latent else 0.0,
            "p_latent_exceedance_given_handoff": both/len(hand) if hand else 0.0,
            "risk_weighted_latent_final_exposure": (
                sum(_f(r,"risk_score")*_i(r,"latent_final_exceedance") for r in sub)/risk if risk else 0.0
            ),
            "final_legal_commit_rate":avg("final_legal_commit"),
            "final_illegal_acceptance_rate":avg("final_illegal_acceptance"),
            "finalizer_rejection_rate":avg("finalizer_rejection"),
            "mean_active_pool":avg("active_pool"),
            "mean_total_wire_messages":avg("total_wire_messages"),
        })
    return out


def handoff_trace(rows: list[dict]) -> list[dict]:
    out=[]
    for r in rows:
        if not _i(r,"actual_handoff"):
            continue
        out.append({
            "repeat":r["repeat"], "attack":r["attack"], "seed":r["seed"],
            "block":r["block"], "method":r["method"],
            "observable_trigger":"hint_assembly_timeout",
            "primary_warning_max":r.get("primary_warning_max","0"),
            "resampled":r.get("resampled","0"),
            "selected_member_ids":r.get("selected_member_ids","") or r.get("primary_member_ids",""),
            "latent_final_exceedance_offline":r["latent_final_exceedance"],
            "final_Q_fixed":"27",
        })
    return out


def main(folder: Path=DEFAULT_DIR):
    source=folder/"DURAC_phase16_block_level.csv"
    rows=augment(read_csv(source))
    write_csv(folder/"DURAC_observable_selection_committee_block_level.csv", rows)
    write_csv(folder/"DURAC_observable_selection_committee_summary.csv", summarize(rows))
    ht=handoff_trace(rows)
    if ht: write_csv(folder/"HANDOFF_TRIGGER_TRACE.csv", ht)
    print(f"wrote {len(rows)} block rows; handoffs={len(ht)}")

if __name__ == "__main__": main()
