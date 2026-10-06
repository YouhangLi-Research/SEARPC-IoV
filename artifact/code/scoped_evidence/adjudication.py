"""Deterministic scoped evidence adjudication-channel perturbations for sensitivity tests."""
from __future__ import annotations
import hashlib

def deterministic_uniform(*parts) -> float:
    h=hashlib.sha256('|'.join(map(str,parts)).encode('utf-8')).digest()
    return int.from_bytes(h[:8],'big') / 2**64

def perturb_binary_truth(truth:float, *, seed:int, event_index:int, error_rate:float, tag:str) -> float:
    if not 0.0 <= error_rate <= 1.0:
        raise ValueError(error_rate)
    if error_rate and deterministic_uniform('adjudication',tag,seed,event_index) < error_rate:
        return 1.0-float(truth)
    return float(truth)
