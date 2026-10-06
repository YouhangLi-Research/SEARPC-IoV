#!/usr/bin/env python3
"""Localhost candidate-reconfiguration and fixed-quorum certificate prototype.

The selector uses a deterministic warning schedule to isolate execution cost.
Canonical audit delivery and the validator lifecycle are evaluated separately
in the paired protocol trajectories. This prototype supplies no BFT locking
or view-change state machine.
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
import csv
import hashlib
import json
import multiprocessing as mp
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

THIS = Path(__file__).resolve()
EXPERIMENT_ROOT = THIS.parents[2]
FROZEN_ROOT = EXPERIMENT_ROOT / "code" / "frozen_searpc"
sys.path.insert(0, str(FROZEN_ROOT))
from run_process_prototype import committee_for

ROOT = EXPERIMENT_ROOT
OUT = ROOT / "results" / "scoped_evidence" / "rq5_extended"
PROTOCOL = ROOT / "protocols" / "frozen" / "SEARPC_FULL_FINALITY_PROTOCOL.md"
EVIDENCE_PROTOCOL = ROOT / "protocols" / "scoped_evidence" / "SCOPED_EVIDENCE_PROTOCOL.md"
HEADER = struct.Struct("!I")
METHODS = ("full_set", "fixed_k13", "searpc_conditioned")
AVAILABILITY = ("cached", "fetch")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ConnectionError("socket closed")
        chunks.extend(part)
    return bytes(chunks)


def _recv_frame(sock: socket.socket) -> tuple[bytes, int]:
    header = _recv_exact(sock, HEADER.size)
    size = HEADER.unpack(header)[0]
    return _recv_exact(sock, size), HEADER.size + size


def _send_frame(sock: socket.socket, payload: bytes) -> int:
    frame = HEADER.pack(len(payload)) + payload
    sock.sendall(frame)
    return len(frame)


def _qc_hash(qc: list[list[object]]) -> bytes:
    return hashlib.sha256(json.dumps(qc, separators=(",", ":")).encode()).digest()


@dataclass(frozen=True)
class CertificatePolicy:
    """Certificate requirements installed by the local experiment controller."""

    digest_hex: str
    signer_ids: frozenset[int]
    quorum: int


def _install_policy(clients: list["PersistentClient"], digest: bytes, members: list[int]) -> None:
    """Provision trusted local state outside the network request channel."""
    n = len(clients)
    if len(digest) != 32 or not members or len(set(members)) != len(members):
        raise ValueError("invalid local certificate policy")
    if any(type(member) is not int or not 0 <= member < n for member in members):
        raise ValueError("invalid locally configured member")
    members_set = set(members)
    values = [_quorum(len(members)), *digest, *(int(i in members_set) for i in range(n))]
    state = clients[0].policy_state
    with state.get_lock():
        state[:] = values


def _read_policy(state) -> CertificatePolicy | None:
    with state.get_lock():
        values = list(state[:])
    if values[0] == 0:
        return None
    return CertificatePolicy(
        bytes(values[1:33]).hex(),
        frozenset(i for i, enabled in enumerate(values[33:]) if enabled),
        int(values[0]),
    )


def _verify_qc(
    publics: list[Ed25519PublicKey],
    qc: list[list[object]],
    message: bytes,
    quorum: int,
    *,
    allowed_signers: frozenset[int] | None = None,
) -> None:
    if type(quorum) is not int or not 1 <= quorum <= len(publics):
        raise ValueError("invalid certificate quorum")
    permitted = frozenset(range(len(publics))) if allowed_signers is None else allowed_signers
    if len(permitted) < quorum or any(type(i) is not int or not 0 <= i < len(publics) for i in permitted):
        raise ValueError("invalid certificate signer configuration")
    if not isinstance(qc, list):
        raise ValueError("invalid certificate encoding")
    signers = set()
    for item in qc:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError("invalid certificate entry")
        signer, signature_hex = item
        if type(signer) is not int or not 0 <= signer < len(publics):
            raise ValueError("invalid signer")
        if signer not in permitted:
            raise ValueError("signer outside configured candidate set")
        if signer in signers:
            raise ValueError("duplicate signer")
        if not isinstance(signature_hex, str):
            raise ValueError("invalid signature encoding")
        signature = bytes.fromhex(signature_hex)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        publics[signer].verify(signature, message)
        signers.add(signer)
    if len(signers) < quorum:
        raise ValueError("certificate below quorum")


def _handle_request(
    request: dict,
    private: Ed25519PrivateKey,
    publics: list[Ed25519PublicKey],
    blocks: dict[str, bytes],
    *,
    policy: CertificatePolicy | None = None,
) -> dict:
    phase = str(request.get("phase", ""))
    digest_hex = str(request.get("digest", ""))
    try:
        digest = bytes.fromhex(digest_hex)
    except ValueError:
        return {"error": "invalid_digest"}
    payload_hex = request.get("payload")
    if payload_hex is not None:
        try:
            payload = bytes.fromhex(str(payload_hex))
        except ValueError:
            return {"error": "invalid_payload_encoding"}
        if hashlib.sha256(payload).digest() != digest:
            return {"error": "payload_digest_mismatch"}
        blocks[digest_hex] = payload
        if len(blocks) > 256:
            blocks.pop(next(iter(blocks)))

    if phase == "cache":
        return {"cached": digest_hex in blocks}
    if phase == "availability":
        return {"available": digest_hex in blocks}
    if digest_hex not in blocks:
        return {"error": "missing_block"}
    if policy is None or policy.digest_hex != digest_hex:
        return {"error": "missing_local_policy"}
    if type(policy.quorum) is not int or policy.quorum != _quorum(len(policy.signer_ids)):
        return {"error": "invalid_local_policy"}
    if phase in {"commit", "finality"}:
        supplied_quorum = request.get("quorum")
        if type(supplied_quorum) is not int or supplied_quorum != policy.quorum:
            return {"error": "quorum_mismatch"}
    if phase == "prepare":
        signed = b"prepare:" + digest
    elif phase == "commit":
        prepare_qc = request.get("prepare_qc", [])
        quorum = policy.quorum
        try:
            _verify_qc(publics, prepare_qc, b"prepare:" + digest, quorum, allowed_signers=policy.signer_ids)
        except (ValueError, TypeError, InvalidSignature):
            return {"error": "invalid_prepare_qc"}
        signed = b"commit:" + digest + _qc_hash(prepare_qc)
    elif phase == "finality":
        commit_qc = request.get("commit_qc", [])
        quorum = policy.quorum
        prepare_qc = request.get("prepare_qc", [])
        try:
            commit_message = b"commit:" + digest + _qc_hash(prepare_qc)
            _verify_qc(publics, commit_qc, commit_message, quorum, allowed_signers=policy.signer_ids)
        except (ValueError, TypeError, InvalidSignature):
            return {"error": "invalid_commit_qc"}
        signed = b"finality:" + digest + _qc_hash(commit_qc)
    else:
        return {"error": "unknown_phase"}
    return {"signature": private.sign(signed).hex()}


def worker_main(private_raw: bytes, public_raws: list[bytes], ready, stop, policy_state) -> None:
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    publics = [Ed25519PublicKey.from_public_bytes(item) for item in public_raws]
    blocks: dict[str, bytes] = {}
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(2)
    server.settimeout(0.2)
    ready.send(server.getsockname()[1])
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        conn.settimeout(0.2)
        with conn:
            while not stop.is_set():
                try:
                    raw, _ = _recv_frame(conn)
                except socket.timeout:
                    continue
                except (ConnectionError, OSError):
                    break
                try:
                    request = json.loads(raw)
                    policy = _read_policy(policy_state) if request.get("phase") in {"prepare", "commit", "finality"} else None
                    response = _handle_request(request, private, publics, blocks, policy=policy)
                except Exception as exc:  # defensive isolation of a validator process
                    response = {"error": type(exc).__name__}
                try:
                    _send_frame(conn, json.dumps(response, separators=(",", ":")).encode())
                except OSError:
                    break
    server.close()


class PersistentClient:
    def __init__(self, port: int, policy_state):
        self.policy_state = policy_state
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
        self.sock.settimeout(5.0)
        self.lock = threading.Lock()

    def call(self, body: dict) -> tuple[dict, int]:
        payload = json.dumps(body, separators=(",", ":")).encode()
        with self.lock:
            sent = _send_frame(self.sock, payload)
            response_raw, received = _recv_frame(self.sock)
        return json.loads(response_raw), sent + received

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def _quorum(n: int) -> int:
    return 2 * ((n - 1) // 3) + 1


def _call_many(
    clients: list[PersistentClient],
    executor: ThreadPoolExecutor,
    members: list[int],
    body_for,
) -> tuple[list[tuple[int, dict]], int]:
    futures = [(member, executor.submit(clients[member].call, body_for(member))) for member in members]
    replies = []
    wire = 0
    for member, future in futures:
        response, used = future.result()
        replies.append((member, response))
        wire += used
    return replies, wire


def _signatures(
    replies: list[tuple[int, dict]],
    publics: list[Ed25519PublicKey],
    message: bytes,
) -> list[list[object]]:
    qc = []
    for member, response in replies:
        if "signature" not in response:
            continue
        signature_hex = str(response["signature"])
        publics[member].verify(bytes.fromhex(signature_hex), message)
        qc.append([member, signature_hex])
    return qc


@dataclass
class BlockResult:
    process_count: int
    payload_bytes: int
    method: str
    availability: str
    repeat: int
    block: int
    committed: int
    final_signature_count: int
    final_quorum: int
    certificate_latency_ms: float
    accounted_latency_ms: float
    total_wire_bytes: int
    availability_wire_bytes: int
    on_demand_availability_wire_bytes: int
    certificate_wire_bytes: int
    signatures_generated: int
    fetch_count: int
    resampled: int
    selection_us: float
    backup_used: int
    fallback_used: int


def run_block(
    clients: list[PersistentClient],
    publics: list[Ed25519PublicKey],
    executor: ThreadPoolExecutor,
    method: str,
    availability: str,
    repeat: int,
    block: int,
    payload_size: int,
    *,
    force_handoff_probe: bool = False,
    force_fallback: bool = False,
) -> BlockResult:
    n = len(clients)
    final_quorum = _quorum(n)
    selector_method = "durac_conditioned" if method == "searpc_conditioned" else method
    committee, resampled, selection_us = committee_for(selector_method, n, block)
    fast_quorum = _quorum(len(committee))
    fast_signers = committee[:fast_quorum]
    payload = hashlib.shake_256(f"phase22:{repeat}:{block}".encode()).digest(payload_size)
    digest = hashlib.sha256(payload).digest()
    digest_hex = digest.hex()
    payload_hex = payload.hex()
    _install_policy(clients, digest, committee)
    total_started = time.perf_counter_ns()
    availability_wire = 0
    on_demand_availability_wire = 0

    initial_holders = list(range(n)) if availability == "cached" else committee
    cache_body = {"phase": "cache", "digest": digest_hex, "payload": payload_hex}
    cached, used = _call_many(clients, executor, initial_holders, lambda _: cache_body)
    if not all(reply.get("cached") for _, reply in cached):
        raise RuntimeError("candidate data distribution failed")
    availability_wire += used

    certificate_started = time.perf_counter_ns()
    prepare_body = {"phase": "prepare", "digest": digest_hex}
    prepared, prepare_wire = _call_many(clients, executor, fast_signers, lambda _: prepare_body)
    prepare_qc = _signatures(prepared, publics, b"prepare:" + digest)
    if len(prepare_qc) != fast_quorum:
        raise RuntimeError("prepare quorum failed")
    commit_body = {"phase": "commit", "digest": digest_hex, "prepare_qc": prepare_qc, "quorum": fast_quorum}
    committed, commit_wire = _call_many(clients, executor, fast_signers, lambda _: commit_body)
    commit_message = b"commit:" + digest + _qc_hash(prepare_qc)
    commit_qc = _signatures(committed, publics, commit_message)
    if len(commit_qc) != fast_quorum:
        raise RuntimeError("commit quorum failed")
    certificate_wire = prepare_wire + commit_wire
    signatures_generated = len(prepare_qc) + len(commit_qc)
    fetch_count = 0
    fallback_used = int(force_fallback and method != "full_set")

    if method == "full_set" or fallback_used:
        if fallback_used:
            fallback_members = list(range(n))
            _install_policy(clients, digest, fallback_members)
            fallback_signers = fallback_members[:final_quorum]
            cached, used = _call_many(clients, executor, fallback_signers, lambda _: cache_body)
            if not all(reply.get("cached") for _, reply in cached):
                raise RuntimeError("fallback data distribution failed")
            availability_wire += used
            prepared, used = _call_many(clients, executor, fallback_signers, lambda _: prepare_body)
            fallback_prepare = _signatures(prepared, publics, b"prepare:" + digest)
            certificate_wire += used
            fallback_commit_body = {"phase": "commit", "digest": digest_hex, "prepare_qc": fallback_prepare, "quorum": final_quorum}
            committed, used = _call_many(clients, executor, fallback_signers, lambda _: fallback_commit_body)
            final_qc = _signatures(committed, publics, b"commit:" + digest + _qc_hash(fallback_prepare))
            certificate_wire += used
            signatures_generated += len(fallback_prepare) + len(final_qc)
        else:
            final_qc = commit_qc
    else:
        final_members = fast_signers + [member for member in range(n) if member not in fast_signers][: final_quorum - fast_quorum]
        finality_message = b"finality:" + digest + _qc_hash(commit_qc)

        def final_body(member: int) -> dict:
            nonlocal fetch_count
            body = {
                "phase": "finality",
                "digest": digest_hex,
                "prepare_qc": prepare_qc,
                "commit_qc": commit_qc,
                "quorum": fast_quorum,
            }
            if availability == "fetch" and member not in committee:
                body["payload"] = payload_hex
            return body

        if availability == "fetch":
            missing = [member for member in final_members if member not in committee]
            probes, probe_wire = _call_many(
                clients,
                executor,
                missing,
                lambda _: {"phase": "availability", "digest": digest_hex},
            )
            if any(reply.get("available") for _, reply in probes):
                raise RuntimeError("a non-committee fetch target unexpectedly had the block")
            availability_wire += probe_wire
            fetch_count = len(missing)
        finalized, finality_wire = _call_many(clients, executor, final_members, final_body)
        if availability == "fetch":
            for member in missing:
                with_payload = final_body(member)
                without_payload = dict(with_payload)
                without_payload.pop("payload", None)
                payload_increment = len(
                    json.dumps(with_payload, separators=(",", ":")).encode()
                ) - len(json.dumps(without_payload, separators=(",", ":")).encode())
                availability_wire += payload_increment
                on_demand_availability_wire += payload_increment
                finality_wire -= payload_increment
        final_qc = _signatures(finalized, publics, finality_message)
        certificate_wire += finality_wire
    if len(final_qc) != final_quorum:
        raise RuntimeError(f"final certificate has {len(final_qc)} signatures, expected {final_quorum}")

    certificate_latency = (time.perf_counter_ns() - certificate_started) / 1_000_000.0
    accounted_latency = (time.perf_counter_ns() - total_started) / 1_000_000.0
    return BlockResult(
        n,
        payload_size,
        method,
        availability,
        repeat,
        block,
        1,
        len(final_qc),
        final_quorum,
        certificate_latency,
        accounted_latency,
        availability_wire + certificate_wire,
        availability_wire,
        on_demand_availability_wire,
        certificate_wire,
        signatures_generated + (0 if method == "full_set" or fallback_used else len(final_qc)),
        fetch_count,
        int(resampled),
        selection_us,
        int(force_handoff_probe),
        fallback_used,
    )


def start_workers(n: int):
    context = mp.get_context("spawn")
    private_keys = [Ed25519PrivateKey.generate() for _ in range(n)]
    private_raws = [key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()) for key in private_keys]
    public_raws = [key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) for key in private_keys]
    publics = [Ed25519PublicKey.from_public_bytes(item) for item in public_raws]
    policy_state = context.Array("i", [0] * (33 + n))
    processes, ports, stops = [], [], []
    for private_raw in private_raws:
        recv_end, send_end = context.Pipe(duplex=False)
        stop = context.Event()
        process = context.Process(target=worker_main, args=(private_raw, public_raws, send_end, stop, policy_state))
        process.start()
        ports.append(recv_end.recv())
        processes.append(process)
        stops.append(stop)
    clients = [PersistentClient(port, policy_state) for port in ports]
    return clients, publics, processes, stops


def stop_workers(clients, processes, stops) -> None:
    for client in clients:
        client.close()
    for stop in stops:
        stop.set()
    for process in processes:
        process.join(timeout=3)
        if process.is_alive():
            process.terminate()
            process.join()


def _percentile(values, q):
    return float(np.percentile(np.asarray(values, dtype=float), q))


def _summarize(rows: list[dict], fields: tuple[str, ...]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault(tuple(row[field] for field in fields), []).append(row)
    output = []
    for key, subset in sorted(groups.items(), key=lambda item: tuple(map(str, item[0]))):
        record = {field: value for field, value in zip(fields, key, strict=True)}
        record.update(
            blocks=len(subset),
            successful_commits=sum(int(row["committed"]) for row in subset),
            final_signature_count=min(int(row["final_signature_count"]) for row in subset),
            final_quorum=min(int(row["final_quorum"]) for row in subset),
            certificate_p50_ms=_percentile([row["certificate_latency_ms"] for row in subset], 50),
            certificate_p95_ms=_percentile([row["certificate_latency_ms"] for row in subset], 95),
            certificate_p99_ms=_percentile([row["certificate_latency_ms"] for row in subset], 99),
            accounted_p50_ms=_percentile([row["accounted_latency_ms"] for row in subset], 50),
            accounted_p95_ms=_percentile([row["accounted_latency_ms"] for row in subset], 95),
            accounted_p99_ms=_percentile([row["accounted_latency_ms"] for row in subset], 99),
            mean_total_wire_bytes=float(np.mean([row["total_wire_bytes"] for row in subset])),
            mean_availability_wire_bytes=float(np.mean([row["availability_wire_bytes"] for row in subset])),
            mean_on_demand_availability_wire_bytes=float(np.mean([row["on_demand_availability_wire_bytes"] for row in subset])),
            mean_certificate_wire_bytes=float(np.mean([row["certificate_wire_bytes"] for row in subset])),
            mean_signatures=float(np.mean([row["signatures_generated"] for row in subset])),
            mean_fetch_count=float(np.mean([row["fetch_count"] for row in subset])),
            resample_rate=float(np.mean([row["resampled"] for row in subset])),
            backup_rate=float(np.mean([row["backup_used"] for row in subset])),
            fallback_rate=float(np.mean([row["fallback_used"] for row in subset])),
        )
        output.append(record)
    return output


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _fault_checks() -> list[dict]:
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    publics = [Ed25519PublicKey.from_public_bytes(public_raw)]
    payload = b"valid block"
    digest = hashlib.sha256(payload).digest()
    blocks: dict[str, bytes] = {}
    missing = _handle_request({"phase": "prepare", "digest": digest.hex()}, private, publics, blocks)
    corrupt = _handle_request({"phase": "cache", "digest": digest.hex(), "payload": b"corrupt".hex()}, private, publics, blocks)
    valid = _handle_request({"phase": "cache", "digest": digest.hex(), "payload": payload.hex()}, private, publics, blocks)
    return [
        {"check": "missing_block_refuses_signature", "pass": int(missing.get("error") == "missing_block")},
        {"check": "corrupt_block_refuses_signature", "pass": int(corrupt.get("error") == "payload_digest_mismatch")},
        {"check": "valid_block_is_cached", "pass": int(valid.get("cached") is True)},
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--blocks", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/searpc_system"),
        help="Write generated files outside the frozen package by default.",
    )
    args = parser.parse_args()
    repeats = 1 if args.quick else args.repeats
    blocks = 2 if args.quick else args.blocks
    warmup = 1 if args.quick else args.warmup
    counts = (16,) if args.quick else (16, 40)
    payload_size = 16_384
    rows: list[dict] = []
    for n in counts:
        for repeat in range(1, repeats + 1):
            clients, publics, processes, stops = start_workers(n)
            executor = ThreadPoolExecutor(max_workers=n)
            try:
                cells = [(method, availability) for method in METHODS for availability in AVAILABILITY]
                shift = (repeat - 1) % len(cells)
                cells = cells[shift:] + cells[:shift]
                for cell_index, (method, availability) in enumerate(cells):
                    print(f"[SEARPC] n={n} repeat={repeat}/{repeats} method={method} availability={availability}", flush=True)
                    for local_block in range(warmup + blocks):
                        block_id = repeat * 1_000_000 + cell_index * 10_000 + local_block
                        result = run_block(clients, publics, executor, method, availability, repeat, block_id, payload_size)
                        if local_block >= warmup:
                            result.block = local_block - warmup + 1
                            rows.append(result.__dict__)
                if repeat == 1:
                    handoff_probe = run_block(clients, publics, executor, "searpc_conditioned", "fetch", repeat, 9_900_001, payload_size, force_handoff_probe=True)
                    fallback = run_block(clients, publics, executor, "searpc_conditioned", "fetch", repeat, 9_900_002, payload_size, force_fallback=True)
                    if not handoff_probe.committed or handoff_probe.final_signature_count != handoff_probe.final_quorum:
                        raise RuntimeError("additional certificate handoff check failed")
                    if not fallback.committed or not fallback.fallback_used or fallback.final_signature_count != fallback.final_quorum:
                        raise RuntimeError("fallback check failed")
            finally:
                executor.shutdown(wait=True)
                stop_workers(clients, processes, stops)

    output_dir = args.output_dir
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    per_launch = _summarize(rows, ("process_count", "payload_bytes", "method", "availability", "repeat"))
    pooled = _summarize(rows, ("process_count", "payload_bytes", "method", "availability"))
    validity = _fault_checks() + [
        {"check": "all_legal_blocks_committed", "pass": int(all(row["committed"] for row in rows))},
        {"check": "fixed_final_quorum_never_lowered", "pass": int(all(row["final_signature_count"] == row["final_quorum"] for row in rows))},
        {"check": "forty_process_uses_Q27", "pass": int(args.quick or all(row["final_quorum"] == 27 for row in rows if row["process_count"] == 40))},
        {"check": "additional_certificate_handoff_valid", "pass": 1},
        {"check": "full_set_fallback_recovers", "pass": 1},
    ]
    paths = {
        "blocks": output_dir / "SEARPC_process_block_level.csv",
        "launches": output_dir / "SEARPC_process_per_launch.csv",
        "pooled": output_dir / "SEARPC_process_pooled.csv",
        "validity": output_dir / "SEARPC_process_validity_checks.csv",
    }
    _write_csv(paths["blocks"], rows)
    _write_csv(paths["launches"], per_launch)
    _write_csv(paths["pooled"], pooled)
    _write_csv(paths["validity"], validity)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {
        "protocol_status": "fixed-quorum certificate integration prototype",
        "selector": "deterministic synthetic warning schedule",
        "validation_policy": "trusted local candidate set and quorum; network requests cannot lower either",
        "timing_scope": "execution after candidate selection and local policy installation",
        "bft_locking_and_view_change": False,
        "protocol_sha256": digest(PROTOCOL),
        "scoped_evidence_protocol_sha256": digest(EVIDENCE_PROTOCOL),
        "runner_sha256": digest(Path(__file__)),
        "process_counts": list(counts),
        "payload_bytes": payload_size,
        "repeats": repeats,
        "warmup_blocks_per_cell": warmup,
        "measured_blocks_per_cell": blocks,
        "persistent_connections": True,
        "reused_thread_pool": True,
        "all_validity_checks_pass": all(row["pass"] for row in validity),
        "runtime_environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "mem_total_bytes": int(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')) if hasattr(os, 'sysconf') else None,
        },
        "interpretation": "same-host fixed-Q integration cost; not a production BFT/WAN latency claim",
        "outputs": {name: {"path": str(path), "sha256": digest(path)} for name, path in paths.items()},
    }
    manifest_path = output_dir / "SEARPC_process_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
