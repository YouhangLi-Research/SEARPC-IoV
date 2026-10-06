"""Local TCP/Ed25519 multi-process prototype for DURAC validation paths."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import multiprocessing as mp
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from statistics import median

import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results/durac_phase18_process_prototype"
PROTOCOL = ROOT / "SEARPC_PROCESS_PROTOTYPE_PROTOCOL.md"
HEADER = struct.Struct("!I")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise ConnectionError("socket closed")
        chunks.extend(part)
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> tuple[bytes, int]:
    header = recv_exact(sock, HEADER.size)
    size = HEADER.unpack(header)[0]
    return recv_exact(sock, size), HEADER.size + size


def send_frame(sock: socket.socket, payload: bytes) -> int:
    frame = HEADER.pack(len(payload)) + payload
    sock.sendall(frame)
    return len(frame)


def worker_main(private_raw: bytes, public_raws: list[bytes], ready, stop) -> None:
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    publics = [Ed25519PublicKey.from_public_bytes(item) for item in public_raws]
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(0.2)
    ready.send(server.getsockname()[1])
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        with conn:
            raw, _ = recv_frame(conn)
            request = json.loads(raw)
            digest = bytes.fromhex(request["digest"])
            phase = request["phase"]
            if phase == "commit":
                for signer, signature_hex in request["prepare_qc"]:
                    publics[int(signer)].verify(bytes.fromhex(signature_hex), b"prepare:" + digest)
                signed = b"commit:" + digest + hashlib.sha256(
                    json.dumps(request["prepare_qc"], separators=(",", ":")).encode()
                ).digest()
            else:
                signed = b"prepare:" + digest
            response = json.dumps({"signature": private.sign(signed).hex()}, separators=(",", ":")).encode()
            send_frame(conn, response)
    server.close()


@dataclass
class CellResult:
    process_count: int
    payload_bytes: int
    method: str
    measured_blocks: int
    successful_commits: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    mean_wire_bytes: float
    mean_signatures: float
    resample_rate: float
    mean_selection_us: float


def percentile(values: list[float], q: float) -> float:
    return float(np.percentile(np.asarray(values), q))


def request(port: int, body: dict) -> tuple[dict, int]:
    payload = json.dumps(body, separators=(",", ":")).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as sock:
        sent = send_frame(sock, payload)
        response_raw, received = recv_frame(sock)
    return json.loads(response_raw), sent + received


def committee_for(method: str, n: int, block: int) -> tuple[list[int], bool, float]:
    start = time.perf_counter_ns()
    size = n if method == "full_set" else min(13, n)
    primary = [((block * 7) + offset) % n for offset in range(size)]
    resampled = False
    if method == "durac_conditioned":
        warned = {idx for idx in range(n) if (idx + block // 4) % 17 == 0}
        if warned.intersection(primary) and len(set(range(n)) - warned) >= size:
            clean = [idx for idx in range(n) if idx not in warned]
            primary = [clean[((block * 7) + offset) % len(clean)] for offset in range(size)]
            resampled = True
    elapsed_us = (time.perf_counter_ns() - start) / 1_000.0
    return primary, resampled, elapsed_us


def run_block(
    ports: list[int],
    publics: list[Ed25519PublicKey],
    method: str,
    block: int,
    payload_size: int,
) -> tuple[bool, float, int, int, bool, float]:
    committee, resampled, selection_us = committee_for(method, len(ports), block)
    f = (len(committee) - 1) // 3
    quorum = 2 * f + 1
    payload = hashlib.shake_256(f"block:{block}".encode()).digest(payload_size)
    digest = hashlib.sha256(payload).digest()
    started = time.perf_counter_ns()
    wire = 0
    prepare_body = {"phase": "prepare", "digest": digest.hex(), "payload": payload.hex()}
    with ThreadPoolExecutor(max_workers=len(committee)) as pool:
        prepared = list(pool.map(lambda idx: (idx, request(ports[idx], prepare_body)), committee))
    prepare_qc = []
    for idx, (response, used) in prepared:
        signature = bytes.fromhex(response["signature"])
        publics[idx].verify(signature, b"prepare:" + digest)
        prepare_qc.append([idx, response["signature"]])
        wire += used
    prepare_qc = prepare_qc[:quorum]
    commit_body = {"phase": "commit", "digest": digest.hex(), "prepare_qc": prepare_qc}
    qc_hash = hashlib.sha256(json.dumps(prepare_qc, separators=(",", ":")).encode()).digest()
    with ThreadPoolExecutor(max_workers=len(committee)) as pool:
        committed = list(pool.map(lambda idx: (idx, request(ports[idx], commit_body)), committee))
    valid = 0
    for idx, (response, used) in committed:
        signature = bytes.fromhex(response["signature"])
        publics[idx].verify(signature, b"commit:" + digest + qc_hash)
        valid += 1
        wire += used
    latency_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    signatures = len(prepared) + len(committed)
    return valid >= quorum, latency_ms, wire, signatures, resampled, selection_us


def run_cell(n: int, payload: int, method: str, warmup: int, blocks: int) -> CellResult:
    context = mp.get_context("spawn")
    private_keys = [Ed25519PrivateKey.generate() for _ in range(n)]
    private_raws = [key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()) for key in private_keys]
    public_raws = [key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) for key in private_keys]
    publics = [Ed25519PublicKey.from_public_bytes(item) for item in public_raws]
    processes = []
    ports = []
    stops = []
    for private_raw in private_raws:
        recv_end, send_end = context.Pipe(duplex=False)
        stop = context.Event()
        proc = context.Process(target=worker_main, args=(private_raw, public_raws, send_end, stop))
        proc.start()
        ports.append(recv_end.recv())
        processes.append(proc)
        stops.append(stop)
    latencies: list[float] = []
    wires: list[int] = []
    signatures: list[int] = []
    selections: list[float] = []
    successes = 0
    resamples = 0
    try:
        for block in range(warmup + blocks):
            ok, latency, wire, sigs, resampled, selection_us = run_block(
                ports, publics, method, block, payload
            )
            if block >= warmup:
                successes += int(ok)
                latencies.append(latency)
                wires.append(wire)
                signatures.append(sigs)
                selections.append(selection_us)
                resamples += int(resampled)
    finally:
        for stop in stops:
            stop.set()
        for proc in processes:
            proc.join(timeout=3)
            if proc.is_alive():
                proc.terminate()
                proc.join()
    return CellResult(
        n, payload, method, blocks, successes, median(latencies), percentile(latencies, 95),
        percentile(latencies, 99), sum(wires) / blocks, sum(signatures) / blocks,
        resamples / blocks, sum(selections) / blocks,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--blocks", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    counts = [16] if args.quick else [16, 40]
    payloads = [1024] if args.quick else [1024, 16384]
    methods = ["full_set", "fixed_k13", "durac_conditioned"]
    blocks = 3 if args.quick else args.blocks
    warmup = 1 if args.quick else args.warmup
    rows = []
    for n in counts:
        for payload in payloads:
            for method in methods:
                print(f"[prototype] n={n} payload={payload} method={method}", flush=True)
                rows.append(run_cell(n, payload, method, warmup, blocks).__dict__)
    OUT.mkdir(parents=True, exist_ok=True)
    output = OUT / "DURAC_phase18_process_results.csv"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    manifest = {
        "protocol_sha256": hashlib.sha256(PROTOCOL.read_bytes()).hexdigest(),
        "blocks": blocks,
        "warmup": warmup,
        "cells": len(rows),
        "all_committed": all(row["successful_commits"] == blocks for row in rows),
    }
    (OUT / "DURAC_phase18_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()

