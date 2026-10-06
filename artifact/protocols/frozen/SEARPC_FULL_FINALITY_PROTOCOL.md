# DURAC full finality: Complete data availability and fixed-finality prototype

Status: frozen before inspecting process measurements

Date: 2026-08-26

## Scope

This phase closes the gap between the simulated fixed final certificate and the
process prototype/19 committee-only microbenchmark.  It uses real localhost TCP,
serialization, SHA-256, Ed25519 signing and signature verification in 16 and 40
independent validator processes.  It remains a process prototype rather than a
production PBFT, wireless, or WAN benchmark.

For a registered set of size N, `F=floor((N-1)/3)` and the fixed finality
threshold is `Q=2F+1`: Q=11 for N=16 and Q=27 for N=40.  A size-13 fast
committee uses q=9.  Neither content risk nor validator risk may change N, F,
Q, k, or q.

## Validation chain

1. The complete 16 KiB candidate block is made available to every selected
   fast-committee member.
2. Fast validators recompute the block digest, then produce q valid Prepare and
   q valid Commit signatures.
3. A non-committee final signer without the block refuses to sign.
4. On the fetch path it obtains the complete block, recomputes its digest,
   validates the q-signature Commit certificate, and only then signs finality.
5. A fixed Q-signature final certificate is required.  For the full-set method,
   its Q-signature Commit certificate is already the final certificate.
6. A primary-collector failure uses the registered backup collector.  A final
   certificate timeout invokes the full-set authenticated fallback; Q is never
   lowered.

## Availability boundaries and accounting

- `cached`: all registered validators already receive the complete block via a
  common propagation layer.  Its propagation bytes and time are retained
  separately and included in fully accounted totals.
- `fetch`: only the selected fast committee initially receives the block;
  additional final signers fetch it on demand.

Every method uses the same payload, framing, serializer, key type, persistent
connection implementation, and reused thread pool.  Report certificate and
fully accounted latency, exact application wire bytes, signatures, final
signature count, fetch count, resampling, backup use, and fallback use.

## Frozen run

- process counts: 16 and 40;
- payload: 16 KiB;
- methods: full-set authenticated quorum, fixed k13, conditioned k13;
- availability: cached and fetch;
- five independent process launches;
- five warm-up and thirty measured blocks per cell;
- method/availability order rotates by launch;
- normal cells must commit every legal block with exactly Q final signatures;
- explicit checks must show missing/corrupt data does not obtain a signature,
  backup collection succeeds, and fallback succeeds without lowering Q.

The experiment may support feasibility and cost-bound claims.  It cannot be
described as a production deployment or a newly invented finality algorithm.
