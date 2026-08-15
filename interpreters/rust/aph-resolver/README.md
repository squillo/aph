# aph-resolver

Ready-made I/O adapters for APH notary-key discovery (spec §8.4).

`aph-core` parses and never fetches: it declares two narrow one-method ports
(`discovery::ports::TxtRecordLookup`, `discovery::ports::DidDocumentFetch`)
and keeps no HTTP client, no resolver and no async runtime. This crate is one
implementation of those two ports, carrying `hickory-resolver` and `reqwest`
so `aph-core` does not have to.

```toml
[dependencies]
aph-resolver = "0.1"
```

```rust
// Both values come from the envelope being verified: the DID URL from
// `proof.verificationMethod`, the instant from `decisionTimestamp` — not the
// wall clock, so an envelope signed before a rotation keeps verifying.
let key = aph_resolver::resolve(
  "did:web:notary.example.com#k1",
  "2026-06-01T00:00:00Z",
)
.await?;
```

## Who this is for

Adopters with **no adapter layer of their own** — a CLI, a service, a test
harness with no opinion about how HTTP and DNS should be performed.

It is deliberately **not** for a host that already has a transport stack. An
OS or platform with its own HTTP client, DNS policy, timeout budget and audit
log should implement `aph_core::discovery::ports` over that stack — a few
dozen lines — and keep one place where outbound requests are made. Two HTTP
clients in one process means two timeout policies, two proxy configurations,
and two answers to "what did this machine connect to".

## What it decides, and what it does not

Every parsing, selection and ordering rule stays in `aph-core`. This crate
contributes bytes plus exactly one judgement, the ABSENCE/FAILURE split, which
only an adapter can see: NXDOMAIN, and NOERROR with no TXT records, are
absence (`Ok(vec![])`, and §8.4.6 advances to the next mechanism), while
timeout, SERVFAIL and REFUSED are `APH_E008` and stop the sequence. Reporting
absence as failure would make every `did:web`-only notary unverifiable;
reporting failure as absence would let whoever can block DNS choose which
anchor a verifier trusts.

## Security posture

The host being fetched is named by the envelope, so it is chosen by an
untrusted party. `ReqwestDocumentFetch` applies five controls:

1. A deny table over **every** resolved address before any connect (loopback,
   RFC 1918, link-local including cloud metadata, CGNAT, multicast, reserved,
   the IPv6 equivalents, and the IPv4 addresses embedded in mapped, compatible,
   NAT64 and 6to4 forms) — then the validated set is **pinned** so the connect
   cannot re-resolve.
2. HTTPS only, with no certificate-validation escape hatch anywhere.
3. Redirects refused, plus an origin-equality re-check on the response.
4. A 5 s connect and total budget, and a 64 KiB body cap enforced **while
   streaming** rather than after reading.
5. One opaque `APH_E008` outward for every failure — no status, no address, no
   timing — so a verifier cannot be steered into acting as a network probe.

Full protocol text: [`spec/aph-0.1.md`](../../../spec/aph-0.1.md) §8.4.
