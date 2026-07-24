# RT-002 — TDX verification accepts out-of-date TCB and expired collateral

**Status:** LIVE-VERIFIED end-to-end against Intel PCS (2026-07-23): ran the
attestation-api binary built from `main` (pre-fix) and from this branch, and
POSTed the genuine `tdx_quote_4.dat` hardware quote (collateral fetched live
from Intel PCS — `collateral_verified: true`).

| Server | Request | Result |
|---|---|---|
| pre-fix (`main`) | `allow_debug` only | **ACCEPTED** — `tcb_status: OutOfDate`, FMSPC `50806f000000`, **11 active Intel advisories** (INTEL-SA-00837, -00960, -00982, -00986, -01010, -01036, -01076, -01079, -01099, -01103, -01111) |
| this branch | `allow_debug` only | REJECTED — `TDX TCB status is OutOfDate` |
| this branch | client sets `allow_out_of_date_tcb`, server config default | REJECTED — `allow_out_of_date_tcb is disabled by server configuration` |
| this branch | client + server opt-in both set | ACCEPTED (explicit operator choice) |
**Severity:** High
**Adversary:** operator of a genuine TDX platform with a known-vulnerable or
revoked-in-flight TCB; network adversary able to starve the verifier of fresh
Intel PCS collateral (e.g. the c8s adversarial host, which controls guest
egress)

## Summary

Two compounding fail-open defaults in the TDX DCAP verification path let
evidence from a platform Intel itself considers untrustworthy pass with
`signature_valid: true` — and c8s's `EnforceVerdict` has no TCB-status gate,
so such evidence flows straight into mesh-certificate issuance.

### 1. Only `Revoked` TCB status is rejected

`crates/attestation/src/platforms/tdx/verify.rs` and
`crates/attestation/src/platforms/az_tdx/verify.rs` evaluated the TCB Info
correctly but enforced only:

```rust
if status.tcb_status == TdxTcbStatus::Revoked { return Err(...) }
```

`OutOfDate` and `OutOfDateConfigurationNeeded` — Intel's statuses for "this
TCB is covered by published security advisories and must not be trusted" —
fell through to success, as did `SWHardeningNeeded` / `ConfigurationNeeded`.

This is not hypothetical: the repo's own v4 test fixture is a genuine TDX
quote whose TCB Intel's current collateral maps to **OutOfDate**. Before this
branch, the test suite asserted that quote *passed*; the regression tests now
assert it fails by default.

### 2. Expired collateral is a log line, not a failure

`evaluate_tcb_status` (`crates/attestation/src/platforms/tdx/dcap.rs`)
computed `collateral_expired` from the TCB Info `nextUpdate`, logged a
warning, and returned success. Staleness is the load-bearing freshness
signal for revocation: an adversary who blackholes Intel PCS after time T
(the c8s threat model's host controls guest egress) freezes the verifier at
pre-revocation collateral indefinitely, and every subsequently revoked or
out-dated TCB keeps passing. An unparseable `nextUpdate` also silently
evaluated to "not expired".

## Fix (this branch)

- `VerifyParams.allow_out_of_date_tcb` (default **false**) — when false,
  `OutOfDate` / `OutOfDateConfigurationNeeded` are rejected alongside
  `Revoked` (which remains always-rejected). `SWHardeningNeeded` /
  `ConfigurationNeeded` remain accepted (Intel's lenient profile).
- `VerifyParams.allow_expired_collateral` (default **false**) — when false,
  a TCB Info whose `nextUpdate` is past fails with the new
  `AttestationError::CollateralExpired`. A missing or unparseable
  `nextUpdate` is treated as expired (fail closed) — the pre-fix behavior
  silently evaluated it to "not expired".
- Shared enforcement in `dcap::enforce_tcb_policy`, called from both the
  bare-metal/GCP (`platforms/tdx`) and Azure (`platforms/az_tdx`) paths.
- HTTP API: `allow_out_of_date_tcb` / `allow_expired_collateral` request
  params, each honored only when the server config enables the same flag
  (default off) — mirroring the existing `allow_debug` server gate, so the
  server operator controls the floor.
- The attestation-api's `CachedTdxProvider` now caches the Intel PCS
  issuer-chain response headers alongside the collateral bodies and serves
  them to the verifier, so TCB Info / QE Identity signatures are verified in
  the deployed service (previously the chains were dropped and collateral
  signature verification was skipped with a log warning).
- Regression tests: the v4 fixture (genuine OutOfDate quote + expired TCB
  Info) now fails by default and passes only with both opt-ins; the two
  pre-existing fixture tests were updated to opt in explicitly. The OutOfDate
  rejection test opts into expired collateral so it exercises the TCB-status
  gate in isolation (the expiry gate fires first otherwise), and a
  truth-table unit test covers `enforce_tcb_policy` over all TCB statuses
  and flag combinations.

## Consumer note (c8s)

c8s's `attestationclient.EnforceVerdict` gates only on `SignatureValid` and
`ReportDataMatch`, and its TDX path explicitly has no minimum-TCB policy
(`pkg/attestationclient/verify.go`). With this fix deployed in the
attestation-api, out-of-date TCB and stale collateral fail at the verdict
source, which is the right layer — no c8s change required. A future
hardening step is surfacing `tcb_status` in the EAR/claims so relying
parties can pin it.

## Reproduce

```
cargo test -p attestation --lib test_verify_evidence_v4_out_of_date_tcb_rejected_by_default
cargo test -p attestation --lib test_verify_evidence_v4_expired_collateral_rejected_by_default
```

Both fail against the parent commit (the fixture passes verification) and
pass on this branch.
