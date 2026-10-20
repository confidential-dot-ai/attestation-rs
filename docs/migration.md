# Migrating from 0.5.0 to the current interface

This guide describes current main, not an announcement of a released version.
Upgrade binaries and their clients together after selecting a released version;
old request/result types are not wire-compatible. See the interface guides for
complete examples rather than copying obsolete parameter names.

## Rust

| Previous interface | Replacement |
| --- | --- |
| `VerifyParams` | Per-platform params inside `Policies` |
| `VerificationResult` | `Verified` with `PlatformResult`, optional GPU result and collateral |
| `signature_valid`, `collateral_verified` | `Ok` establishes genuineness; check `Verified::passed()` for acceptance |
| Policy mismatch errors | Result fields such as `report_data_match`, `min_tcb_met`, `crl_ok` |
| `CertProvider`, `DefaultCertProvider`, `TdxCollateralProvider`, static providers | Reusable `Verifier::new(Context)` |
| `CertFetchError` | `CollateralUnavailable { collateral, retry_after, detail }` |
| Single digest pins | Nonempty sets: `Vec<[u8; 48]>` |

Choose platforms explicitly; omitted policies refuse evidence. Use
[the Rust example](../crates/attestation/README.md#rust-verification) and handle
both `Ok(v)` with `!v.passed()` and non-retryable errors. Only collateral
unavailability is retryable. RTMR pins are separate `rtmr0`–`rtmr3` fields.

`Policies` is serde JSON across Rust/API/WASM. Bytes are standard base64;
allowed digest sets accept a scalar or array and serialize as arrays. Unknown
fields are refused. Serialized policies omit absent platforms and include
`floors`; Azure PCR maps serialize empty maps when unpinned. Do not depend on
old policy-claim formatting or error message text.

`Context::with_vendors()` exists and bypasses automatic host discovery.
`with_upstream(url)?` selects a cache, `with_cache_dir(dir)` persists collateral,
and `Context::offline()` disables fetching. Generate with `attest`, then call
`Verifier::attach_collateral` if the recipient needs attached copies. The raw
library `attest` call does not attach them. See [lifecycle](collateral.md).

## CLI

Add `--platform` or a platform-specific measurement pin to every verify call:

```sh
attestation-cli verify --platform snp --expected-report-data "$NONCE_HEX" < evidence.json
```

Read `passed`, not `signature_valid`. Handle exit 0 (passed), 1 (rejected),
2 (usage/invalid params) and 3 (collateral unavailable). Retry only 3 with a
bounded policy. Repeat measurement flags for allowlists. `--offline` uses
attached/saved collateral, not an expiry bypass. There are no upstream, floor
or grace flags. [CLI guide](../crates/attestation-cli/README.md).

## HTTP clients and operators

- Replace top-level `params` with `policies` keyed by accepted platform.
- Move `expected_report_data` to `<platform>.report_data`, `expected_mrtd` to
  `mrtd`, `expected_rtmrN` to `rtmrN`, and `expected_launch_digest` to
  `launch_digest`. Init-data policy is `init_data` for TDX, `host_data` for SNP.
- Move GPU policy fields under `policies.nvidia_gpu`: `user_nonce`, `required`,
  `expected_archs`, `allowed_bindings`, `device_policy`.
- Preserve top-level `platform`, platform-specific `evidence`, `nvidia_gpu`
  evidence and `collateral`; do not nest the full envelope under `evidence`.
- Read top-level `passed`; GPU results are under `result.gpu`, collateral under
  `result.collateral`. HTTP 200 alone is not acceptance.
- Retry 502 `collateral_unavailable` with bounded backoff and `Retry-After`;
  400/422 are not transient collateral failures.
- Delete `[certs]` configuration. Move NRAS URL overrides to `[nras]` as
  `gpu_url` / `switch_url`. Removed `/certs/status` and `/certs/refresh` routes
  are no longer available. Unknown settings fail startup.
- SNP now requires its AMD CRL. Plan vendor access or host-cache discovery;
  do not treat temporary CRL unavailability as a valid verdict.
- dstack remains outside the API contract; do not add its policy key.

Check [server policy restrictions and tokens](../crates/attestation-api/README.md#verification-and-tokens).
Token issuance requires nonempty platform report data; the relying party must
still bind the token policy to its own challenge. Config cannot lower version
floors or change the fixed grace period.

## WASM

Replace platform-specific `verify_*` exports with async
`collateral_needed(envelope_json)` and
`evaluate(envelope_json, policies_json, collateral_json)`. All arguments are
JSON strings, not JS typed arrays. Catch errors by `kind` and read returned
`passed`. Keep attached collateral intact; fetch missing vendor responses with
their issuer-chain headers. See the [browser example](../crates/attestation-wasm/README.md).
Dstack is enabled in this harness, NVIDIA is not.

## Evidence transport and cache rollout

Evidence now may carry substantial collateral. Transport it as an HTTP body
or file, not an environment variable, command-line argument, header or
certificate extension. Preserve the complete envelope; check body limits at
every hop (the HTTP API accepts at most 1 MiB; the library limit is 10 MiB).
Dropping collateral forces fetching and can break offline verification.

Cache deployment is optional for correctness but not an elimination of all
live dependencies. Deploy a protected HTTPS site cache before pointing Linux
host caches at it; enable host vsock port 8455 for supported guests. Test cold
start, warmed operation and restart with your own network policy. Explicit
cache-config failures are fatal; browser OPTIONS is unauthenticated while
protected GET requires a key. See [operations](../crates/attestation-cache/README.md).

Floors and 7-day grace bound accepted old collateral; they do not guarantee the
latest vendor publication. NRAS nonce-bound answers remain a live dependency
when no valid answer is attached. No GPU end-to-end or production rollout claim
is made here.
