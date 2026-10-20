# attestation: Rust library and shared policy contract

Generate and verify TEE evidence with one policy-driven Rust interface across
AMD SEV-SNP, Intel TDX, Azure, GCP and dstack. Verification runs natively or in
WebAssembly, with pure-Rust cryptography and shared vendor collateral handling.

See the [supported platform matrix](../../README.md#capabilities) and
[generate/verify walkthrough](../../README.md#verify-evidence-in-rust) to get
started; this guide covers policy fields, results and integration choices.

## Rust verification

This function accepts TDX only. Supply a fresh relying-party challenge and a
trusted expected MRTD; do not derive either from the untrusted evidence.

```rust
use attestation::{Policies, TdxParams};

async fn check(
    evidence: &[u8], nonce: &[u8], expected_mrtd: [u8; 48],
) -> attestation::Result<bool> {
    let policies = Policies {
        tdx: Some(TdxParams {
            report_data: Some(nonce.to_vec()),
            mrtd: Some(vec![expected_mrtd]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let verified = attestation::verify(evidence, &policies).await?;
    Ok(verified.passed())
}
```

For explicit storage and time control, reuse `Verifier::new(context)` and call
`verifier.verify(evidence, &policies).await`. `Context::new()` uses native
network access; `Context::offline()` does not. Both accept attached collateral.
Native `.with_cache_dir(dir)` persists copies; `.with_upstream(url)?` chooses a
cache; `.at(unix_seconds)?` fixes evaluation time. See the
[collateral lifecycle](../../docs/collateral.md) for their limits.

## Policies

`Policies` is the shared Rust/serde contract used by API `/verify` and WASM
`evaluate`. Enabled platform features determine the library policy keys; see
the [API](../attestation-api/README.md) and [WASM](../attestation-wasm/README.md)
guides for their interface-specific choices.

- `Policies::default()` / `{}` accepts **no CPU platform**.
- `Policies::all()` accepts every compiled-in CPU platform with default checks,
  not GPU bundles. Use only when every such platform is acceptable.
- `.with_report_data(&nonce)` sets the nonce on CPU policies already present;
  it does not add platforms or set GPU params.
- Each absent or null CPU policy refuses that platform. `{ "tdx": {} }`
  accepts TDX with defaults, but pins neither workload nor challenge.
- Unknown keys and fields are refused, including irrelevant fields set to null.
- Bytes in policy JSON use standard base64, not hex. Rust digest sets are
  `Option<Vec<[u8; 48]>>`. JSON accepts one 48-byte value or a nonempty array;
  serialization emits arrays. A measurement must equal one of the values.

Minimal JSON (illustrative challenge only; use a fresh random challenge):

```json
{"tdx":{"report_data":"AQIDBA==","accepted_tcb_statuses":["UpToDate"]}}
```

| Policy | Fields |
| --- | --- |
| `tdx`, `gcp-tdx`, `az-tdx`, `dstack` | `report_data`, `init_data`, `mrtd`, `rtmr0`–`rtmr3`, `allow_debug`, `accepted_tcb_statuses` |
| `snp`, `gcp-snp`, `az-snp` | `report_data`, `host_data`, `launch_digest`, `allow_debug`, `min_tcb`, `max_vmpl` |
| `az-tdx`, `az-snp` additionally | `pcrs`: map of index 0–23 to 32-byte SHA-256 value; duplicate indices refused |
| `nvidia_gpu` (Rust field `gpu`) | `user_nonce`, `required`, `expected_archs`, `allowed_bindings`, `device_policy` |
| `floors` | [Collateral version floors](../../docs/collateral.md#freshness-and-version-floors) |

Rust cloud wrapper params contain `tdx: TdxParams` or `snp: SnpParams`; JSON
flattens them. `DstackParams` wraps `TdxParams`. Azure params additionally
contain a `BTreeMap<u8, [u8; 32]>` of PCR pins.

Default CPU checks disallow debug; SNP requires VMPL 0 and applies no caller
minimum TCB unless set. TDX defaults accept `UpToDate`, `SWHardeningNeeded`,
`ConfigurationNeeded`, `ConfigurationAndSWHardeningNeeded`, `OutOfDate` and
`OutOfDateConfigurationNeeded`, **not just UpToDate**. They refuse `Revoked`
and `NoMatchingLevel`. Choose a narrower nonempty set when required.

`report_data` is at most 64 bytes and zero-padded for CPU reports; Azure binds
it to the vTPM quote nonce instead. `host_data` is at most 32 bytes; TDX
`init_data` is at most 48. On Azure the init-data pin is a 32-byte hash checked
against PCR[8]. Empty report data is an all-zero pin, not a fresh challenge.

SNP `min_tcb` is an object with `bootloader`, `tee`, `snp`, `microcode` and
optional `fmc`; minimum checks compare components, not an aggregate version.
See generated rustdocs for exact field types. API adds
[server-side policy restrictions](../attestation-api/README.md#verification-and-tokens).

## Results, errors and retry

| Outcome | Library contract |
| --- | --- |
| Genuine evidence, every requested rule and collateral check passed | `Ok(v)` and `v.passed()` |
| Measurement/nonce mismatch, debug/VMPL/TCB rejection, revocation, stale beyond grace or below-floor collateral | `Ok(v)` and `!v.passed()` |
| Malformed evidence, invalid params, disabled/disallowed platform, bad signature/chain/event log or GPU nonce binding | Non-retryable `Err` |
| Required collateral absent and unavailable | `Err(CollateralUnavailable { collateral, retry_after, detail })` |

Only `is_retryable()` errors should enter a bounded retry/backoff path; honor
`retry_after()` when present. Do not retry a policy mismatch as if it were a
network outage. `*_match: None` means a check was not requested, not that it
passed. Read platform fields via `verified.platform`, optional GPU result via
`verified.gpu` with that feature, and freshness via `verified.collateral`.

Plain serialization of `Verified` does not add a `passed` field; call
`passed()` yourself. CLI, HTTP API and WASM add it to their own output. Results
are `#[must_use]`, but callers still need an explicit acceptance decision.

## Generation and features

The default features are `snp`, `tdx`, `az-snp`, `az-tdx`, `gcp-snp`, `gcp-tdx`.
Use `default-features = false` to choose fewer. `dstack` implies `tdx`.
`attest` enables Linux guest generation and implies `snp` and `tdx`;
`az-snp-attest` / `az-tdx-attest` are compatibility aliases. Native generation:

```rust,ignore
let platform = attestation::detect()?;
let raw = attestation::attest(
    platform, &nonce, &attestation::AttestOptions::default(),
).await?;
let verifier = attestation::Verifier::new(attestation::Context::new());
let envelope = verifier.attach_collateral(&raw, &nonce).await?;
```

This integration fragment requires a Linux TEE, `attest`, and an application
nonce. Attachment may be incomplete; see [lifecycle](../../docs/collateral.md).
Platform examples are hardware-only, for example:

```sh
cargo run --locked -p attestation --example snp --features snp,attest
cargo run --locked -p attestation --example tdx --features tdx,attest
cargo run --locked -p attestation --example az_snp --features az-snp,attest
cargo run --locked -p attestation --example az_tdx --features az-tdx,attest
cargo run --locked -p attestation --example gcp_snp --features gcp-snp,attest
cargo run --locked -p attestation --example gcp_tdx --features gcp-tdx,attest
```

`nvidia-gpu` adds portable bundle verification. `nvidia-gpu-attest` adds the
NVIDIA SDK dependency for collection; it also needs `attest` for combined CPU
and GPU generation, compatible NVIDIA drivers/CC hardware, SDK build prerequisites
and `libnvat` at runtime. See [NVIDIA's SDK](https://github.com/NVIDIA/attestation-sdk)
for installation and service terms, and [NRAS limits](../../docs/collateral.md#nvidia-gpu).

## Development

```sh
cargo test --locked -p attestation
cargo test --locked -p attestation --doc
cargo doc --locked -p attestation --no-deps
cargo check --locked -p attestation --target wasm32-unknown-unknown   --no-default-features --features snp,tdx,az-snp,az-tdx,gcp-snp,gcp-tdx,dstack
```

The WASM target must be installed first. Verification uses pure-Rust crypto;
Linux generation paths are not compiled on WASM. The library license is
Apache-2.0, as specified in `Cargo.toml`.
