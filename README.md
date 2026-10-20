# attestation-rs

[![CI](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml)

One Rust interface to generate and verify attestation evidence across AMD
SEV-SNP, Intel TDX, Azure, GCP and dstack. Check vendor signatures, bind evidence
to a fresh challenge, and match workload measurements against your policy.
Use the library directly, verify in a browser with WebAssembly, or integrate
through the CLI and HTTP service.

Evidence can carry its vendor collateral, so the same envelope can travel from
a confidential guest to a server or browser verifier. The library verifies that
collateral against built-in vendor roots; a shared cache supports hosts and sites.

## Capabilities

| Platform | Attest | Verify | WASM Verify |
| --- | --- | --- | --- |
| AMD SEV-SNP (bare-metal) | Yes | Yes | Yes |
| Intel TDX (bare-metal) | Yes | Yes | Yes |
| Azure SEV-SNP (vTPM) | Yes | Yes | Yes |
| Azure TDX (vTPM) | Yes | Yes | Yes |
| GCP SEV-SNP (non-vTPM) | Yes | Yes | Yes |
| GCP TDX (non-vTPM) | Yes | Yes | Yes |
| Dstack TDX | Yes | Yes | Yes |

This is the library's platform matrix. The six CPU platform features are enabled
by default; add `dstack` for its TDX socket integration. Generation needs the
`attest` feature and Linux with the matching guest devices or socket. The
[WASM harness](crates/attestation-wasm/README.md) includes all seven verifiers.
See each interface guide for its exposed platforms and build features.

**NVIDIA GPUs:** add `nvidia-gpu` for portable verification of GPU bundles
alongside CPU evidence. Collection uses `nvidia-gpu-attest`, NVIDIA's SDK and
`libnvat` on a compatible guest. The CLI and HTTP API support GPU verification;
the JS harness focuses on CPU evidence. See the [GPU workflow and trust
boundaries](docs/collateral.md#nvidia-gpu).

## Verify evidence in Rust

For an application next to this checkout, add to `Cargo.toml` (adjust the path
to your clone):

```toml
[dependencies]
attestation = { path = "../attestation-rs/crates/attestation" }
```

The verifier takes an evidence envelope and a policy chosen by the relying
party. This concrete example accepts Intel TDX, requires the verifier's fresh
challenge, and pins a trusted workload measurement. Other platforms use their
own params with the same `verify` / `passed()` flow.

```rust
use attestation::{Policies, TdxParams};

async fn verify_tdx(
    evidence_json: &[u8],
    challenge: &[u8],
    expected_mrtd: [u8; 48],
) -> attestation::Result<bool> {
    let policies = Policies {
        tdx: Some(TdxParams {
            report_data: Some(challenge.to_vec()),
            mrtd: Some(vec![expected_mrtd]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let verified = attestation::verify(evidence_json, &policies).await?;
    Ok(verified.passed())
}
```

Supply the UTF-8 JSON envelope as bytes, a fresh challenge of at most 64 bytes,
and a 48-byte MRTD from your trusted build/deployment policy, not from the
received evidence. **Accept only `Ok(true)`**: `Ok(false)` means a policy or
freshness check failed; `Err` means evidence could not be verified or required
collateral was unavailable. Errors propagate to the caller.

`Policies::default()` accepts no platforms. The policy above accepts TDX only;
its defaults disallow debug but accept several non-revoked TCB statuses, not
only `UpToDate`. [Policies](crates/attestation/README.md#policies) explains
measurement allowlists, Azure PCR pins, TCB choices and collateral floors.

## Generate evidence in a guest

Enable `attest` in that dependency and run inside a Linux TEE:

```toml
[dependencies]
attestation = { path = "../attestation-rs/crates/attestation", features = ["attest"] }
```

Pass the relying party's challenge unchanged. This function returns the envelope to send
back to that party, with available vendor collateral attached:

```rust
async fn generate_evidence(challenge: &[u8]) -> attestation::Result<Vec<u8>> {
    let platform = attestation::detect()?;
    let evidence = attestation::attest(
        platform, challenge, &attestation::AttestOptions::default(),
    ).await?;
    let verifier = attestation::Verifier::new(attestation::Context::new());
    verifier.attach_collateral(&evidence, challenge).await
}
```

Native verifiers fetch missing collateral automatically. Complete, current
attached collateral also supports offline verification; use
`Verifier::new(Context::offline())` when network access must be disabled.
See [the collateral lifecycle](docs/collateral.md) for attachment, refresh,
cache discovery and freshness rules.

## Try the CLI

Build from this checkout:

```sh
cargo build --locked -p attestation-cli --release --features attest,nvidia-gpu
```

For a TDX guest, set `NONCE_HEX` to the relying party's fresh challenge encoded
as hex (at most 64 bytes), and `MRTD` to its trusted 96-character hex measurement.
Generate in the guest, then transfer `evidence.json` to the verifier:

```sh
./target/release/attestation-cli attest --platform tdx \
  --report-data-hex "$NONCE_HEX" --output evidence.json
```

Verify on a machine with the CLI, using the original challenge and trusted pin:

```sh
./target/release/attestation-cli verify --evidence evidence.json --platform tdx \
  --expected-report-data "$NONCE_HEX" --expected-mrtd "$MRTD"
```

Exit 0 means all checks passed. The JSON output includes `passed` and detailed
results. [CLI usage](crates/attestation-cli/README.md) covers other platforms,
stdin, GPU options, offline mode and failure exit codes.

## Guides and interfaces

| Package | Guide | Use |
| --- | --- | --- |
| `attestation` | [Rust and shared Policies](crates/attestation/README.md) | Embed generation or verification |
| `attestation-cli` | [CLI](crates/attestation-cli/README.md) | Generate evidence; verify files or stdin |
| `attestation-api` | [HTTP API](crates/attestation-api/README.md) | Serve attestation and verification; optionally issue JWTs |
| `attestation-wasm` | [WASM](crates/attestation-wasm/README.md) | Verify in JS with caller-supplied collateral |
| `attestation-cache` | [Cache operations](crates/attestation-cache/README.md) | Mirror verified vendor collateral for hosts and sites |

- [Evidence and collateral](docs/collateral.md): envelope lifecycle, trust,
  freshness, offline use and upstream discovery.
- [Migration](docs/migration.md): changes from the released 0.5.0 interface.
  These docs describe this checkout.

## Build and check

Run from the workspace root with Rust and Cargo:

```sh
cargo build --locked -p attestation-api --release
cargo build --locked -p attestation-cache --release
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
```

The default API build verifies GPU bundles. For collection, add
`--features nvidia-gpu-attest` on a suitably provisioned Linux guest.
`docker build .` builds the API image, published as
`ghcr.io/confidential-dot-ai/attestation-api`.

Tests include fixtures, network tests and hardware-gated paths. The matrix
shows supported functionality, not live hardware test coverage; individual
guides identify hardware-only examples.
