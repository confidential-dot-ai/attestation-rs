# Attestation

[![CI](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml)

A Rust library providing a unified interface for TEE (Trusted Execution Environment) attestation evidence generation and verification.

## Supported Platforms

| Platform                      | Attest | Verify | WASM Verify |
| ----------------------------- | ------ | ------ | ----------- |
| AMD SEV-SNP (bare-metal)      | Yes    | Yes    | Yes         |
| Intel TDX (bare-metal)        | Yes    | Yes    | Yes         |
| Azure SEV-SNP (vTPM)          | Yes    | Yes    | Yes         |
| Azure TDX (vTPM)              | Yes    | Yes    | Yes         |
| GCP SEV-SNP (non-vTPM)        | Yes    | Yes    | Yes         |
| GCP TDX (non-vTPM)            | Yes    | Yes    | Yes         |
| Dstack TDX                    | Yes    | Yes    | Yes         |

## Feature Flags

```toml
[dependencies]
attestation = { path = "crates/attestation", features = ["snp", "tdx"] }
```

| Feature  | Description                                                               |
| -------- | ------------------------------------------------------------------------- |
| `snp`    | AMD SEV-SNP support (verify always, attest when `attest` also enabled)    |
| `tdx`    | Intel TDX support                                                         |
| `az-snp`  | Azure SEV-SNP vTPM support (implies `snp`)                               |
| `az-tdx`  | Azure TDX vTPM support (implies `tdx`)                                   |
| `gcp-snp` | GCP SEV-SNP non-vTPM support (implies `snp`)                             |
| `gcp-tdx` | GCP TDX non-vTPM support (implies `tdx`)                                 |
| `dstack`  | Dstack TDX support via Unix socket (implies `tdx`)                       |
| `attest` | Enable guest-side evidence generation for enabled platforms (Linux-only, requires TEE hardware) |
| `az-snp-attest` | Compatibility alias for `attest` + `az-snp`                      |
| `az-tdx-attest` | Compatibility alias for `attest` + `az-tdx`                      |

All six platform features are enabled by default. Verification is always compiled when a platform feature is enabled. The `attest` feature gates guest-side code that requires hardware access and includes the default SEV-SNP + TDX attestation set.

## Usage

### Verifier (Server-Side or WASM)

Say which platforms you accept and what each must satisfy:

```rust
use attestation::{Policies, TdxParams};

#[tokio::main]
async fn main() {
    // evidence_json is a self-describing AttestationEvidence envelope
    let evidence_json: &[u8] = b"...";

    let policies = Policies {
        tdx: Some(TdxParams {
            report_data: Some(nonce.to_vec()),
            mrtd: Some(vec![expected_mrtd]), // any of the allowed values
            ..Default::default()
        }),
        ..Default::default()
    };

    match attestation::verify(evidence_json, &policies).await {
        Ok(verified) if verified.passed() => { /* accept */ }
        Ok(verified) => { /* genuine, but a rule failed: read the fields */ }
        Err(e) if e.is_retryable() => { /* collateral unavailable: retry */ }
        Err(e) => { /* not verifiable: refuse */ }
    }
}
```

`Policies::all()` accepts every compiled-in platform with its default params,
and `.with_report_data(&nonce)` requires your nonce on each of them:

```rust
let verified = attestation::verify(evidence_json, &Policies::all().with_report_data(&nonce)).await?;
```

Each platform has its own params and result (`TdxParams`/`TdxResult`,
`SnpParams`/`SnpResult`, `AzTdxParams`, `AzSnpParams`, `GcpTdxParams`,
`GcpSnpParams`, `DstackParams`). If you know the platform, call it directly:

```rust
use attestation::{Context, Platform, Tdx};

let result = Tdx::verify(&evidence, &params, &Context::new()).await?;
```

### What is an error

| Case | Result |
| --- | --- |
| Malformed or too large evidence, platform not compiled in, invalid params | `Err` |
| Evidence for a platform with no params in `Policies` | `Err(PlatformNotAllowed)` |
| Bad signature, cert chain, QE binding, event log, GPU nonce binding (overall or per device) | `Err` |
| Collateral could not be fetched (AMD KDS, Intel PCS, NRAS) | `Err(CollateralUnavailable)`, retryable |
| Measurement, RTMR, launch digest, `report_data` or init data mismatch | value: `*_match: Some(false)` |
| Debug, VMPL, minimum TCB, TDX TCB status (including no matching level), revoked TDX PCK, GPU device policy | value |
| A check you did not ask for | value: `None` |

`passed()` is true only when every rule in the params held. Results are
`#[must_use]`.

### Custom Providers and Time

```rust
use attestation::{Context, Verifier};

let verifier = Verifier::new(
    Context::new()
        .with_cert_provider(my_cert_provider)
        .with_tdx_provider(my_tdx_provider),
);
let verified = verifier.verify(evidence_json, &policies).await?;
```

`Context::offline()` never touches the network: checks that need fetched
collateral (TDX CRLs, TCB status and QE identity) are skipped and their fields
stay `None`, and evidence that cannot be verified without a fetch (SNP
without an inline VEK, an NVIDIA GPU bundle) is `CollateralUnavailable`. `Context::at(unix_seconds)` fixes the
time used for certificate, CRL and token validity.

### Attester (Guest-Side Agent)

```rust
#[tokio::main]
async fn main() {
    // Auto-detect the TEE platform
    let platform = attestation::detect().expect("no TEE platform detected");
    println!("Detected platform: {}", platform);

    // Generate evidence with a challenge nonce
    let nonce = b"server-provided-challenge-nonce";
    let evidence_json = attestation::attest(platform, nonce, &attestation::AttestOptions::default()).await.unwrap();

    // Send evidence_json to the verifier — it's a self-describing envelope
    println!("Evidence: {} bytes", evidence_json.len());
}
```

## Examples

Each platform has a dedicated example. Run on the appropriate hardware:

```bash
cargo run -p attestation --example snp     --features "snp,attest"
cargo run -p attestation --example tdx     --features "tdx,attest"
cargo run -p attestation --example az_snp  --features "az-snp,attest"
cargo run -p attestation --example az_tdx  --features "az-tdx,attest"
cargo run -p attestation --example gcp_snp --features "gcp-snp,attest"
cargo run -p attestation --example gcp_tdx --features "gcp-tdx,attest"
```

Azure examples accept an optional nonce argument:

```bash
cargo run -p attestation --example az_snp --features "az-snp,attest" -- "my-custom-nonce"
```

GCP examples accept an optional nonce argument:

```bash
cargo run -p attestation --example gcp_snp --features "gcp-snp,attest" -- "my-custom-nonce"
cargo run -p attestation --example gcp_tdx --features "gcp-tdx,attest" -- "my-custom-nonce"
```

## CLI

The CLI lives in the `attestation-cli` package:

```bash
# Build the CLI
cargo build -p attestation-cli --release

# Generate evidence (on TEE hardware, Linux only)
cargo build -p attestation-cli --release --features attest
./target/release/attestation-cli attest --report-data "my-nonce"

# Verify evidence (works anywhere)
echo "$EVIDENCE" | ./target/release/attestation-cli verify
```

## Evidence JSON Schemas

### SNP Evidence

```json
{
  "attestation_report": "<base64-encoded 1184-byte SNP report>",
  "cert_chain": {
    "vcek": "<base64-encoded DER certificate>",
    "ask": "<base64-encoded DER certificate, optional>",
    "ark": "<base64-encoded DER certificate, optional>"
  }
}
```

### TDX Evidence

```json
{
  "quote": "<base64-encoded TDX quote bytes>",
  "cc_eventlog": "<base64-encoded CCEL eventlog, optional>"
}
```

### Azure SNP Evidence

```json
{
  "version": 1,
  "tpm_quote": {
    "signature": "<hex-encoded RSA signature>",
    "message": "<hex-encoded TPMS_ATTEST>",
    "pcrs": ["<hex-encoded 32-byte PCR value>", "...(24 entries)"]
  },
  "hcl_report": "<url-safe-base64-encoded HCL report (2600 bytes)>",
  "vcek": "<url-safe-base64-encoded DER certificate>"
}
```

### Azure TDX Evidence

```json
{
  "version": 1,
  "tpm_quote": {
    "signature": "<hex-encoded RSA signature>",
    "message": "<hex-encoded TPMS_ATTEST>",
    "pcrs": ["<hex-encoded 32-byte PCR value>", "...(24 entries)"]
  },
  "hcl_report": "<url-safe-base64-encoded HCL report (2600 bytes)>",
  "td_quote": "<url-safe-base64-encoded TD quote>"
}
```

### GCP SNP Evidence

GCP SEV-SNP uses the same wire format as bare-metal SNP. The `platform` field in the evidence envelope is set to `gcp-snp` to distinguish it from bare-metal SNP evidence.

```json
{
  "attestation_report": "<base64-encoded 1184-byte SNP report>",
  "cert_chain": {
    "vcek": "<base64-encoded DER certificate>",
    "ask": "<base64-encoded DER certificate, optional>",
    "ark": "<base64-encoded DER certificate, optional>"
  }
}
```

### GCP TDX Evidence

GCP TDX uses the same wire format as bare-metal TDX. The `platform` field in the evidence envelope is set to `gcp-tdx` to distinguish it from bare-metal TDX evidence.

```json
{
  "quote": "<base64-encoded TDX quote bytes>",
  "cc_eventlog": "<base64-encoded CCEL eventlog, optional>"
}
```

### Dstack TDX Evidence

```json
{
  "quote": "<base64-encoded TDX quote bytes>",
  "event_log": "<JSON-encoded dstack event log, optional>",
  "vm_config": "<VM configuration string, optional>"
}
```

### Verification Result

`Verified` serializes as the platform result plus a `platform` tag, and a `gpu`
object when the evidence carried a GPU bundle. SNP example:

```json
{
  "platform": "snp",
  "claims": {
    "launch_digest": "<96-char hex string (48 bytes)>",
    "report_data": "<128-char hex string (64 bytes)>",
    "signed_data": "<hex-encoded bytes>",
    "init_data": "<hex-encoded bytes>",
    "tcb": { "type": "Snp", "bootloader": 3, "tee": 0, "snp": 8, "microcode": 115 },
    "platform_data": { "...": "..." }
  },
  "report_data_match": true,
  "host_data_match": null,
  "launch_digest_match": null,
  "debug": false,
  "allow_debug": false,
  "vmpl": 0,
  "max_vmpl": 0,
  "reported_tcb": { "bootloader": 3, "tee": 0, "snp": 8, "microcode": 115 },
  "min_tcb_met": null
}
```

## Running Tests

```bash
# Unit tests (no hardware needed)
cargo test --features snp
cargo test --features tdx
cargo test --features az-snp
cargo test --features az-tdx
cargo test --features gcp-snp
cargo test --features gcp-tdx
cargo test --features dstack

# Integration tests on Azure SNP CVM
cargo test --test az_snp_live --features "az-snp,attest" -- --ignored

# Integration tests on Azure TDX CVM
cargo test --test az_tdx_live --features "az-tdx,attest" -- --ignored

# Benchmarks
cargo bench --features snp
cargo bench --features tdx
cargo bench --features az-snp
cargo bench --features az-tdx
cargo bench --features gcp-snp
cargo bench --features gcp-tdx
```

## WASM Support

The library compiles to `wasm32-unknown-unknown` for verifier-only use:

```bash
cargo check --target wasm32-unknown-unknown --no-default-features --features snp,tdx,az-snp,az-tdx,gcp-snp,gcp-tdx,dstack
```

The `attest` feature is automatically excluded on WASM. All verification uses pure-Rust crypto (no OpenSSL dependency).

## Bundled Certificates

AMD root certificates (ARK + ASK) for Milan, Genoa, and Turin processors are embedded at compile time. Per-chip VCEK certificates are fetched on demand from AMD KDS or Azure IMDS.

## License

MIT
