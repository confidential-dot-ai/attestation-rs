# Attestation Workspace

[![CI](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml)

Rust workspace for TEE attestation libraries, tools, and services.

## Workspace Members

| Package | Path | Description |
| --- | --- | --- |
| `attestation` | `crates/attestation` | Core TEE attestation evidence generation and verification library |
| `attestation-cli` | `crates/attestation-cli` | CLI for generating and verifying attestation evidence |
| `attestation-api` | `crates/attestation-api` | REST API service wrapping the attestation library |
| `attestation-wasm` | `crates/attestation-wasm` | WASM verification harness |

## Common Commands

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Build the CLI with guest-side attestation support:

```bash
cargo build -p attestation-cli --release --features attest
```

Build the REST service:

```bash
cargo build -p attestation-api --release
docker build .
```

The service image is published as `ghcr.io/confidential-dot-ai/attestation-api`.

## WASM verification in the browser

`attestation-wasm` compiles the SNP verification path to WebAssembly so evidence
can be verified entirely client-side. To produce a blob usable in a browser, build
with the `web` target (this requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/)):

```bash
cd crates/attestation-wasm
wasm-pack build --target web --release
```

This writes an ES module and the `.wasm` binary to `pkg/`:

- `pkg/attestation_wasm.js` — JS bindings and the `init` loader
- `pkg/attestation_wasm_bg.wasm` — the WASM blob

Serve `pkg/` over HTTP (browsers won't load WASM from `file://`) and use it from a
module script:

```html
<script type="module">
  import init, { verify_snp } from './pkg/attestation_wasm.js';

  await init(); // fetches and instantiates the .wasm blob

  // evidence: SNP evidence JSON with an inline cert_chain.vcek (base64 DER)
  // generation: "milan" | "genoa" | "turin"
  // expectedReportData (optional): Uint8Array of the nonce to bind against
  const resultJson = verify_snp(
    JSON.stringify(evidence),
    'genoa',
    new TextEncoder().encode('my-nonce'),
  );
  console.log(JSON.parse(resultJson));
</script>
```

The module also exports `verify_az_snp` for full **Azure SEV-SNP** (vTPM)
verification. Unlike `verify_snp`, which checks only the bare SNP hardware report,
it verifies the HCL-wrapped report *and* the vTPM quote — the TPM signature against
the attestation key (AK) in the HCL runtime data, the AK→TEE binding, and the
freshness anchor in the quote's `extraData` (not the SNP `report_data`). The
processor generation is auto-detected from the report CPUID, so no `generation`
argument is needed:

```js
import init, { verify_az_snp } from './pkg/attestation_wasm.js';
await init();
// evidence: AzSnpEvidence JSON { version, tpm_quote, hcl_report, vcek }
// expectedReportData (optional): Uint8Array the quote's extraData must equal
const resultJson = verify_az_snp(JSON.stringify(evidence), expectedReportData);
```

It returns the same result shape as `verify_snp` with `platform: "az-snp"`. The
WASM path skips the async CRL revocation check (`collateral_verified: false`); the
native async `az_snp::verify::verify_evidence` adds it via a `CertProvider`.

For a Node.js end-to-end example (generate live evidence, fetch the VCEK from AMD
KDS, verify in WASM), build with `--target nodejs` and run
`crates/attestation-wasm/example.mjs`.

## Pinning launch measurements

`VerifyParams` carries optional reference values that the verifier compares
against the measurement registers in the quote. When the operator supplies a
value, the corresponding `VerificationResult` field is `Some(true)`/`Some(false)`;
when omitted the result is `None` (no check requested).

```rust
use attestation::types::VerifyParams;

let params = VerifyParams {
    // TDX policy
    expected_mrtd: Some(mrtd_bytes),                   // [u8; 48]
    expected_rtmr1: Some(rtmr1_bytes),
    expected_rtmr2: Some(rtmr2_bytes),
    // SNP policy
    expected_launch_digest: Some(launch_digest_bytes), // [u8; 48]
    // existing fields
    expected_report_data: Some(nonce.to_vec()),
    ..Default::default()
};

let result = attestation::verify(&evidence_json, &params).await?;
assert_eq!(result.mrtd_match, Some(true));
assert_eq!(result.rtmr1_match, Some(true));
assert_eq!(result.rtmr2_match, Some(true));
```

All comparisons are constant-time (`subtle::ConstantTimeEq`) and do not
short-circuit — every populated reference is checked. `VerificationResult`
carries `#[must_use]` so dropping the result without inspecting the policy
outcomes is a compile-time warning.

The CLI exposes matching flags:

```bash
attestation-cli verify \
  --evidence evidence.json \
  --expected-mrtd $MRTD \
  --expected-rtmr1 $RTMR1 \
  --expected-rtmr2 $RTMR2
# exit 0 on full match; exit 1 on any explicit --expected-* mismatch.
```

A failing `--expected-*` check forces the process to exit non-zero, so a
CI gate using these flags fails closed on a wrong workload.

## Documentation

- Core library: `crates/attestation/README.md`
- REST service: `crates/attestation-api/README.md`
