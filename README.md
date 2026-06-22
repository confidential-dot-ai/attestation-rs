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
  // expectedNonce (optional): Uint8Array of the nonce to bind against
  const resultJson = verify_snp(
    JSON.stringify(evidence),
    'genoa',
    new TextEncoder().encode('my-nonce'),
  );
  // result: { signature_valid, collateral_verified, nonce_match,
  //           launch_measurement, report_data, ... }
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
// expectedNonce (optional): Uint8Array the quote's extraData must equal
const resultJson = verify_az_snp(JSON.stringify(evidence), expectedNonce);
```

It returns the same result shape as `verify_snp` with `platform: "az-snp"`. The
WASM path skips the async CRL revocation check (`collateral_verified: false`); the
native async `az_snp::verify::verify_evidence` adds it via a `CertProvider`.

For a Node.js end-to-end example (generate live evidence, fetch the VCEK from AMD
KDS, verify in WASM), build with `--target nodejs` and run
`crates/attestation-wasm/example.mjs`.

## Pinning launch measurements

`VerifyParams` splits policy anchors into two layers:

1. **Canonical anchors** that every vendor exposes uniformly:
   `nonce`, `report_data`, and `launch_measurement` (a 48-byte synthetic
   digest — see [Canonical launch_measurement formula](#canonical-launch_measurement-formula)).
2. **Vendor-specific pins** that only make sense for one TEE family
   (MRTD/RTMRs for TDX, `min_tcb` for SNP, AK thumbprint for Azure
   overlays). These live in the `vendor: VendorParams` enum.

```rust
use attestation::{VerifyParams, VendorParams, VerifyTdx};

// Canonical-only: works on any platform.
let params = VerifyParams {
    nonce: Some(nonce.to_vec()),
    launch_measurement: Some(canonical_lm.to_vec()), // 48-byte SHA-384
    ..Default::default()
};

// Vendor-precise: pin per-RTMR digests on a TDX deployment.
let params = VerifyParams {
    nonce: Some(nonce.to_vec()),
    vendor: VendorParams::Tdx(VerifyTdx {
        mrtd: Some(mrtd_bytes),
        rtmrs: [None, Some(rtmr1), Some(rtmr2), None],
        mr_config_id: None,
    }),
    ..Default::default()
};

let result = attestation::verify(&evidence_json, &params).await?;
assert!(result.signature_valid);
assert!(!result.policy_failed());
```

All comparisons are constant-time (`subtle::ConstantTimeEq`) and do not
short-circuit — every populated reference is checked. `VerifyResult` is
`#[must_use]`, so dropping it without inspecting the policy outcomes is
a compile-time warning.

`result.policy_failed()` aggregates ALL pin outcomes (canonical and
vendor-specific) into a single `bool`. The CLI uses it as the exit-code
gate.

### Canonical launch_measurement formula

| Vendor                              | Formula                                                |
|-------------------------------------|--------------------------------------------------------|
| TDX / AzTdx / GcpTdx / Dstack       | `SHA-384(mrtd ‖ rtmr1 ‖ rtmr2 ‖ rtmr3)` (48 bytes)     |
| SNP / AzSnp / GcpSnp                | `report.measurement` verbatim (48 bytes)               |

RTMR3 is included because it is runtime-extendable by the guest
(`TDG.MR.RTMR.EXTEND`), letting workloads bind application-specific data
(model hashes, config digests) into the canonical identity. This formula
is **locked** — changing it would invalidate every pinned reference in
the wild.

### CLI

```bash
attestation-cli verify \
  --evidence evidence.json \
  --nonce $NONCE_HEX \
  --launch-measurement $CANONICAL_LM_HEX
# exit 0 on success; exit 1 on signature failure OR any policy mismatch.
```

The CLI exposes only the **canonical** anchors. Vendor-precise pinning
is library-only; callers who need per-RTMR control write Rust.

## Documentation

- Core library: `crates/attestation/README.md`
- REST service: `crates/attestation-api/README.md`
