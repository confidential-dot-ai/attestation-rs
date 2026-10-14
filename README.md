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

Build the CLI with guest-side CPU attestation and portable NVIDIA GPU bundle
verification:

```bash
cargo build -p attestation-cli --release --features attest,nvidia-gpu
```

The released CLI uses this feature set. GPU evidence collection remains in the
guest attestation service; the CLI verifies the returned bundle via NRAS without
linking NVIDIA's SDK or `libnvat`.

Build the REST service:

```bash
cargo build -p attestation-api --release
docker build .
```

The default API build verifies NVIDIA bundles but does not collect them. A
guest attester that handles `POST /attest` with `nvidia_gpu: true` must be built
with `--features nvidia-gpu-attest` and supplied with NVIDIA's SDK and `libnvat`.

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
  import init, { evaluate_snp } from './pkg/attestation_wasm.js';

  await init(); // fetches and instantiates the .wasm blob

  // evidence: SNP evidence JSON with an inline cert_chain.vcek (base64 DER)
  // generation: "milan" | "genoa" | "turin"
  // expectedReportData (optional): Uint8Array of the nonce to bind against
  const result = JSON.parse(evaluate_snp(
    JSON.stringify(evidence),
    'genoa',
    new TextEncoder().encode('my-nonce'),
  ));
  if (!result.passed) throw new Error('attestation did not pass');
</script>
```

The module also exports `evaluate_az_snp` for full **Azure SEV-SNP** (vTPM)
verification. Unlike `evaluate_snp`, which checks only the bare SNP hardware report,
it verifies the HCL-wrapped report *and* the vTPM quote — the TPM signature against
the attestation key (AK) in the HCL runtime data, the AK→TEE binding, and the
freshness anchor in the quote's `extraData` (not the SNP `report_data`). The
processor generation is auto-detected from the report CPUID, so no `generation`
argument is needed:

```js
import init, { evaluate_az_snp } from './pkg/attestation_wasm.js';
await init();
// evidence: AzSnpEvidence JSON { version, tpm_quote, hcl_report, vcek }
// expectedReportData (optional): Uint8Array the quote's extraData must equal
const resultJson = evaluate_az_snp(JSON.stringify(evidence), expectedReportData);
```

It returns the same top-level keys as `evaluate_snp` (with `platform: "az-snp"`),
including `passed`. The other exports are `evaluate` (any accepted platform,
from a `{ platform, evidence }` envelope and a required list of accepted
platform tags), `evaluate_tdx` and `evaluate_az_tdx`. Every export throws only
when the evidence cannot be evaluated; mismatches and policy flags are fields,
so the caller must read `passed`. (The exports were named `verify*` before the
result shape changed; the rename makes old callers that treated "no throw" as
success fail loudly.) Without a CRL argument the revocation check is skipped.

For a Node.js end-to-end example (generate live evidence, fetch the VCEK from AMD
KDS, verify in WASM), build with `--target nodejs` and run
`crates/attestation-wasm/example.mjs`.

## Verifying evidence

Callers say which platforms they accept and what each must satisfy, with one
params type per platform:

```rust
use attestation::{Policies, TdxParams};

let policies = Policies {
    tdx: Some(TdxParams {
        report_data: Some(nonce.to_vec()),
        mrtd: Some(mrtd_bytes),                  // [u8; 48]
        rtmr: [None, Some(rtmr1_bytes), None, None],
        ..Default::default()
    }),
    ..Default::default()
};

let verified = attestation::verify(&evidence_json, &policies).await?;
if !verified.passed() { /* refuse */ }
```

To accept any platform with its default checks, and require your nonce:

```rust
let verified = attestation::verify(&evidence_json, &Policies::all().with_report_data(&nonce)).await?;
```

`Err` means the evidence could not be verified (malformed, not genuine,
platform not allowed, invalid params) or, retryably, that collateral could not
be fetched (`CollateralUnavailable`). A genuine answer the caller may not like
is a value: mismatches are `*_match: Some(false)`, and debug, VMPL, minimum TCB
and TCB status are fields. `passed()` is true only when every rule held. Pins,
`report_data` and init data are compared in constant time.

The CLI exposes matching flags:

```bash
attestation-cli verify \
  --evidence evidence.json \
  --platform tdx \
  --expected-mrtd $MRTD \
  --expected-rtmr1 $RTMR1 \
  --expected-rtmr2 $RTMR2
```

`--platform` (repeatable) says which platforms to accept. Without it, the
platform-specific pins decide (`--expected-mrtd`/`--expected-rtmrN`: the TDX
platforms; `--expected-launch-digest`: the SNP platforms); the evidence's own
platform tag never does. A pin an accepted platform does not have
(`--expected-mrtd` with `--platform snp`) is a usage error. `--offline`
verifies without network access.

| Exit code | Meaning |
|---|---|
| 0 | Passed: genuine, and every rule in the flags held |
| 1 | Did not pass, or the evidence is not genuine |
| 2 | Usage error or invalid params |
| 3 | Collateral unavailable (AMD KDS, Intel PCS, NRAS); retrying may help |

## Documentation

- Core library: `crates/attestation/README.md`
- REST service: `crates/attestation-api/README.md`

## Confidential e2e (SNP-metal)

`.github/workflows/confidential-e2e.yml` runs this workspace's TEE-gated tests
**inside a real SEV-SNP CVM** on every push to `main` (and via dispatch) — the
`has_tee()` real paths, the `#[ignore]`d attest tests, and the network CRL/DCAP
tests, none of which can pass on a hosted runner. It builds a `cargo nextest
archive` outside the TEE, pulls it into a measured CVM, and runs it there via
the confidential-ci `cvm-e2e` primitive. `az_snp_live`/`az_tdx_live` run on the
Azure lane instead (vTPM). Never `pull_request` — org self-hosted hardware.

One-time after the first run: set the auto-created `ci-tests` package **public**
and the repo's role on it to **Write** (org → Packages). Details and the
matrix/dispatcher pattern: confidential-dot-ai/confidential-ci
`USING-THE-PRIMITIVE.md`.
