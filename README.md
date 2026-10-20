# attestation-rs

[![CI](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml)

Generate TEE evidence in a guest and verify it in Rust, a command-line tool,
an HTTP service, or WebAssembly. Verification checks vendor signatures and
caller-selected policies. **Accept only when `passed()` / `passed` is true.**
A valid signature alone does not establish an approved workload or freshness.

These docs describe this checkout. For changes from the released 0.5.0
interface, see [Migration](docs/migration.md).

## Choose an interface

| Package | Guide | Use |
| --- | --- | --- |
| `attestation` | [Rust and shared Policies](crates/attestation/README.md) | Embed generation or verification |
| `attestation-cli` | [CLI](crates/attestation-cli/README.md) | Generate evidence; verify files or stdin |
| `attestation-api` | [HTTP API](crates/attestation-api/README.md) | Serve attestation and verification; optionally issue JWTs |
| `attestation-wasm` | [WASM](crates/attestation-wasm/README.md) | Verify in JS with caller-supplied collateral |
| `attestation-cache` | [Cache operations](crates/attestation-cache/README.md) | Mirror verified vendor collateral for hosts and sites |

Read [evidence and collateral](docs/collateral.md) for the lifecycle, trust
boundaries, offline use, freshness and upstream discovery.

## Capabilities

| Evidence | Rust | CLI / HTTP API | WASM harness |
| --- | --- | --- | --- |
| `snp`, `tdx` | Generate / verify | Generate / verify | Verify |
| `az-snp`, `az-tdx` (vTPM) | Generate / verify | Generate / verify | Verify |
| `gcp-snp`, `gcp-tdx` (non-vTPM) | Generate / verify | Generate / verify | Verify |
| `dstack` (TDX socket) | Generate / verify, opt-in feature | Not exposed | Verify |
| NVIDIA GPU bundle alongside CPU evidence | Opt-in collection / verification | Opt-in collection; portable verification | Not enabled |

Generation needs Linux, the matching guest devices or socket, and `attest`.
GPU collection also needs `nvidia-gpu-attest`, NVIDIA's SDK and `libnvat`;
portable verification uses `nvidia-gpu` without that SDK. It depends on a
nonce-bound NRAS answer, not just cached signing keys. See the
[GPU limitations](docs/collateral.md#nvidia-gpu).
The matrix describes interfaces, not a claim of live hardware coverage.

The six CPU platform features are on by default in the Rust library;
`dstack` and NVIDIA support are opt-in. The API explicitly refuses dstack
policy keys and evidence, even if dependency feature unification enables it.
Cloud tags select checks; they are not proof of cloud-provider identity.

## Build and check

Run from the workspace root with Rust and Cargo:

```sh
cargo build --locked -p attestation-cli --release --features attest,nvidia-gpu
cargo build --locked -p attestation-api --release
cargo build --locked -p attestation-cache --release
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
```

The default API build verifies GPU bundles but does not collect them. For
collection, build the API with `--features nvidia-gpu-attest` on a suitably
provisioned Linux guest. `docker build .` builds the API image; the published
image is `ghcr.io/confidential-dot-ai/attestation-api`.

Tests include fixtures, network tests and hardware-gated paths. A successful
local doc build or unit test run does not establish live TEE, GPU or deployment
coverage. See individual guides for hardware-only examples.
