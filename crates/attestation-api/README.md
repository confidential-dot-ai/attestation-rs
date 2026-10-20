# Attestation Service

[![CI](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml)

A REST API service for generating and verifying Trusted Execution Environment (TEE) attestation evidence. Built in Rust with Axum, it wraps the `attestation-rs` library to expose attestation workflows over HTTP.

## Supported Platforms

- AMD SEV-SNP
- Intel TDX
- Azure and Google Cloud SNP / TDX variants

The API does not accept dstack evidence or policy keys (including null keys),
regardless of workspace features. On a dstack host, automatic detection uses
bare TDX only when that interface is available. The library and WASM retain
dstack support.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with cache stats |
| `GET` | `/platform` | Detect TEE platform |
| `POST` | `/attest` | Generate attestation evidence (requires `attestation.enabled = true`) |
| `POST` | `/verify` | Verify evidence, optionally issue a JWT |
| `GET` | `/token/jwks` | JWKS for issued attestation JWTs |

## Quick Start

```bash
# Build
cargo build -p attestation-api --release

# Run with default config (config.toml)
cargo run -p attestation-api --release

# Run with a custom config
cargo run -p attestation-api --release -- -c crates/attestation-api/config.example.toml

# Run tests
cargo test -p attestation-api

# Build the container image from the workspace root
docker build .
```

## Configuration

Configuration is TOML-based. See `config.example.toml` for all options. An unknown key is a startup error that names it, so a misspelt or removed option (for example the old `vcek_ttl_hours` or `skip_snp_crl`) is never silently ignored.

```toml
[server]
bind = "0.0.0.0:8400"

[server.tls]
enabled = false
cert_path = ""
key_path = ""

[auth]
api_keys = []                   # Bearer tokens; empty = no auth (warning logged)

[nras]
gpu_url = ""                    # Empty = NV_NRAS_GPU_URL, else NVIDIA's endpoint
switch_url = ""

[token]
enabled = false
issuer = "attestation-api"
duration_minutes = 5
key_path = ""                   # Empty = ephemeral key

[attestation]
enabled = true                  # Set to false to disable /attest
platforms = ["snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"]
allow_debug = false             # Accept policies with allow_debug = true
allow_revoked_or_unlisted_tcb = false  # Accept "Revoked" or "NoMatchingLevel" in accepted_tcb_statuses
allow_nonzero_vmpl = false      # Accept max_vmpl above 0
```

## Authentication

When `auth.api_keys` contains one or more Bearer tokens, all endpoints except `/health` require a valid `Authorization: Bearer <token>` header. If no API keys are configured the service runs unauthenticated and logs a warning on startup.

## Attestation

The `/attest` endpoint is available when `attestation.enabled = true` (the default). Set it to `false` on verification-only deployments. The `attestation.platforms` list controls which platforms the service is allowed to generate evidence for.

## Collateral

The service verifies with one in-memory collateral store for its lifetime:
AMD, Intel, Google and NVIDIA collateral is fetched on first use, checked
against the vendor roots compiled into the library, kept, and refetched near
its nextUpdate (a failed refetch keeps the current copy). A piece held
nowhere and not fetchable is `502 collateral_unavailable` (with `Retry-After`
when the vendor sent one); a piece that is not the vendor's is `422
verification_failed`.

All callers, including unauthenticated `/verify` callers, share a limit of
10 new pieces per second per vendor host. Put the API behind per-client rate
limiting so forged requests cannot exhaust this shared fetch budget.

## Usage Examples

**Generate attestation evidence:**

```bash
curl -X POST http://127.0.0.1:8400/attest \
  -H "Content-Type: application/json" \
  -d '{"platform": "auto", "report_data": "AQIDBA=="}'
```

**Verify evidence and get a JWT:**

`policies` lists the platforms you accept, each with its params (byte values
in base64). Evidence for a platform without an entry is refused.

```bash
curl -X POST http://127.0.0.1:8400/verify \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "snp",
    "evidence": { ... },
    "policies": {
      "snp": { "report_data": "AQIDBA==", "launch_digest": "<48 bytes>" },
      "tdx": { "report_data": "AQIDBA==", "mrtd": "<48 bytes>" }
    },
    "issue_token": true
  }'
```

Params per platform: `tdx`, `az-tdx`, `gcp-tdx` take `report_data`,
`init_data`, `mrtd`, `rtmr0`..`rtmr3`, `allow_debug`, `accepted_tcb_statuses`
(`mrtd`, `rtmr0`..`rtmr3` and `launch_digest` take one value or an array of
allowed values);
`snp`, `az-snp`, `gcp-snp` take `report_data`, `host_data`, `launch_digest`,
`allow_debug`, `min_tcb`, `max_vmpl`; `az-tdx` and `az-snp` also take `pcrs`
(`{ "<index>": "<32 bytes>" }`, index 0-23, each index once);
`nvidia_gpu` takes `user_nonce`,
`required`, `expected_archs`, `allowed_bindings`, `device_policy`; `floors`
raises the lowest accepted collateral versions (`amd_crl_milan`,
`amd_crl_genoa`, `amd_crl_turin`, `intel_tcb_info`, `intel_qe_identity`).
A field the platform does not have is a `400`. This is `attestation::Policies`
as JSON, the same shape the WASM `evaluate` takes.

The server sets floors: `allow_debug: true`, `max_vmpl` above 0, and a TCB
status Intel does not consider valid (`"Revoked"`, `"NoMatchingLevel"`) in
`accepted_tcb_statuses` are a `400` unless the matching `attestation.allow_*`
option is enabled (`allow_debug` covers `nvidia_gpu.device_policy.allow_debug`
too); `floors` below the shipped versions and a `device_policy` that drops
`require_secboot` or `require_measres_success` are always a `400`. `issue_token` requires a non-empty `report_data` in the policy for the
evidence's platform.

A token alone is not fresh: anyone who can call `/verify` can replay old
evidence with that evidence's own `report_data` and get a new token. A relying
party must compare `policy.<platform>.report_data` in the token (`<platform>`
is the token's `platform` claim) to the nonce it issued, and refuse the token
if they differ.

Responses:

- `200` with `{ "result": ..., "passed": bool, "token"?: "..." }` for genuine
  evidence. `passed` is true only when every rule held; the token is issued
  only then. Its `result` claim is the result and its `policy` claim is the
  `policies` it was evaluated against.
- `400 bad_request` for a malformed body or invalid params.
- `413 payload_too_large` for a body over 1 MiB.
- `415 unsupported_media_type` without `Content-Type: application/json`.
- `502 collateral_unavailable` when collateral could not be fetched (retry).
- `422 platform_not_allowed` for evidence of a platform without a policy.
- `422 verification_failed` for evidence that cannot be verified.

## Key Features

- **Collateral** — One in-memory store of verified vendor collateral, shared by all requests
- **JWT issuance** — Optional ES256 token generation after successful verification
- **TLS support** — Optional HTTPS with configurable cert/key paths
- **Load testing** — Built-in load test binary (`cargo run -p attestation-api --release --bin loadtest`)
- **Structured logging** — JSON-formatted tracing output
- **Graceful shutdown** — Handles SIGTERM and Ctrl+C

## Container Image

CI publishes the service image as `ghcr.io/confidential-dot-ai/attestation-api`.
