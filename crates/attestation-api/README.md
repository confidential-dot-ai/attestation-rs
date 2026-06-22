# Attestation Service

[![CI](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/confidential-dot-ai/attestation-rs/actions/workflows/ci.yml)

A REST API service for generating and verifying Trusted Execution Environment (TEE) attestation evidence. Built in Rust with Axum, it wraps the `attestation-rs` library to expose attestation workflows over HTTP.

## Supported Platforms

- AMD SEV-SNP
- Intel TDX
- Azure SNP / TDX variants

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check with cache stats |
| `GET` | `/platform` | Detect TEE platform |
| `POST` | `/attest` | Generate attestation evidence (requires `attestation.enabled = true`) |
| `POST` | `/verify` | Verify evidence, optionally issue a JWT |
| `GET` | `/certs/status` | Certificate cache status |
| `POST` | `/certs/refresh` | Force certificate refresh |
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

Configuration is TOML-based. See `config.example.toml` for all options.

```toml
[server]
bind = "0.0.0.0:8400"

[server.tls]
enabled = false
cert_path = ""
key_path = ""

[auth]
api_keys = []                   # Bearer tokens; empty = no auth (warning logged)

[certs]
cache_max_entries = 1024
vcek_ttl_hours = 24
chain_ttl_hours = 168           # 7 days
crl_refresh_hours = 6
tdx_collateral_ttl_hours = 24
prefetch_chains = ["milan"]

[token]
enabled = false
issuer = "attestation-api"
duration_minutes = 5
key_path = ""                   # Empty = ephemeral key

[attestation]
enabled = true                  # Set to false to disable /attest
platforms = ["snp", "tdx", "az-snp", "az-tdx", "gcp-snp", "gcp-tdx"]
```

## Authentication

When `auth.api_keys` contains one or more Bearer tokens, all endpoints except `/health` require a valid `Authorization: Bearer <token>` header. If no API keys are configured the service runs unauthenticated and logs a warning on startup.

## Attestation

The `/attest` endpoint is available when `attestation.enabled = true` (the default). Set it to `false` on verification-only deployments. The `attestation.platforms` list controls which platforms the service is allowed to generate evidence for.

## Usage Examples

**Generate attestation evidence:**

```bash
curl -X POST http://127.0.0.1:8400/attest \
  -H "Content-Type: application/json" \
  -d '{"platform": "auto", "report_data": "AQIDBA=="}'
```

**Verify evidence and get a JWT:**

```bash
curl -X POST http://127.0.0.1:8400/verify \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "snp",
    "evidence": { ... },
    "params": {
      "nonce": "AQIDBA==",
      "allow_debug": false
    },
    "issue_token": true
  }'
```

## Key Features

- **Certificate caching** — Multi-layer async cache (Moka) with configurable TTLs and background refresh
- **JWT issuance** — Optional ES256 token generation after successful verification
- **TLS support** — Optional HTTPS with configurable cert/key paths
- **Load testing** — Built-in load test binary (`cargo run -p attestation-api --release --bin loadtest`)
- **Structured logging** — JSON-formatted tracing output
- **Graceful shutdown** — Handles SIGTERM and Ctrl+C

## Container Image

CI publishes the service image as `ghcr.io/confidential-dot-ai/attestation-api`.
