# attestation-api

HTTP generation and verification over the [Rust library](../attestation/README.md).
The API accepts the six CPU platforms and optional NVIDIA bundles; it refuses
dstack evidence and policy keys (even null keys), regardless of workspace
features. See [capabilities](../../README.md#capabilities).

## Run and configure

From the workspace root:

```sh
cargo build --locked -p attestation-api --release
cargo run --locked -p attestation-api --release --bin attestation-api --   -c crates/attestation-api/config.example.toml
cargo test --locked -p attestation-api
```

[config.example.toml](config.example.toml) is the configuration reference.
Unknown keys are startup errors, including the removed `[certs]` settings.
Default bind is `0.0.0.0:8400`, API keys are empty, `/attest` is enabled and
token issuance is disabled. These are development defaults, not an
access-control recommendation. The service speaks plain HTTP only and refuses
`server.tls.enabled = true`. Terminate TLS in front of it and bind to an
address only the terminator reaches: loopback for a sidecar (the example
config does this), a private address for an ingress. Set `auth.api_keys`
before exposing the service.

All endpoints except `/health` require `Authorization: Bearer TOKEN` when
keys are configured. An empty list allows unauthenticated access and logs a
warning. Set `attestation.enabled = false` for a verifier-only deployment.
`attestation.platforms` restricts generation, not the caller's verification
policy. Default builds verify NVIDIA bundles; GPU collection requires
`--features nvidia-gpu-attest` plus the SDK/runtime on Linux.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Process health and store statistics |
| GET | `/platform` | Guest platform detection |
| POST | `/attest` | Generate evidence, attempt collateral attachment |
| POST | `/verify` | Evaluate evidence and policy; optionally issue a JWT |
| GET | `/token/jwks` | Public keys for issued JWTs |

## Generate evidence

This example is for an unauthenticated local development service on a supported
Linux guest. In real use choose a fresh random challenge and send the bearer
header when configured. `AQIDBA==` is an illustrative challenge, not a secure
nonce-generation procedure:

```sh
curl --fail-with-body http://127.0.0.1:8400/attest   -H 'Content-Type: application/json'   -d '{"platform":"auto","report_data":"AQIDBA=="}' > evidence.json
```

The response is an envelope with `platform`, `evidence`, optional `nvidia_gpu`
and `collateral`. Preserve all fields. Generation can succeed without complete
collateral: see [attachment semantics](../../docs/collateral.md#lifecycle-and-trust).
GPU generation adds `"nvidia_gpu": true` and requires a nonce of at least
16 bytes.

## Verification and tokens

Use the [shared policy contract](../attestation/README.md#policies). `/verify`
takes platform-specific `evidence`, not a nested envelope. This example uses
`jq` to preserve the generated envelope and add an independently selected SNP
policy (choose the intended platform, never infer it from the received tag):

```sh
jq '. + {policies: {snp: {report_data: "AQIDBA=="}}, issue_token: false}'   evidence.json > verify-request.json
curl --fail-with-body http://127.0.0.1:8400/verify   -H 'Content-Type: application/json' --data-binary @verify-request.json
```

This policy checks a challenge and defaults only; add trusted measurement pins
for workload identity. A non-SNP envelope is refused by this SNP-only policy.
The result is `{ "result": ..., "passed": bool, "token": ... }`, with token
omitted when not issued. **HTTP 200 does not mean passed.**

The server additionally refuses these policies with 400:

- `allow_debug: true` (including GPU device policy), unless
  `attestation.allow_debug` is enabled;
- SNP `max_vmpl > 0`, unless `allow_nonzero_vmpl` is enabled;
- TDX `Revoked` / `NoMatchingLevel`, unless
  `allow_revoked_or_unlisted_tcb` is enabled;
- collateral floors below shipped defaults, always;
- GPU device policy disabling `require_secboot` or `require_measres_success`, always.

For JWT issuance, enable `[token]`, then request `issue_token: true`. The policy
for the evidence's platform must contain nonempty `report_data`. A token is
issued only on a passing result. Tokens use ES256 and include `result` and the
serialized policy as `policy`. Default duration is 5 minutes; an empty key path
uses an ephemeral key, so configure persistence if keys must survive restart.

For SNP measurement registers, add `measurement_registers` to the `snp`
policy ([semantics](../attestation/README.md#snp-kernel-measurement-registers));
`report_data` is then the requester's 64 bytes. The token's
`result.measurement_registers` carries the registers only on a passing result.

A newly issued token is **not proof of fresh evidence**: callers could replay
old evidence and ask for a new token. The relying party must validate the token
and compare `policy.<platform>.report_data` with its own outstanding challenge,
where `<platform>` is the token's platform claim.

## Errors and collateral

| Response | Meaning |
| --- | --- |
| 200 | Evaluated; inspect `passed` |
| 400 `bad_request` | Malformed request or invalid/disallowed params |
| 401 | Missing/incorrect configured bearer token |
| 413 `payload_too_large` | Body exceeds 1 MiB |
| 415 `unsupported_media_type` | Missing JSON content type |
| 422 `platform_not_allowed` | No policy for the evidence platform |
| 422 `verification_failed` | Evidence/collateral cannot be verified |
| 502 `collateral_unavailable` | Missing collateral could not be fetched; bounded retry may help |

Honor `Retry-After` on collateral failures when provided. Match error keys, not
message text. A request for tokens without token configuration also fails;
turn on token configuration before requesting them.

One in-memory verifier/store is reused for the process. The API has no disk
cache or explicit collateral-upstream configuration. It uses native
[host discovery](../../docs/collateral.md#upstream-selection) and attached
collateral; a host/site cache can provide persistence outside the API.
`[nras]` overrides NRAS endpoints, not collateral-cache routing.

All requests share a limit of 10 new pieces per second per vendor host. Apply
per-client rate limiting at the boundary, especially with public verification:
forged evidence can consume the shared fetch budget. The service does not
replace workload authorization, challenge management or network access control.

## Container

`docker build .` builds the API image from the workspace root. The published
image is `ghcr.io/confidential-dot-ai/attestation-api`. No deployment or live
hardware validation is implied by the examples above.
