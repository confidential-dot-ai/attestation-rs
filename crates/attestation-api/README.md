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
config does this), a private address for an ingress. The container image runs
with no config and so binds `0.0.0.0:8400`; run it only behind a terminator on
a private network. The service logs a warning at startup when it binds a
non-loopback TCP address. Set `auth.api_keys` before exposing the service.

To serve on a Unix socket instead, set `bind = "unix:///run/attestation-api/api.sock"`
(an absolute path). `socket_mode` sets the socket's mode (default `"0660"`;
modes granting access to other users, or without owner write, are refused) and
`socket_group` chgrps it to a group name or gid, so filesystem permissions
decide who can connect. Unset, the socket keeps the group the filesystem
assigns: the process group, or the parent's under a setgid directory, so set
it explicitly in shared directories. Group names resolve against `/etc/group`
only, not NSS; give a numeric gid for groups from LDAP or sssd. The socket is bound in a private 0700 directory
`.sock-<12 hex>` next to the target, given its mode and group there, then
renamed into place, so it is never connectable with looser permissions. The
process therefore needs write access to the parent directory, which must exist,
and the staging path must fit the platform's socket path limit (107 bytes on
Linux, 103 on macOS and the BSDs). A process killed
mid-bind can leave that directory behind; it is safe to delete. A socket at
the path that refuses connections is replaced; a live one, one the process
cannot connect to, or anything else there is a startup error. That check is
not atomic with the replacement, so run one instance per path. Shutdown
removes the socket file.

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

With `[verify.selected_tdx]`, a TDX guest with attestation enabled can
produce bare CPU evidence over `/attest`. A verifier can accept that
evidence from a separate guest when its own attestation is disabled.
`/verify` requires a TDX policy and `issue_token=false`, and rejects
attached collateral and GPU evidence or policies. HTTP 502 also covers
a helper that times out or cannot obtain the authenticated selection or
site time. `/platform` reports local TDX availability and the `/health`
cache count excludes per-request selections. See the
[helper contract](../../docs/collateral.md#site-selected-tdx).

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
| 502 `collateral_unavailable` | Missing collateral could not be fetched (or not within `verify.fetch_deadline_ms`); bounded retry may help |
| 503 `overloaded` | The queue is full, no worker was free within `verify.queue_deadline_ms`, or the request outlived its total deadline |

502 and 503 carry `Retry-After` (1 s unless a vendor asked for longer); honor it. Match error keys, not
message text. A request for tokens without token configuration also fails;
turn on token configuration before requesting them.

The listener speaks HTTP/1.1 only. List the collateral every request needs in
`[verify] warm`. Missing collateral and NRAS answers are fetched outside the
workers: at most 32 requests in flight per vendor host, 100 NRAS POSTs a second,
and a 429 or 503 from NRAS pauses it. Request bodies take at most
`server.max_connections` × 1 MiB; cap connections per client at the TLS terminator.

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
