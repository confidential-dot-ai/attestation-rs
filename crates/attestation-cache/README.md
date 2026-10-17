# attestation-cache

Keeps vendor collateral (AMD VCEKs and CRLs, Intel TCB Info, QE Identity and
CRLs, Google launch endorsements, the NRAS key set) on disk and serves it at
the vendor's own path: `GET /{vendor host}/{vendor path}?{query}` answers what
`https://{vendor host}/{vendor path}?{query}` would, with the same bytes and
Intel's issuer-chain header. Every piece is verified against the roots
compiled into the attestation library before it is kept or served, so a cache
cannot make a verifier accept collateral the vendor did not sign.

The same binary runs at two levels:

```
vendors  <-  site cache (upstream: the vendors; the only egress to vendors)
         <-  host cache (upstream: the site cache; one per bare-metal host)
         <-  attesters in the host's VMs, over vsock
```

## Behaviour

- One upstream fetch per piece, however many clients ask at once.
- A piece is kept until a newer valid copy replaces it, and refetched at a
  random time in the last quarter of its validity (at least a day before its
  nextUpdate). Pieces are looked at every 10 minutes.
- When the upstream is down, the last good copy is served; after a restart
  pieces are served from disk.
- Answers: `200` with the vendor's bytes; `404` when the vendor does not
  publish the piece, or the path names no collateral; `502` when the only
  copy does not verify; `503` (with `Retry-After` when the upstream sent
  one) when there is no copy and the upstream did not answer.
- Every answer carries `Access-Control-Allow-Origin: *` and exposes the Intel
  issuer-chain headers, so browsers can fetch Intel collateral from it
  (Intel PCS itself sends no CORS headers).

## Guests

Inside a confidential VM the attestation library finds the host's cache by
itself: on its first fetch it connects to vsock port 8455 of the host (CID 2).
When that succeeds, all collateral comes from there and the vendors are never
contacted from the guest; when nothing listens, the guest uses the vendors.
The evidence it makes carries the collateral, so its verifiers need no
network.

## Running

```
cargo build --release -p attestation-cache
install -m 0755 target/release/attestation-cache /usr/local/bin/
install -D -m 0644 crates/attestation-cache/config.example.toml /etc/attestation-cache/config.toml
install -m 0644 crates/attestation-cache/attestation-cache.service /etc/systemd/system/
systemctl enable --now attestation-cache
```

Configuration: see `config.example.toml` (`dir`, `upstream`, `listen`,
`vsock_port`, `warm`). The listener speaks plain HTTP. A site cache that host
caches reach over the network must be served over HTTPS, for example behind
a TLS terminator; hosts accept plain HTTP only from a loopback address.
