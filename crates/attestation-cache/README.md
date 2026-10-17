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
  nextUpdate). The `warm` pieces and up to 1024 pieces every client of a kind
  needs (CRLs, TCB Info, QE Identity, the NRAS key set) are looked at every
  10 minutes; per-chip VCEKs and GCE endorsements are not refreshed ahead.
- At most 16 pieces not in memory are fetched at once; a request for another
  one gets `503` with `Retry-After: 5`. At most 10 pieces held nowhere (not
  in memory, not on disk) are fetched from one vendor host per second; more
  get `503` with `Retry-After: 1`. After an upstream outage, a piece is not
  asked for again for 10 seconds (or the upstream's Retry-After); its
  clients get `503` meanwhile. A `429` or `503` from the upstream pauses
  every fetch to that vendor host for its Retry-After (10 seconds without
  one).
- A connection must send its request headers within 10 seconds, and is
  closed after 60 seconds.
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
itself: it asks `GET /health` at vsock port 8455 of the host (CID 2). Once
that answers 200, all collateral comes from there and the vendors are never contacted
from the guest; while nothing listens, the guest uses the vendors and tries
the host again every minute. A `404` from a cache is not taken as the
vendor's word: to the guest it is `CollateralUnavailable`, not a refusal.
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
`vsock_port`, `warm`). The listener speaks plain HTTP.

`GET /health` answers 200 while the process runs; `GET /ready` answers 200
once a piece was fetched (a `warm` one or any served), or at once when
`warm` is empty; 503 before.

Every request is logged at info level (target `attestation_cache::request`):
method, path, status, where a served piece came from (`memory`, `disk`,
`vendor`, `cache`) and the time taken. A request without a valid key is
logged at warn, and a piece refused for not verifying at warn. Keys,
`Authorization` headers and bodies are never logged. Set `RUST_LOG` (default
`info`) to change the level.

With `keys` set, every other request needs `Authorization: Bearer KEY` with
one of them (else 401); a host cache sends its site's key with
`upstream_key`. Keys are compared in constant time and never logged. Use
keys only over HTTPS (behind the TLS terminator). Keys apply to every
listener, vsock included, and guests never send a key: so set `keys` on site
caches, not on a host cache that serves guests (keep its TCP listener on
loopback instead).

A site cache reachable by anyone beyond its intended clients must set
`keys`: without them, anyone can make it fetch new pieces (for example many
made-up VCEKs) and use up the site's request budget at the vendor. The rate
limits above bound this, but also slow the site's real clients while it
lasts.

## Replicas

A hosted site cache can run as N replicas behind a load balancer (health
check `/health`, traffic once `/ready`). Replicas share nothing: each has its
own `dir` and its own memory, and each fetches from the vendors by itself.
So vendor load grows with N: each replica fetches each piece once when first
asked, then about once per piece validity (Intel and AMD CRLs, TCB Info and
QE Identity: about monthly; the NRAS key set: hourly while used), plus one
VCEK and one GCE endorsement per chip or image it is asked for. With about
15 shared pieces this is on the order of a thousand requests per replica per
month, most of them for the NRAS key set. A host cache whose upstream is the load balancer may reach a
different replica each time; that is fine, as every replica serves verified
vendor bytes.

Without `keys`, it is an unauthenticated mirror of public vendor collateral: anyone who can
reach it can make it fetch from the vendors, within the limits above (see keys). Make it
reachable only by its intended clients (loopback and the host's guests over
vsock for a host cache; the host caches, for a site cache). A site cache that host
caches reach over the network must be served over HTTPS, for example behind
a TLS terminator; hosts accept plain HTTP only from a loopback address.
