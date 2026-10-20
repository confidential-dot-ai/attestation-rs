# Evidence and collateral

## Lifecycle and trust

1. A relying party issues a fresh challenge and chooses accepted platforms,
   workload measurements and other [Policies](../crates/attestation/README.md#policies).
2. An attester produces an `AttestationEvidence` JSON envelope: `platform`,
   platform-specific `evidence`, optional `nvidia_gpu`, and optional `collateral`.
   `attestation::attest(platform, report_data, &options)` produces CPU evidence;
   it does **not** attach collateral itself.
3. `Verifier::attach_collateral(&evidence, report_data)` gathers collateral
   through its store and returns the augmented envelope. CLI `attest` and API
   `/attest` attempt this automatically. Preserve the whole envelope in transit.
4. A verifier authenticates evidence and collateral, evaluates the policy and
   checks freshness. The caller must check the complete `Verified::passed()`:
   `verified.platform.passed()` alone omits collateral and GPU checks.

Collateral supplies AMD VCEKs and CRLs, Intel TCB Info/QE Identity/CRLs,
Google launch endorsements and NVIDIA NRAS signing keys. Each piece is checked
against compiled-in vendor trust anchors and the identity named by the evidence.
The NRAS JWKS is not itself signed: its keys carry certificate chains; the
actual token signing key and its validity are checked when used.

An attached item is `{ "url": "<vendor URL>", "body": "<standard base64>",
"issuer_chain": "<optional PEM>" }`. Attachment omits roots and deduplicates
issuer chains: a piece without a chain inherits the preceding chain. Do not
reorder or selectively reconstruct the array. Attached copies are untrusted
inputs, not new trust anchors; an invalid attached piece is an error even if
another source has a good copy.

Attachment is best effort for unavailable collateral. The vendor client
retries short outages once; attachment keeps what it gathered, without an
incomplete NRAS signing-key set. CLI/API can still return evidence if attachment
fails. A successful attest response is not proof that a disconnected verifier
will have everything it needs.

## Store and offline use

`attestation::verify` reuses one process-wide store. For explicit lifecycle,
reuse a `Verifier::new(Context::new())`. Native contexts use memory and network;
`with_cache_dir(dir)` adds persistent disk storage. CLI uses the user cache
directory automatically; the API uses an in-memory store.

The store checks incoming copies and does not replace a newer held version
with an older one. Failed refreshes retain a good copy. Refresh is randomized
in the last quarter of validity, at least a day before `nextUpdate`.

`Context::offline()` disables network, but accepts attached collateral, held
responses and configured disk storage. Missing collateral is
`CollateralUnavailable`. `Context::held(responses)` supplies vendor responses
without native disk/network access. WASM always requires attached or
caller-supplied responses; see [WASM](../crates/attestation-wasm/README.md).

`Context::at(unix_seconds)?` fixes evaluation time for reproducible checks.
It is not a substitute for a trusted current clock in a live verifier.

## Freshness and version floors

Each result lists used collateral with `name`, `from`, `version`,
`next_update`, `current`, `stale` and `floor` (optional fields where applicable).
Sources include `attached`, `held`, `memory`, `disk`, `vendor` and `cache`.

A piece beyond `nextUpdate` remains acceptable for the fixed **7-day grace**,
marked stale. Beyond grace, or below its version floor, it produces a result
with `passed() == false`, not a retryable error. Grace does not waive evidence
signature checks, certificate checks or NRAS token expiration.

`Policies::floors` uses `collateral::VersionFloors`. Current defaults, recorded
in source as served on 2026-10-14, are:

| Field | Default |
| --- | ---: |
| `amd_crl_milan` | 12 |
| `amd_crl_genoa` | 11 |
| `amd_crl_turin` | 8 |
| `intel_tcb_info` | 20 |
| `intel_qe_identity` | 20 |

AMD versions are CRL Numbers; Intel versions are tcbEvaluationDataNumber.
Intel PCK and Root CA CRLs have no floor (their CRL Number is 1). Omitted floor
fields retain defaults. Raise floors to reject older signed copies. Library
and WASM allow lowering them; the API refuses that. CLI has no floor or grace
flags. No surface exposes a configurable grace period.

A cache is not an authority on the newest version. A new verifier may receive
an older valid copy bounded only by its floors and validity plus grace.
Persistence and already-observed newer versions help; they do not prove global
freshness. Cache HTTP 200 means bytes were served, not that a policy passed.

## Upstream selection

On Linux, discovery checks for `/dev/tdx_guest`, `/dev/sev-guest` or configfs-TSM.
In such a guest, each context probes `GET /health` on host CID 2, vsock port
8455. Until found, it uses vendors and retries discovery every minute. Once
found, that context stays on the host cache; outage does not trigger direct
vendor fallback. Outside these detected guests, vendors are used. Azure vTPM
guests and dstack containers without these interfaces do not auto-discover.

Native Rust callers can set `Context::with_upstream(url)?`: HTTPS base URL
without query, loopback-only HTTP, or `vsock://CID:PORT` (Linux). Use
`with_upstream_key(Some(key))` for authenticated upstream requests.
`with_vendors()` bypasses host discovery. Explicit upstreams never fall back
to vendors; offline contexts fetch nothing. CLI and API have no explicit
upstream option: they use discovery. `RUST_LOG=info` shows the chosen source.

The cache maps vendor URLs to `GET /{vendor host}/{vendor path}?{query}`.
A cache 404 is retryable `CollateralUnavailable`, not proof the vendor never
published the piece. A direct vendor 404 for a VCEK or TCB Info named by the
evidence is non-retryable. Google's missing endorsement instead gives
`endorsement_match: false`.

See [host/site setup](../crates/attestation-cache/README.md). This cache is
for **verification collateral**, not quote generation. Intel PCCS / `pccsd`
and quote-generation services provision material needed to make a TDX quote;
`attestation-cache` does not replace them or supply a quote-generation endpoint.

## Platform checks and limits

SNP checks the VEK issuing ASK/ASVK against AMD's CRL. TDX checks the PCK chain
against Intel CRLs and evaluates TCB Info and QE Identity. Azure additionally
checks its vTPM evidence; PCR pins count only in the signed SHA-256 selection
of a TPM2_Quote. GCP checks the measured firmware against Google's launch
endorsement; this identifies endorsed firmware, not a Google-hosted machine.
None of these checks alone selects an approved application: pin measurements
and bind the challenge using a policy from the relying party, not the attester.

Dstack verifies its TDX quote and requested measurement pins, but does not
replay its application event log or check Docker image digest policy. Those
remain caller responsibilities; do not treat an unverified event log as claims.

## NVIDIA GPU

GPU evidence is a bundle alongside CPU evidence, not a standalone CPU platform.
Verification needs explicit `Policies::gpu` (`nvidia_gpu` in JSON), a user nonce
of at least 16 bytes, and matching CPU `report_data`. `Policies::all()` and
`with_report_data()` do not enable GPU verification. Set `required` if missing
GPU evidence must fail.

NRAS attestation requests are nonce-bound and go directly to NRAS, never through
`attestation-cache`. Cached NRAS keys alone cannot replace that request. An
attached NRAS answer can be reused only while all its tokens are valid; once
expired it needs a fresh NRAS answer. This is a live external dependency when
no usable answer is attached. The shipped WASM harness does not enable NVIDIA
verification, even though the library's portable feature can compile for WASM.
When an attached NRAS answer is used, the verifier authenticates its signed
claims and nonce, but does not bind that answer to the supplied bundle's
device-evidence bytes.
Nonce binding proves participation under the same challenge, not physical
CPU/GPU co-location: an attester can relay another GPU's evidence. The verifier
checks each NRAS submodule's signed nonce rather than re-deriving NVIDIA's
detached submodule digest. No live GPU end-to-end validation is implied by
these interfaces.
