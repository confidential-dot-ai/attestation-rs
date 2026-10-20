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

`attestation-wasm` compiles the verifier to WebAssembly so evidence
can be verified entirely client-side. To produce a blob usable in a browser, build
with the `web` target (this requires [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/)):

```bash
cd crates/attestation-wasm
wasm-pack build --target web --release
```

This writes an ES module and the `.wasm` binary to `pkg/`:

- `pkg/attestation_wasm.js` — JS bindings and the `init` loader
- `pkg/attestation_wasm_bg.wasm` — the WASM blob

Serve `pkg/` over HTTP (browsers won't load WASM from `file://`). WASM does
no network or disk I/O, so the caller fetches the vendor URLs the evidence
needs and hands the responses over; each is verified against the vendor roots
compiled into the verifier, exactly as on native:

```html
<script type="module">
  import init, { collateral_needed, evaluate } from './pkg/attestation_wasm.js';

  await init(); // fetches and instantiates the .wasm blob

  // envelope: { platform, evidence } JSON string
  const needed = JSON.parse(await collateral_needed(envelope)); // vendor URLs
  const chainHeaders = ['TCB-Info-Issuer-Chain', 'SGX-Enclave-Identity-Issuer-Chain',
    'SGX-PCK-CRL-Issuer-Chain'];
  const collateral = [];
  for (const url of needed) {
    const resp = await fetch(url); // AMD KDS, Intel PCS (via a proxy: no CORS)
    const header = chainHeaders.map((h) => resp.headers.get(h)).find(Boolean);
    collateral.push({
      url,
      body: btoa(String.fromCharCode(...new Uint8Array(await resp.arrayBuffer()))),
      issuer_chain: header ? decodeURIComponent(header) : undefined,
    });
  }
  const result = JSON.parse(await evaluate(
    envelope, ['snp', 'tdx'], new TextEncoder().encode('my-nonce'),
    undefined, undefined, undefined, JSON.stringify(collateral),
  ));
  if (!result.passed) throw new Error('attestation did not pass');
</script>
```

`evaluate(envelope, platforms, report_data, init_data, rtmr3, min_tcb,
collateral)` throws only when the evidence cannot be evaluated (malformed, not
genuine, platform not accepted, needed collateral missing or not the
vendor's); mismatches, policy flags and expired collateral are fields, so the
caller must read `passed`.

For a Node.js end-to-end example (generate live evidence, fetch its collateral,
verify in WASM), build with `--target nodejs` and run
`crates/attestation-wasm/example.mjs`.

## Verifying evidence

Callers say which platforms they accept and what each must satisfy, with one
params type per platform:

```rust
use attestation::{Policies, TdxParams};

let policies = Policies {
    tdx: Some(TdxParams {
        report_data: Some(nonce.to_vec()),
        mrtd: Some(vec![mrtd_a, mrtd_b]),        // any of; [u8; 48] each
        rtmr: [None, Some(vec![rtmr1]), None, None],
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

`mrtd`, each `rtmr` and `launch_digest` take a set of allowed values, because
firmware the cloud provider owns varies (the Azure paravisor build, the GCP
firmware per memory size or machine type). The measurement must equal one of
them; an empty set is invalid params (`Err`).

## Collateral

Collateral is what a verifier needs besides the evidence: AMD VCEKs and CRLs,
Intel TCB Info, QE Identity and CRLs, Google's launch endorsements, NVIDIA's
NRAS keys. The library fetches each piece from its vendor, verifies its
signature against the roots compiled into the crate and that it is the piece
the evidence names, and keeps it by its vendor URL: one store is shared by
every `attestation::verify` call in the process. A piece is replaced only by a
valid copy that is not older, refetched when it nears its nextUpdate, and kept
when a refetch fails. The CLI also saves collateral in the user cache directory
and reuses it in later runs; `--offline` uses only that.

Evidence carries its own collateral. `Verifier::attach_collateral(evidence,
report_data)` gathers, through the store, what a verifier of the evidence
needs and adds it to the envelope as `collateral: [{url, body (base64),
issuer_chain}]`: vendor bytes, never roots, each issuer chain once (a piece
without one takes the chain of the piece before it), and for NVIDIA the NRAS
answer and only the NRAS key that signed it. The CLI's `attest` and the API's
`/attest` attach it. The vendor client retries short outages once; attach
keeps what it could get, without an incomplete NRAS key set. An attached NRAS
answer is used until any of its tokens expires, then the attester must ask NRAS again. A verifier uses the
newest of the attached collateral and its own copies, and checks it like a
fetched copy (one attached piece that does not verify makes the evidence not
genuine), so a verifier with only the
compiled-in roots (a browser, a server without egress) can judge the evidence.
Fetching what the evidence lacks is a fallback: on in the CLI and servers,
off with `Context::offline()` (`--offline`); in the browser the JS wrapper
fetches what `collateral_needed` lists.

Where evidence is made, collateral comes from an `attestation-cache` rather
than the vendors (see `crates/attestation-cache`). Inside a confidential VM
(a `/dev/tdx_guest`, `/dev/sev-guest` or configfs-tsm guest) the library finds
the host's cache by itself: a `Context` asks `GET /health` at vsock port 8455
of the host (CID 2); once that answers, every fetch of that `Context` goes
there and the vendors are never asked directly; while nothing answers, the
vendors are used and the host is tried again every minute. Each `Context`
looks on its own. Outside a confidential VM, and in Azure vTPM guests and
dstack containers (which show none of those devices), the vendors are used.
`Context::with_upstream` sets a cache
explicitly (`https://` base URL without query, `http://` on loopback only, or
`vsock://CID:PORT`). The choice is logged at info level (the CLI logs per
`RUST_LOG`), and a `CollateralUnavailable` detail names the upstream asked.
Answers from a cache are verified like the vendors' and
reported `from: cache`; a cache's "not found" is `CollateralUnavailable`, as
only the vendor itself can say a piece is not published. A cache can still
hand a fresh process an older copy that is valid: that copy is bounded by the
version floors and its own nextUpdate (plus the grace), and is never taken
over a newer copy the process already has. Each
piece is refreshed at a random time in the last quarter of its validity, and
at least a day before its nextUpdate. NRAS attestation requests (GPU) go to
NRAS directly.

- No copy anywhere is `CollateralUnavailable { collateral, retry_after,
  detail }`, the only retryable error: it names the piece, the vendor's
  Retry-After when it sent one, and why in `detail`.
- A piece that is not the vendor's (bad signature, wrong piece) is
  refused like evidence that is not genuine, and so is a VCEK or TCB Info the
  vendor does not publish (404) for the chip or platform the evidence names.
- The result lists every piece used (`collateral`: `name`, `from`,
  `version`, `next_update`, `current`, `stale`, `floor`). A piece past its
  nextUpdate passes for 7 days marked `stale` (AMD publishes its
  fixed-calendar CRL late at times); after that `passed()` is false.
- Version floors (`Policies::floors`: AMD CRL Number per generation, Intel
  tcbEvaluationDataNumber of TCB Info and QE Identity) default to the versions
  served when the release was made; callers may raise them. A piece below its
  floor is a value, not an error: `passed()` is false. This stops an older,
  validly signed copy from being replayed. Intel's PCK and Root CA CRLs always
  carry CRL Number 1, so they have no floor.

SEV-SNP (`snp`, `gcp-snp`, `az-snp`) checks the VEK's issuing ASK/ASVK against
the AMD CRL (`crl_ok`). TDX platforms check the PCK chain against Intel's CRLs
(`crl_ok`) and grade the TCB with TCB Info and the QE Identity (`tcb_status`).
GCP platforms check the firmware against Google's launch endorsement for the
measurement (`endorsement_match`: false when Google publishes none, or it does
not list the MRTD or measurement, or for SNP the guest policy is wider than the
endorsed one). It shows the firmware is a Google OVMF build, not that the host
is GCP.

The CLI exposes matching flags (`--expected-mrtd`, `--expected-rtmrN` and
`--expected-launch-digest` are repeatable: any of the given values):

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
verifies without network access, with the collateral saved by earlier runs.

| Exit code | Meaning |
|---|---|
| 0 | Passed: genuine, and every rule in the flags held |
| 1 | Did not pass, or the evidence is not genuine |
| 2 | Usage error or invalid params |
| 3 | Collateral unavailable (AMD KDS, Intel PCS, NRAS); retrying may help |

On Azure CVMs (`az-snp`, `az-tdx`) the guest boot chain is measured into vTPM
PCRs. `AzTdxParams::pcrs` / `AzSnpParams::pcrs` pin SHA-256 PCR values by
index; `pcrs_match` is `false` if any pin does not match. A PCR counts only if
its index is in the TPM quote's signed PCR selection, because the quote signs
only a digest over the selected PCRs, and only a `TPM2_Quote` over one
SHA-256 selection is compared. An index above 23, or the same index pinned
twice, is invalid params. The CLI flag is `--expected-pcr INDEX=HEX`
(repeatable); on its own it accepts the Azure platforms:

```bash
attestation-cli verify \
  --evidence evidence.json \
  --expected-pcr 4=$PCR4 \
  --expected-pcr 9=$PCR9 \
  --expected-pcr 11=$PCR11
```

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
