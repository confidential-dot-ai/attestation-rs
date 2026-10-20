# attestation-wasm

The JS harness verifies the six CPU platforms and dstack using the same
[Policies](../attestation/README.md#policies) as Rust. It does no network or
disk I/O and does not enable NVIDIA GPU verification.

## Build

Install the Rust `wasm32-unknown-unknown` target and
[wasm-pack](https://rustwasm.github.io/wasm-pack/installer/), then:

```sh
cd crates/attestation-wasm
wasm-pack build --target web --release
```

Serve `pkg/attestation_wasm.js` and `pkg/attestation_wasm_bg.wasm` over HTTP,
not `file://`. The module exports two async functions returning JSON strings:

- `collateral_needed(envelope_json)` lists vendor URLs missing from the evidence
  or needing replacement under default policies/floors.
- `evaluate(envelope_json, policies_json, collateral_json)` returns the result
  plus `passed`. The third argument is an array of `{url, body, issuer_chain}`
  encoded as JSON, or `"[]"` when nothing else is needed.

The discovery call uses `Policies::all()` with default floors, not your custom
policy. With raised floors, callers may need to supply newer copies themselves;
a stale/low-floor verdict is not automatically a thrown error.

## Browser integration

This function assumes `init()` has completed, an evidence envelope JSON string,
a relying-party policy object and a configured HTTPS cache URL. It preserves
vendor URLs as collateral identities while fetching through the cache. Do not
ship a private site-wide cache key in a public browser application.

```js
import init, { collateral_needed, evaluate } from './pkg/attestation_wasm.js';
await init();

async function verifyEnvelope(envelope, policies, cacheBase, bearerKey) {
  const urls = JSON.parse(await collateral_needed(envelope));
  const chainHeaders = ['TCB-Info-Issuer-Chain',
    'SGX-Enclave-Identity-Issuer-Chain', 'SGX-PCK-CRL-Issuer-Chain'];
  const collateral = [];
  for (const url of urls) {
    const vendor = new URL(url);
    const target = `${cacheBase.replace(/\/$/, '')}/${vendor.host}${vendor.pathname}${vendor.search}`;
    const response = await fetch(target, {
      headers: bearerKey ? { Authorization: `Bearer ${bearerKey}` } : {},
    });
    if (!response.ok) throw new Error(`collateral HTTP ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const chain = chainHeaders.map(h => response.headers.get(h)).find(Boolean);
    collateral.push({ url, body: btoa(binary),
      issuer_chain: chain ? decodeURIComponent(chain) : undefined });
  }
  const result = JSON.parse(await evaluate(
    envelope, JSON.stringify(policies), JSON.stringify(collateral),
  ));
  if (!result.passed) throw new Error('attestation policy or freshness failed');
  return result;
}
```

Complete acceptable attached collateral can produce an empty URL list. Intel
PCS does not provide browser CORS headers; the
[cache](../attestation-cache/README.md#authentication-and-cors) exposes its issuer
chains and supports bearer-authenticated preflight. Fetch failures in the
wrapper are separate from verifier exceptions. Apply bounded retry and your
own request controls; do not let untrusted evidence authorize arbitrary fetches.

Verifier exceptions have a stable `kind`: `bad_request`,
`platform_not_allowed`, `verification_failed`, or `collateral_unavailable`.
Only the last indicates missing/unavailable collateral. A resolved promise is
not acceptance: mismatches and expired/below-floor collateral are values with
`passed: false`.

## Node example and tests

[example.mjs](example.mjs) generates live SNP evidence through the native CLI,
then checks it in WASM. It requires Linux SNP hardware and vendor access for
missing collateral, and is not a fixture-only quick start:

```sh
cd crates/attestation-wasm
wasm-pack build --target nodejs
node example.mjs
```

`cargo test --locked -p attestation-wasm` runs fixture-based entrypoint tests
natively. It does not exercise browser networking, deployed CORS, or a live
GPU. See [collateral limitations](../../docs/collateral.md).
