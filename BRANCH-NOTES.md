# `feat/wasm-expected-rtmr3` — branch notes

_Temporary. Delete before merge._

Base: `origin/main`. One commit: `af64799`.

**This branch is a dependency of `c8s-verify-js@feat/cds-rollup`.** Merge or push
it first — see "Ordering" below.

---

## The problem

TDX RTMR[3] is where c8s binds the **operator key** at CVM launch:

```
RTMR[3] = SHA384( 0x00*48 ‖ SHA384(operator_pubkey_file_bytes) )
```

Without it, a browser verdict reads *"a genuine instance of the audited image on
real silicon"* — which is true of **anyone's** copy of an open-source,
reproducible image, including an attacker who stood one up and proxied you to it.
MRTD plus RTMR[1]/[2] identify the *build*; RTMR[3] is what identifies **this
deployment**. It also survives reinstalls and image rebuilds, so it can be
published in advance.

The WASM verifier had no way to accept that pin.

---

## What changed

`verify_tdx` gains a fourth parameter:

```rust
pub async fn verify_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,   // NEW
) -> Result<String, JsError>
```

It **fails closed**: the core reports `rtmr3_match`, and when a pin was supplied
the wrapper refuses unless it is explicitly `true` —

```rust
if rtmr3_pinned && result.rtmr3_match != Some(true) { return Err(...) }
```

so "the verifier never ran the comparison" is refused rather than reported as a
satisfied pin. `rtmr3_match` is **omitted entirely** when no comparison was
performed, which is what lets callers distinguish *not checked* from *checked and
false* — `undefined` must never read as "fine".

---

## How this was tested

- Rust tests pass; `wasm-pack` build clean.
- Exercised in the browser against a **live bare-metal Intel TDX cluster** via
  `c8s-verify-js`, both directions: the deployment's real RTMR[3]
  (`a9b91d92…`) verifies; any other value is refused with the WASM error
  surfacing as `rtmr3_denied` client-side.
- Cross-checked against the Go implementation: `c8s verify --operator-key`
  derives the same register value from the operator public key file, and both
  agree on the live quote.

---

## Ordering (important for the handoff)

`c8s-verify-js` consumes this through the `vendor/attestation-rs` **submodule**,
and its built WASM is **gitignored** — a fresh clone builds the verifier from
whatever commit the submodule points at.

So this must land first, then the submodule pointer moves. Out of order, the
built WASM lacks `expected_rtmr3` and every verification fails closed with
*"RTMR[3] was not checked"* — correct behaviour that looks exactly like a bug.

---

## What is missing

- **Only RTMR[3] is exposed.** RTMR[1] (guest kernel) and RTMR[2] (guest rootfs)
  are not pinnable from WASM, so the browser pins firmware (MRTD) and deployment
  (RTMR[3]) but **not the guest image** — while the Go CLI pins all three via
  `--image-manifest`. That asymmetry means the browser demo currently proves less
  about *which OS is running* than the CLI does. Adding `expected_rtmr1` /
  `expected_rtmr2` with matching `rtmr1_match` / `rtmr2_match` report fields
  would reuse this exact plumbing.
- **DCAP collateral** (PCK CRL, TCB status, TD-QE identity) is still skipped in
  WASM (`collateral_verified=false`), so a revoked or TCB-outdated platform
  passes in-browser. The Go path does verify it. Deliberately out of scope here.
