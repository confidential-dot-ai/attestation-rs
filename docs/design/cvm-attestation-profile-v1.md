# CVM attestation profile v1

Status: draft for review. Owner: attestation DRI. Companion documents: "Standardizing Attestation" and "SEV-SNP Measurement Registers" (Notion, Confidential AI / Docs). This document is the library-side design those two ask for, and it changes both of them; section 11 lists exactly what.

The [design rationale and field provenance](cvm-attestation-rationale.md) explain why these abstractions were chosen, what comes from external specifications, what this project defines, and the known conformance questions. Standards references below are design inputs, not certification that the current branch or downstream clients fully conform.

Every hash input in this document is byte-exact and every formula has a test vector in Appendix B. Reproducing those vectors establishes agreement on those formulas; complete profile conformance also requires the parsing, validation, policy, trust-boundary and encoding rules, plus negative tests.

## 1. Summary

We propose a common CVM attestation contract using existing message vocabularies and project-specific measurement, binding and policy rules. The proposed SNP register bank is protected by measured kernel software and bound into hardware-signed reports; it is not a hardware register implementation. Novelty is not established by this document.

- Evidence is an EAT claims set (RFC 9711) under the profile `tag:confidential.ai,2026:cvm#1`, carried unprotected (RFC 9781 UJCS/UCCS) because every trusted byte inside it is signed by hardware or derived from a hardware signature by the verifier. One submodule per attester: the CPU TEE, an optional vTPM, and one per NVIDIA device. Arm CCA tokens nest as they are.
- Runtime measurements are a register array with an explicit algorithm, index, source and `backing` label per register, plus a TCG Canonical Event Log (CEL, v1.1) that replays to them. TDX RTMRs, Azure vTPM PCRs, Arm CCA REMs and the new SNP registers all populate the same array.
- Freshness is one nonce bound per platform in a declared mode. On SNP with the register driver, `report_data` becomes the `ats-mr-v1` commitment and the nonce lives in the committed caller data.
- Attestation results are EAR (draft-ietf-rats-ear-04) with our normalized claims in `ear_attester_claims`, collateral outcomes in `ear_verifier_claims`, and the trustworthiness vector filled per AR4SI-10. c8s already mints EAR; it moves from profile 03 to 04 and drops its private claims for the profiled ones.
- The Rust library publishes types, JSON Schemas and vectors for the contract, and the conformance corpus of section 14 is the contract's executable form: an implementation conforms when it reproduces every case's decision. Schema agreement alone does not prevent semantic drift; the corpus is what does.

## 2. Scope and roles

Terminology follows RFC 9334. In our systems the roles are:

| Role | Who |
| --- | --- |
| Attester | `attestation-cli attest`, `attestation-api POST /attest`, inside the CVM; NVIDIA GPUs via the SDK; the Azure paravisor's vTPM; Arm RMM for realms |
| Verifier | `attestation` (native, WASM), `attestation-api POST /verify`, `attestation-go` |
| Relying party | c8s CDS and RA-TLS, confidential agents, browsers through c8s-verify-js |
| Endorser | AMD KDS, Intel PCS, NVIDIA NRAS, Arm CCA platform vendors |
| Reference value provider | confos manifests (launch digests, expected register values) |

Platforms in scope: SEV-SNP bare metal and GCP, SEV-SNP with the confos register driver, Azure SEV-SNP and TDX (vTPM and HCL), TDX bare metal and GCP, dstack TDX, Arm CCA (Vera Rubin), NVIDIA Hopper and Blackwell GPUs and NVSwitch through NRAS.

Goals, restated from the standard-format document with one correction each:

- L0, what launched: the hardware launch measurement (SNP MEASUREMENT, TDX MRTD, CCA RIM). On Azure this is the paravisor plus firmware digest and it is pinnable; c8s pins it today.
- L1, what ran after launch: the register array and its log. The guarantee is what measured producers recorded; section 10 states the limit.
- L2, freshness: one nonce, one declared binding mode per submodule.
- TCB: actual versions per vendor plus vendor status where a service exists; the floor is policy and stays out of the evidence format.
- Host binding: host-set fields are carried as labels; they become guarantees only where measured guest code is known to enforce something about them (Kata initdata is the example).
- Policy bits: normalized, with debug rejected by default.

## 3. Standards used

| Standard | What we take from it |
| --- | --- |
| RFC 9334 (RATS architecture) | roles and message names above |
| RFC 9711 (EAT) | claims set shape, `eat_profile`, `eat_nonce`, `submods`, `dbgstat`, `bootseed`, `measres`, nested tokens; the profile checklist in section 6.3 |
| RFC 9781 (UCCS) | unprotected claims set, CBOR tag 601, JSON form UJCS, nesting rules in Appendix C |
| RFC 9782 (EAT media types) | `application/eat-ucs+json` and `application/eat-ucs+cbor` with the `eat_profile` parameter, which is how the envelope is labeled on the wire |
| RFC 9999 (CMW) | typed evidence records `[type, value, indicator]`, collections, indicator bits (0 reference values, 1 endorsements, 2 evidence, 3 results, 4 policy), and the `id-pe-cmw` X.509 extension (1.3.6.1.5.5.7.1.35) for certificate-carried evidence |
| RFC 8392 section 9.1 (CWT) | claim key ranges; our CBOR keys are in the private-use range (Appendix A) |
| RFC 8949 section 4.2.1 | deterministic CBOR encoding |
| RFC 4648 section 5 | base64url for byte strings in JSON |
| draft-ietf-rats-ear-04 | results: `ear_verifier_id`, `submods`, `ear_status`, `ear_trustworthiness_vector`, `ear_attester_claims`, `ear_verifier_claims`, `ear_raw_evidence` |
| draft-ietf-rats-ar4si-10 | trustworthiness tiers and per-category values |
| draft-kykdxy-rats-tdx-cgpu-ear-profile-02 | the Microsoft, Intel and NVIDIA EAR profile for TDX with confidential GPUs; this profile composes with it (section 5.3) |
| draft-sun-rats-composite-eat-00 | detached-digest binding of multiple attesters under one nonce; adopted for v2 (section 12) |
| draft-ffm-rats-cca-token-04 | the CCA token as a CMW collection under tag 907, keys 0xACCA and 0xACD1, profiles `tag:arm.com,2026:cca_platform#2.0.0` and `tag:arm.com,2026:realm#2.0.0` |
| TCG Canonical Event Log Format v1.1 r11 | record layout (`recnum` per index, register index, `digests`, `content_type` and `content`), the CBOR and JSON encodings of the section 5.2 CDDL, the `$TPMS_CEL_EVENT-extension` socket, replay |
| TCG PC Client Platform Firmware Profile v1.06 r52 | the TCG2 log (the Spec ID header and `TCG_PCR_EVENT2`), event types (Table 27), the `StartupLocality` event, tagged events |
| TCG PC Client Platform TPM Profile v1.05 r14, TPM 2.0 Library Part 1 r1.83 | PCR starting values (PTP Table 7; Part 1 section 34.3 for PCR 0 and the startup locality) |
| TCG TPM 2.0 Library Part 2 | hash algorithm identifiers used in CEL digests and in `alg` fields |
| Arm CCA token (RMM specification; profiles `tag:arm.com,2023:cca_platform#1.0.0`, `tag:arm.com,2023:realm#1.0.0` as shipping firmware emits, and the 2026 2.x profiles of the draft above) | nested as a token submodule, verified by the CCA rules |
| Intel PCK Certificate and CRL Specification | SGX extension OIDs under 1.2.840.113741.1.13.1 (PPID .1, TCB .2, PCE-ID .3, FMSPC .4, SGX type .5, platform instance id .6) |
| AMD SEV-SNP ABI, Intel TDX DCAP, NVIDIA NRAS EAT | the hardware reports and vendor tokens the envelope carries |

## 4. Evidence profile

Profile identifier: `tag:confidential.ai,2026:cvm#1`, carried in `eat_profile` (claim key 265).

### 4.1 RFC 9711 section 6.3 checklist

| Item | Decision |
| --- | --- |
| 6.3.1 JSON, CBOR or both | JSON is the primary wire encoding (this is what every consumer speaks today); rules in section 4.10. CBOR is defined by the same claims with the keys in Appendix A and is used where a token is natively CBOR (Arm CCA) and for the event log. |
| 6.3.2 map and array encoding | definite lengths only |
| 6.3.3 string encoding | definite lengths only |
| 6.3.4 preferred serialization | deterministic encoding, RFC 8949 section 4.2.1, for every CBOR object we produce |
| 6.3.5 tags | UCCS tag 601 when a CBOR evidence set is written; no tag inside JSON. On the wire the envelope is `application/eat-ucs+json; eat_profile="tag:confidential.ai,2026:cvm#1"` (RFC 9782), or `eat-ucs+cbor` |
| 6.3.6 protection | none at the envelope (UJCS/UCCS). Trust comes from the hardware signatures inside; section 4.2 lists which fields are trusted and which are hints. |
| 6.3.7 algorithms | inherited from each hardware report; the profile adds SHA-384 for registers, the anchor and the commitment, SHA-256 for the vTPM AK binding and the GPU nonce derivation |
| 6.3.8 detached bundles | not used in v1 |
| 6.3.9 key identification | per submodule: VCEK or VLEK for SNP, PCK chain for TDX, HCL AK for the vTPM, CCA platform attestation key, NRAS JWKS `kid` |
| 6.3.10 endorsement identification | inline `cvm_endorsements` (section 4.6) or fetched by the verifier; either way anchored to embedded roots, except CCA (section 6) |
| 6.3.11 freshness | one `eat_nonce` at the top, bound per submodule in a declared mode (section 4.5) |
| 6.3.12 claims requirements | tables in sections 4.3 and 4.4 |

### 4.2 Trust boundary inside the envelope

The envelope is unprotected, so the verifier classifies every field as one of:

- signed: bytes covered by a hardware or vendor signature (the SNP report, the TD quote, the HCL report's TEE report, CCA tokens, NRAS tokens, the TPM quote);
- bound: fields the verifier checks against signed bytes before use (registers against the report or the commitment, the log against the registers, the nonce against its binding, endorsements against embedded roots);
- hint: everything else, used only to select a parser and never to make a decision.

`cvm_platform.hosting` is a hint. The vendor and TEE type are re-derived from the signed report. A hint that contradicts the signed data is an error, never a fallback.

### 4.3 Top-level claims

| Claim | Key | Req | Meaning |
| --- | --- | --- | --- |
| `eat_profile` | 265 | must | `tag:confidential.ai,2026:cvm#1` |
| `eat_nonce` | 10 | must | the relying party's challenge, 16 to 64 bytes |
| `submods` | 266 | must | map of attester submodules (section 4.4) |
| `cvm_version` | Appendix A | must | integer, 1 |

Submodule names are chosen by the attester within these reserved forms: `cpu` (exactly one, required), `vtpm` (at most one), `gpu/<ueid>` and `nvswitch/<ueid>` (one per device, `<ueid>` the device UUID string as the SDK reports it). Other names are rejected.

### 4.4 Submodule claims

`cpu` submodule (a claims set):

| Claim | Req | Class | Meaning |
| --- | --- | --- | --- |
| `cvm_platform` | must | hint | `{vendor, tee, generation?, hosting}`; vendor in `amd`, `intel`, `arm`; tee in `sev-snp`, `tdx`, `cca`; hosting in `bare`, `azure`, `gcp`, `dstack` |
| `cvm_report` | must | signed | a CMW record (RFC 9999) `[type, value, 4]`: `type` is the media type of the raw report, `value` the raw bytes, and the indicator is required and exactly 4 (bit 2, evidence). Types: `application/vnd.confidential-ai.sev-snp-report`, `application/vnd.confidential-ai.tdx-quote`; `application/vnd.veraison.tsm-report+json` is accepted on ingest. On Azure this is the SNP report the HCL report wraps, or the TD quote; the HCL report itself rides in the `vtpm` submodule |
| `cvm_binding` | must | bound | freshness pattern, binding mode (section 4.5) and their parameters |
| `cvm_endorsements` | may | bound | inline collateral as a CMW collection, indicator bit 1 (section 4.6) |
| `cvm_registers` | may | bound | runtime register array (section 4.7) |
| `cvm_log` | may | bound | event log (section 4.8) |
| `cvm_chain` | must when binding is `commitment` | bound | `{chain_len}` (section 4.9) |
| `bootseed` (EAT, key 268) | must when binding is `commitment` | bound | 32 random bytes chosen at boot; the first record extended into slot 3 (section 4.9) |
| `dbgstat` (EAT, key 263) | may | hint | RFC 9711 section 4.2.9: a text value in JSON (`enabled`, `disabled`, `disabled-since-boot`, `disabled-permanently`, `disabled-fully-and-permanently`), the integer 0 to 4 in CBOR. The verifier derives the real value from the report and refuses a hint that disagrees with it on whether debug is enabled |
| `cvm_provenance` | may | reserved | hosting-provider evidence (a PPID against a provider's host registry, a TPM attestation key bound into the report, a CoRIM-carried proof of environment). No semantics in v1; a v1 verifier ignores it; key reserved in Appendix A |

For Arm CCA the `cpu` submodule is instead a nested token (RFC 9711 section 4.2.18.3): the CCA token bytes exactly as the RMM emits them. Per draft-ffm-rats-cca-token-04 that token is a CMW collection under CBOR tag 907 with the platform token at key 0xACCA (44234) and the realm token at key 0xACD1 (44241), each a COSE_Sign1 CWT; shipping firmware still emits the earlier EAT-collection form under tag 399 with the 2023 1.0.0 profiles. Neither tag is in the IANA CBOR tag registry yet; the verifier accepts exactly those two by allowlist, and both profile generations. In delegated mode the platform challenge is the hash of the realm attestation key, in direct mode the hash of the realm claims; the realm challenge is our nonce. No `cvm_report` wrapper is needed because the token is already an EAT.

`vtpm` submodule:

| Claim | Req | Class | Meaning |
| --- | --- | --- | --- |
| `cvm_tpm_quote` | must | signed | `{message, signature, pcrs, bank}`; TPMS_ATTEST bytes, its signature, the 24 PCR values of the quoted bank, `bank` a TPM algorithm name (section 4.7) |
| `cvm_tpm_ak` | must | bound | `{method, data}`, how the AK is bound to the CPU report. Method `hcl-report`: `data` is the Azure HCL report; its `var_data` carries the AK public key, its report type names the same TEE as `cvm_platform`, and the verifier requires `report_data[0..32] == SHA-256(var_data)` on the CPU report |
| `cvm_registers` | must | bound | the PCRs projected as registers, source `vtpm-pcr`, backing `privileged-service` |
| `cvm_log` | may | bound | TPM2 event log or CEL |

`gpu/<ueid>` and `nvswitch/<ueid>` submodules: the existing NVIDIA device evidence (`arch`, `evidence_b64`, `cert_chain_b64`) plus `cvm_binding` with mode `nras-nonce`. The verifier sends it to NRAS API v4 (`/v4/attest/gpu`, `/v4/attest/switch`) with claims version 3.0, the request body NVIDIA's own SDK sends, and reads the detached EAT it answers with: an overall token and one token per device, all ES384 under the pinned NVIDIA anchor, each carrying the endpoint's origin as `iss`. The overall token's `submods` holds `["DIGEST", ["SHA-256", hex]]` over each device token's compact form, which the verifier checks, together with the device count, before it reads a device token; each device token's `eat_nonce` then binds it to the session.

### 4.5 Freshness and binding modes

Two freshness patterns exist, and `cvm_binding.pattern` names the one in use:

- `challenge`: the relying party chose `eat_nonce` for this exchange. This is the default and the only pattern for `POST /verify`, KMS release and any exchange with a live peer.
- `certificate`: the evidence is bound to an X.509 certificate that lives for the CVM's lifetime (RA-TLS). The attester chose `eat_nonce` at certificate creation and the certificate is bound through `cvm_binding.key` of kind `x509-tbs-sha256` (section 4.5.1). The relying party bounds the certificate's age itself; the profile records `not_before` and `not_after` in `cvm_freshness`.

`eat_nonce` is mandatory in both patterns and at least 16 bytes. A binding with no nonce, and a relying party that accepts one, were audit findings against shipping products this year.

`cvm_binding.mode` declares where the nonce is bound. The verifier computes the expected value and compares in constant time over the full field; a mismatch is an error.

Definitions used below. `||` is byte concatenation with no separators or length prefixes unless one is written explicitly. Quoted strings are ASCII bytes with no terminator. `pad64(x)` is `x` followed by zero bytes to a length of 64; `x` must be at most 64 bytes. `u8(n)` is one byte, `u16be(n)` two bytes big-endian, `u64le(n)` eight bytes little-endian.

| Mode | Platforms | Expected value |
| --- | --- | --- |
| `report-data` | SNP without the register driver, TDX, dstack | `report_data == pad64(anchor)` |
| `commitment` | SNP with the register driver | `report_data == header16 \|\| C` with `caller_data = pad64(anchor)`; `header16` and `C` in section 4.9 |
| `vtpm-extradata` | Azure SNP, Azure TDX, future SVSM vTPM | TPM quote `extraData == anchor`, and the CPU report binds the AK. `extraData` is a TPM2B_DATA, which holds at most `sizeof(TPMT_HA)` bytes: 50 on Azure's vTPM (SHA-384 as its largest digest), so an unkeyed nonce bound this way is 16 to 50 bytes, and a keyed anchor (48 bytes) always fits |
| `cca-challenge` | Arm CCA | realm token `cca-realm-challenge == pad64(anchor)` |
| `nras-nonce` | NVIDIA devices | SPDM nonce `== SHA-256(nonce \|\| "NVIDIA-GPU-EAT-v1")` for GPUs, `SHA-256(nonce \|\| "NVIDIA-SWITCH-EAT-v1")` for NVSwitch |

`anchor` is the relying party's binding input, derived by the verifier:

```
no key:   anchor = nonce
with key: anchor = SHA-384("ats-anchor-v1" || u8(len(nonce)) || nonce
                           || u8(len(kind)) || kind || u16be(len(value)) || value)
```

`cvm_binding.key` is `{kind, value}`. `kind` is one of:

| kind | value |
| --- | --- |
| `spki-sha256` | the 32-byte SHA-256 of the DER SubjectPublicKeyInfo of the key being bound (challenge pattern, key handoff) |
| `x509-tbs-sha256` | the 32-byte SHA-256 of the DER TBSCertificate of the certificate being bound, which covers its public key, validity window, subject and subject alternative names (certificate pattern) |
| `raw` | an opaque value the relying party chose, at most 65535 bytes |
| `tls-exporter` | reserved for v2: the 32-byte RFC 9266 exporter value of the session (label `EXPORTER-Channel-Binding`, empty context), which gives per-session freshness under the certificate pattern without a relying-party nonce. A v1 verifier rejects it as an unknown kind |

This one derivation replaces the per-platform padding rules c8s carries today and the per-product formulas in the field. Vectors in Appendix B.

#### 4.5.1 Certificate carriage

When evidence rides in a certificate, it is carried in the `id-pe-cmw` extension (RFC 9999 section 4.4, OID 1.3.6.1.5.5.7.1.35) as a CMW record whose type is `application/eat-ucs+json; eat_profile="tag:confidential.ai,2026:cvm#1"` and whose value is this envelope. The verifier recomputes `SHA-256(TBSCertificate)` from the presented certificate and requires it to equal `cvm_binding.key.value`. On ingest the verifier also accepts the private arc used by dstack and Flashbots attested-tls (`1.3.6.1.4.1.62397.1.1` quote, `.1.2` event log, `.1.8` versioned attestation) so those peers verify; it never emits it.

### 4.6 Endorsements

`cvm_endorsements` carries the same collateral set the verifier would otherwise fetch, so verification can be offline and so a KDS or PCS outage does not stop a verifier that already holds fresh collateral. It is a CMW collection (RFC 9999 section 3.3): each entry is a record `[type, value, indicator]` with the indicator exactly 2 (bit 1, endorsements), or exactly 1 (bit 0, reference values) when a deployment ships them inline; nested collections are not accepted in it, its labels are exactly the ones below, and its `__cmwc_t` is `tag:confidential.ai,2026:cvm-endorsements#1`. Entries and their types:

| Entry | Type and content |
| --- | --- |
| `snp.vek` | `application/pkix-cert`, VCEK or VLEK DER |
| `snp.crl` | `application/pkix-crl`, AMD CRL for the generation |
| `tdx.tcb_info` | `application/vnd.confidential-ai.pcs-signed+json`, the JSON object `{body, issuer_chain}` with `body` the exact PCS response bytes and `issuer_chain` the PEM issuer chain from the response header, both as byte strings, so Intel's signature over the body verifies on the bytes Intel produced |
| `tdx.qe_identity` | same type, `{body, issuer_chain}` |
| `tdx.pck_crl`, `tdx.root_crl` | `application/pkix-crl` |
| `nras.jwks` | `application/jwk-set+json` |

Inline endorsements are inputs, never authority: the verifier anchors every certificate to the embedded AMD, Intel or NVIDIA roots and checks every validity window and `nextUpdate` before use. The verifier's own cache (the collateral unification in the sweep) uses the same struct, so inline, cached and fetched collateral are one type with three transports.

### 4.7 Registers

`cvm_registers` is an array, required whenever `cvm_log` is present so a verifier without log support can still pin values; each entry:

| Field | Meaning |
| --- | --- |
| `index` | integer slot, 0 to 65535 |
| `alg` | TPM 2.0 algorithm name: `sha256` (TPM_ALG_SHA256, 0x000B), `sha384` (0x000C) or `sha512` (0x000D); the same names CEL uses in `digests`. Pinned per source: `sha384` for `tdx-rtmr` and `snp-vmr`, the quoted bank for `vtpm-pcr`, `sha256` or `sha512` (the realm hash algorithm) for `cca-rem` |
| `value` | the register value, exactly the digest length of `alg` |
| `source` | `tdx-rtmr`, `snp-vmr`, `vtpm-pcr`, `cca-rem` |
| `backing` | `hardware`, `privileged-service`, `kernel-service`, `virtualized`. In evidence this is a hint constrained by source: `hardware` for `tdx-rtmr` and `cca-rem` (the value is in the signed report), `privileged-service` for `vtpm-pcr`, and never `hardware` for `snp-vmr`; the verifier reports the backing the pinned image establishes (section 10) and never a higher one than the evidence claims |

The verifier never trusts `value` from the envelope. For `tdx-rtmr` and `cca-rem` the authoritative values are in the signed report and the envelope values must equal them. For `vtpm-pcr` the quoted PCR digest must reproduce from them. For `snp-vmr` the commitment must reproduce from them (section 4.9), so `snp-vmr` registers appear only with the `commitment` binding and an envelope that carries them in any other mode is rejected. When a log is present it must replay to them.

Index space: for `tdx-rtmr` the index is the RTMR ordinal 0 to 3, for `cca-rem` the REM ordinal 0 to 3, for `vtpm-pcr` the PCR number, for `snp-vmr` the slot number. The launch measurement (MRTD, RIM, SNP MEASUREMENT) is never a register; it is `cvm_launch_measurement`. Two conventions in the field are offset by one and must be converted on ingest: the UEFI `CC_EVENT` `MrIndex` (0 is MRTD, 1 to 4 are RTMR 0 to 3, so CCEL records subtract one) and the Flashbots and BuilderNet measurement files (index 0 MRTD, 1 to 4 RTMR 0 to 3). CoCo's attestation agent folds TPM PCR 17 into RTMR 3, which the log replay reproduces without renumbering. CEL's `pcr` field carries our index.

Slot semantics are fixed across platforms so policy is portable: slots 0 to 3 carry the TDX RTMR meaning from the TDX virtual firmware design and the TCG firmware profile (0 firmware configuration, the PCR 1 and 7 analog; 1 what the firmware loads, boot loader and partition table, PCR 2 to 5; 2 kernel, command line, initrd and OS-loaded components, PCR 8 to 15; 3 runtime), slots 4 to 15 are workload slots where the platform has them, each allocated at first use by a claim record (section 4.9). `vtpm-pcr` entries keep their PCR index and are distinguished by `source`. The verifier reports the backing of every register it verified, and policy sets a minimum backing so a downgrade from `hardware` to `kernel-service` can never pass silently.

### 4.8 Event log

`cvm_log` is `{format, data}` with `format` in:

| Format | Notes |
| --- | --- |
| `tcg-cel-cbor` | the target. CEL v1.1 records in deterministic CBOR, each the section 5.2 CDDL map `{0: recnum, 1: pcr, 3: digests, 9: content_type, 10: content}`; `data` is the CDDL's `tcg-canonical-event-log`, one array of records. `recnum` counts each index's records from 0 (CEL section 4.2.2) and `pcr` carries our register index. |
| `tcg-cel-json` | the same records in CEL-JSON, for human inspection only: a JSON array of `{recnum, pcr, digests: [{hashAlg, digest}], content_type, content}` with byte strings in hex |
| `tdx-ccel` | the ACPI CCEL as the guest exposes it (TCG2 binary), accepted during transition. MrIndex 1 to 4 become RTMR 0 to 3. The Confidential Containers attestation agent (guest-components v0.15.0 and later) appends its entries to the CCEL it reports: `EV_EVENT_TAG` records whose tagged event has ID 0x4141454C around the text `domain operation content`, with the hash of the whole tagged event as digest and MrIndex 4 (RTMR 3) by default |
| `tpm2-event-log` | TCG2 binary log from a vTPM, accepted during transition; replayed in the quoted bank (this release requires SHA-256) into every PCR it extends, each from its PC Client starting value (PCR 17 to 22 all ones, the others zero, PCR 0 at the locality of a `StartupLocality` event), skipping `EV_NO_ACTION`, and each extended PCR must reproduce the quoted value |
| `dstack-json` | dstack's event log as its guest agent returns it, an array of `{imr, event_type, digest, event, event_payload, version?, preimage?}` with `imr` the RTMR ordinal. Boot events keep their TCG digest. Runtime events (event type 0x08000001) are recomputed under their declared `version`, absent meaning 1: version 1 is `SHA-384(event_type_le32 \|\| ":" \|\| event \|\| ":" \|\| event_payload)`, and a name containing `:` is refused so the hash input splits back into one name; version 2 is `SHA-384(JCS({"name", "payload": hex, "type"}))` and must carry that JCS text as `preimage`. Replay is `R = SHA-384(R \|\| digest)` from zero |
| `aael` | the attestation agent's log where the platform has no CCEL: its fixed 73-byte header, then the same records as above. The `tcg-cel` crate parses it; this release's appraisal refuses it |

Every format becomes CEL records before replay (the `tcg-cel` crate, section 13): a TCG2 event is a `pcclient_std` record with all its digests, the Spec ID header included as an unmeasured record, and a dstack runtime event is a `pcclient_std` record whose `event_data` is its digest's hash input, so it verifies on its own. A record's event type and tagged-event ID lie outside its digest, so a relabeled attestation-agent entry or dstack runtime event still replays; a verifier therefore lists a register's entries or runtime events only when every measured record in that register is one whose digest reproduces.

A c8s runtime event is one CEL record: `recnum` its number within its slot, `pcr` the slot index, `digests` a single entry (`hashAlg` 12, TPM_ALG_SHA384, and `digest` d), `content_type` `cvm` (value 200, 0xC8), and `content` the map `{0: seq (uint), 1: event (bstr)}`. `seq` is the record's place among the log's `cvm` records, from 0. `event` is the deterministic CBOR encoding of the map `{0: domain (tstr), 1: operation (tstr), 2: content_digest (bstr), 3: content (bstr, optional)}`, with `domain` and `operation` each at most 255 bytes of UTF-8. `d = SHA-384("ats-mr-v1/record" || u64le(seq) || u16le(pcr) || event)`, and `d` is the value that was extended. Replay requires `seq` to count the log's `cvm` records without a gap, recomputes `d` from `seq`, the register index and the stored event bytes, requires it to equal the recorded digest, and extends it; the verifier never re-encodes content. The verifier replays every register the log covers and marks each register `replayed: true` or `false` in the result; policy decides which slots must replay (today: RTMR 0 to 2 must, RTMR 3 reports, and counts as replayed when the log accounts for every extend into it). A `tcg-cel-*` or `dstack-json` log on a TDX submodule replays from zero into the RTMRs it extends, each of which must reproduce the signed value; on an SNP submodule in `commitment` mode the log is required, `chain_len` must equal its record count, and section 4.9 governs the replay from genesis. Policy may name a `replay_until_event` (dstack's `system-ready` is the model), in which case the verified register value is the replay up to and including that record and later records are reported, not enforced; this release does not implement it yet.

For SNP `commitment` logs, every record must use `cvm` content; other CEL content is rejected because its digest would not authenticate the sequence. The driver assigns `seq` from its global extension counter and `recnum` from the slot's counter, and computes `d` while holding the same lock used for extension and log append; callers cannot supply either number or substitute a precomputed digest. Swapping records across registers and renumbering them therefore either fails digest validation or changes the register bank and commitment. Imported CCEL, TPM and dstack logs retain their native ordering guarantees.

The order across registers lives in the content because CEL keeps `recnum` per index (section 4.2.2) and requires a record to carry what its digest covers (section 4.2.1.2); how a digest derives from content is the content type's to define (section 4.2.5).

The content type `cvm` is profile-private. CEL v1.1 Table 2 assigns values 4 to 10 (`cel`, `pcclient_std`, reserved, `ima_template`, `ima_tlv`, `systemd`, reserved) and defines no private range, so 200 is taken through the `$TPMS_CEL_EVENT-extension` socket the CEL CDDL provides, and a TCG registration request for it is filed in parallel:

```
$TPMS_CEL_EVENT-extension /= TPMS_CEL_EVENT<CVM, CVM_CONTENT>
CVM = JC<"cvm", 200>
CVM_CONTENT = { seq => uint, event => BYTEBUFFER }
seq = JC<"seq", 0>
event = JC<"event", 1>
```

In CEL-CBOR a record is the map `{0: recnum, 1: slot, 3: [{0: 12, 1: d}], 9: 200, 10: {0: seq, 1: event}}` with `event` a byte string, so the bytes that were hashed are the bytes that are stored; in CEL-JSON it is `{"recnum", "pcr", "digests", "content_type": "cvm", "content": {"seq", "event": hex}}`. Vectors in Appendix B.

### 4.9 SNP registers and the commitment (`ats-mr-v1`)

This is the format from the register document, unchanged where it is specified and fixed where it is not. Notation as in section 4.5.

```
genesis(i):  R[i] = SHA-384(zeros48 || "ats-mr-v1/genesis" || seed || u8(i))
extend:      R[i] = SHA-384(R[i] || d)                      d is the record digest of section 4.8
commit:      C    = SHA-384("ats-mr-v1/commit" || R[0] || R[1] || ... || R[reg_count-1]
                            || u64le(chain_len) || caller_data)
report_data: header16 || C                                   64 bytes exactly
```

- `zeros48` is 48 zero bytes. Every `R[i]` is 48 bytes and they are concatenated in index order.
- `seed` is the 48-byte constant `SHA-384("ats-mr-v1/seed")` (Appendix B). The register document seeded from the launch digest, which forces the provider to obtain a report before its first extend and adds no security the pinned launch digest does not already provide.
- `header16` is 16 bytes: `magic` = the 8 ASCII bytes `ATS-MR-1`, `version` = `u8(1)`, `alg` = `u8(1)` meaning SHA-384, `reg_count` = `u8(16)`, `flags` = `u8(0)` (every bit reserved), `reserved` = 4 zero bytes. The verifier compares all 16 bytes against the pinned header and rejects any difference, so no byte of the header is free for a caller to choose.
- `chain_len` counts every extension since genesis, across all slots, and is carried in `cvm_chain`. `caller_data` is `pad64(anchor)` and is not carried; the verifier derives it from the nonce and `cvm_binding.key`.
- `bootseed` is 32 random bytes the driver draws at boot and extends into slot 3 as record 0 of the log: a c8s event with domain `ats`, operation `boot`, `content_digest = SHA-384(bootseed)` and no `content`, because the seed travels in the `bootseed` claim and the verifier checks the claim's digest against the record. A valid chain therefore has `chain_len` at least 1 with the boot record at record 0, and the verifier requires both whenever the binding is `commitment`. A rebooted chain is distinguishable from a rewound one. Fork detection needs memory: attestation-api keeps `chain_len` and the last commitment per `bootseed` from the release that ships the driver and reports a chain that shrinks or diverges as a fork; the library exposes the hook and holds no state.
- Slots 4 to 15 are allocated at first use. The first record extended into a workload slot is its claim record: a c8s event with domain `ats`, operation `claim`, `content` the deterministic CBOR map `{0: owner (tstr), 1: purpose (tstr)}` with each string at most 255 bytes of UTF-8, and `content_digest = SHA-384(content)`. `owner` is the producer's identity as the register service authenticates it; that authentication is the register document's to define. The service refuses an extend into an unclaimed slot and an extend from any producer other than the slot's owner. The verifier requires every workload slot that left genesis to begin with a claim record, reports `owner` and `purpose` per slot, and policy may pin the owner of a slot (section 7). Vectors in Appendix B.

The verifier runs the order of section 6: chain and signature, then launch measurement and guest policy, then freshness, which for this mode is the commitment recompute, then replay. The register document says the launch measurement and the policy checks are the load-bearing steps, and the order enforces it. Vectors in Appendix B.

### 4.10 Encoding rules

JSON: claim names are strings; profile claims carry the `cvm_` prefix; byte strings are base64url without padding (RFC 4648 section 5); integers are JSON numbers; no floating point anywhere. Unknown claims at the top level or in a submodule claims set are ignored, as EAT extensibility requires; an unknown field inside any `cvm_*` object is rejected. Both JSON encodings in use today (standard base64 in the SNP and TDX payloads, base64url in the Azure payloads, hex in TPM quotes) are replaced by this rule; section 9 covers the transition.

An object with a duplicate member name is rejected, in the envelope, in every `cvm_*` object and in every CMW collection, so no two implementations can disagree about which value was meant; implementations whose JSON library keeps the last duplicate must check for duplicates themselves. Untrusted input is parsed without buffering and within fixed bounds: an envelope carries at most 66 submodules, a CMW collection at most 32 entries and one level of nesting, and every byte string field at most 1 MiB, with the whole envelope at most 10 MiB.

CBOR: claim keys from Appendix A; text strings for names, byte strings for bytes; deterministic encoding; definite lengths.

## 5. Result profile

Results are EAR per draft-ietf-rats-ear-04 with `eat_profile = tag:ietf.org,2026:rats/ear#04`. The library does not sign tokens; it produces the appraisal content and the relying party (c8s CDS today) signs. One EAR `submods` entry per evidence submodule, same names.

Per appraisal:

| Claim | Content |
| --- | --- |
| `ear_status` | AR4SI tier |
| `ear_trustworthiness_vector` | section 5.2 |
| `ear_appraisal_policy_ids` | two identifiers per submodule: the profile URI, which names the verification procedure, and the policy's own name `ni:///sha-384;<base64url>` (RFC 6920), the SHA-384 of the JCS serialization (RFC 8785) of the effective policy, with every member present with its value or default and null members omitted. Two results carry the same second identifier exactly when the same requirements were applied. Vector in Appendix B |
| `ear_attester_claims` | our normalized claims, section 5.1 |
| `ear_verifier_claims` | collateral and reference-value outcomes, section 5.1 |
| `ear_raw_evidence` | a CMW record of type `application/cmw+json` (RFC 9999 section 9.5.2), as the EAR CDDL requires, whose value is a CMW collection carrying the evidence envelope as appraised (indicator bit 2) and the endorsement snapshot the verifier used (bit 1), so the verdict re-verifies after a vendor withdraws collateral; at the top level of the EAR claims set beside `eat_nonce`; optional, on by default in attestation-api |
| `eat_nonce` | the nonce that was bound |

### 5.1 Normalized claims

`ear_attester_claims` for the `cpu` submodule:

| Claim | Meaning |
| --- | --- |
| `cvm_platform` | verified vendor and TEE; hosting as reported; `generation` from the report (SNP CPUID family and model, TDX FMSPC) |
| `cvm_launch_measurement` | `{alg, value}` |
| `cvm_registers` | verified array from section 4.7 plus `replayed` per entry |
| `cvm_freshness` | `{mode, key?}` as bound; presence means the check passed, because a failure is an error |
| `cvm_host_data` | `{semantics, value}`; semantics in `snp-host-data` (32 bytes), `tdx-mrconfigid` (48), `cca-rpv` (64); a label, see section 10 |
| `cvm_owner` | SNP `family_id`, `image_id`, `id_key_digest`, `author_key_digest`; TDX `mr_owner`, `mr_owner_config`. On SNP these are guest-owner values authenticated by the ID block, trustworthy only when policy pins `id_key_digest` or `author_key_digest`; on TDX they are host-set labels |
| `cvm_policy` | `{debug, migratable, smt, single_socket?, vmpl?, sept_ve_disable?, service_td?, reserved_bits_zero?}` normalized booleans and small integers |
| `dbgstat` | EAT debug status derived from `cvm_policy.debug`: `enabled` when the guest policy permits debug, `disabled-since-boot` otherwise, because the policy is fixed at launch (CBOR 0 and 2). It covers the TEE's guest-debug facility (the SNP policy DEBUG bit, the TDX DEBUG attribute), through which the host can read and write guest state; it makes no statement about the chip's hardware debug interfaces |
| `cvm_tcb` | vendor-tagged: SNP `{reported, committed, current, launch}` each with the SPL components; TDX `{tee_tcb_svn, pck_tcb, pcesvn, fmspc, status, advisories}`; CCA `{lifecycle, sw_components}`; GPU `{driver, vbios}` |
| `cvm_identity` | SNP `chip_id` (64 bytes); TDX `ppid`, the 16-byte Platform Provisioning ID from the PCK certificate's SGX extension (OID 1.2.840.113741.1.13.1.1); CCA `instance_id`; GPU `ueid` |
| `cvm_workload_id` | reserved: the derived TDX identity `keccak256(MRTD \|\| RTMR0..3 \|\| MRCONFIGID \|\| XFAM \|\| TDATTRIBUTES)` that on-chain policies key on. Never emitted in v1; the name and key are held so a later version cannot collide |

`ear_verifier_claims`:

| Claim | Meaning |
| --- | --- |
| `cvm_collateral` | per check: `{status: checked or skipped or not-applicable, reason?, this_update?, next_update?, signed?}` for `snp_crl`, `tdx_pck_crl`, `tdx_root_crl`, `tdx_tcb_info`, `tdx_qe_identity`, `nras_jwks` |
| `cvm_reference` | which reference values matched: launch measurement, per-slot registers |
| `cvm_backing_min` | the minimum backing the policy required and the weakest backing seen |

`collateral_verified: bool` does not survive. Neither does any `*_match: Option<bool>`; a supplied expectation that fails is an error.

### 5.2 Trustworthiness vector

Filled from AR4SI-10 values. The library returns the vector; it never returns a token for a failed cryptographic check, so the contraindicated crypto values (99) are reached only by a relying party that chooses to record failures.

| Category | Value and condition |
| --- | --- |
| hardware | 2 when the chain anchors, the signature verifies and the TCB status is acceptable; 32 when the vendor reports known vulnerabilities (TDX `OutOfDate`, `SWHardeningNeeded`, `ConfigurationNeeded`); 96 when revoked |
| instance-identity | 2 when the identity is on the policy's machine allowlist (chip id, PPID, instance id, GPU ueid); 97 when an allowlist is set and the identity is absent from it, which fails the appraisal; 0 when no allowlist is configured |
| executables | 2 when the launch measurement and every required register match reference values; 3 when only the launch measurement matched; 33 when a required register carries unrecognized extends; 96 when a contraindicated value is present |
| configuration | 2 when policy bits are acceptable; 96 when debug is enabled or VMPL is not 0 |
| runtime-opaque | 2 for every CVM whose report verified: the runtime is inside the TEE, encrypted and opaque to the hypervisor and host; this is the claim a TEE uniquely earns. Nothing is claimed about isolation between processes inside the guest |
| file-system | 0 unless an IMA-backed slot is verified, then 2 or 32 |
| storage-opaque | 0 in v1 |
| sourced-data | 2 for a GPU submodule NRAS affirmed with an acceptable device policy |

An `isSafe` boolean is not part of the profile. A relying party that wants one derives it from `ear_status` under its own policy.

### 5.3 Composition with the TDX and confidential-GPU EAR profile

draft-kykdxy-rats-tdx-cgpu-ear-profile (Microsoft, Intel, NVIDIA) defines EAR submodules `tdx`, `cvm_guest` and `gpu_N`, reuses Intel Trust Authority claim names for the TDX report (`tdx_mrtd`, `tdx_rtmr0` to `tdx_rtmr3`, `tdx_mrconfigid`, `tdx_mrowner`, `tdx_mrownerconfig`, `tdx_td_attributes`, `tdx_tee_tcb_svn`, `tdx_xfam`, `tdx_mrseam`, `tdx_mrsignerseam`), Azure MAA names for the guest (`tpm_*`), and defines `ear_all_submods_bound`, `ear_managed_keysets` and the `ear_nvidia_*` result claims. It covers no SEV-SNP, no Arm, no runtime registers beyond the RTMRs and no event logs.

This profile composes with it: for a TDX submodule the verifier emits the `tdx_*` claims above verbatim inside `ear_attester_claims` beside the vendor-neutral `cvm_*` claims, GPU submodules carry the NRAS claim names unchanged in `ear_attester_claims` (with `cvm_identity` and `cvm_tcb` beside them) and the draft's `ear_nvidia_evidence` (`signature_verified`, `parsed`, `nonce_match`, taken from NRAS's signed `x-nvidia-gpu-attestation-report-*` claims, or `x-nvidia-switch-attestation-report-*` for an NVSwitch) in `ear_verifier_claims`, and `ear_all_submods_bound` is set from the binding checks of section 4.5. A relying party written against that draft reads our tokens without a mapping; a relying party written against this profile gains SNP, Arm, registers and logs.

Multi-attester binding in v1 is `ear_all_submods_bound`, set from the per-submodule nonce checks of section 4.5. The detached-digest bundle of draft-sun-rats-composite-eat (SHA-384 digests, tag 602, one nonce for every sub-attester) is v2, so the GPU submodule ships now.

### 5.4 Composition with Confidential Containers Trustee

AMD runs no attestation service and defines no claim vocabulary; the only SNP names shared across deployments are the ones the Trustee verifier emits. For an SNP `cpu` submodule the verifier therefore emits an `snp` object inside `ear_attester_claims`, beside the `cvm_*` claims, carrying those names verbatim with Trustee's types: `policy_abi_major`, `policy_abi_minor` (integers), `policy_smt_allowed`, `policy_migrate_ma`, `policy_debug_allowed`, `policy_single_socket` (booleans), `reported_tcb_bootloader`, `reported_tcb_tee`, `reported_tcb_snp`, `reported_tcb_microcode` (integers), `platform_tsme_enabled`, `platform_smt_enabled` (booleans), `measurement`, `report_data`, `init_data` (Trustee's name for `HOST_DATA`) and `chip_id` (lowercase hex strings). Trustee nests exactly this object under the TEE name `snp` in its annotated evidence, so a policy written against Trustee's structure reads ours unchanged. The object is compatibility output: the `cvm_*` claims are normative, the `snp` object duplicates and never extends them, and its keys stay text in both encodings (Appendix A).

## 6. Verification procedure

Normative order for the `cpu` submodule; every step fails closed.

1. Parse the envelope. Reject unknown profile versions and unknown submodule names.
2. Select the parser from `cvm_report.format`. Re-derive vendor and TEE from the report and reject a contradicting `cvm_platform`.
3. Verify the hardware chain to the trust anchor and the report signature. SNP: ARK to ASK or ASVK to VEK against the embedded AMD roots, VEK validity, chip id and TCB cross-check against the report, VLEK detected from the certificate. When policy carries a machine allowlist, the identity this step authenticated must be on it. TDX: PCK chain to the embedded Intel SGX Root CA, QE report signature and binding. CCA: the platform token by the platform attestation key, which is endorsed per instance by the vendor (implementation id and instance id resolve the key through the verification service or a CoRIM; there is no single embedded root), then the realm token by the realm attestation key, then `hash(realm key) == platform challenge`.
4. Enforce guest policy. SNP: debug disabled unless policy allows, VMPL 0, migration disallowed unless policy allows. TDX, matching Intel's quote verification policy: debug bit clear, `SEPT_VE_DISABLE` set, every reserved TD attribute bit zero, and no migration-service TD (a non-zero MRSERVICETD in a 1.5 quote) unless policy allows. CCA: lifecycle in the accepted set.
5. Bind freshness per `cvm_binding.mode`. For `commitment` this is the recompute of section 4.9 over the registers established in step 7, so steps 5 and 7 run together for that mode.
6. Verify collateral per policy: revocation, TCB status and advisories against the TCB floor the machine's allowlist entry or `default_floor` names, QE identity, each with its signing chain anchored; record each outcome.
7. Establish registers: authoritative values from the report, the quote's PCR digest, or the commitment; reject envelope values that differ.
8. Replay the log when present; mark each register `replayed`.
9. Apply reference values and the backing minimum; produce claims, verifier claims and the vector.

For `vtpm`, steps 3 and 5 are the TPM signature by the AK and the AK binding to the CPU report, and step 7 projects PCRs. For GPU submodules the existing NRAS flow applies with the per-device policy gates the library already has: one request per architecture, every device of that architecture in it. NRAS names the submodules of a batch `GPU-<i>` and `SWITCH-<i>` with `<i>` the position in the request; the verifier maps them back by that index, requires the count to match, and takes the device identity from the signed `ueid` claim. The `<ueid>` in the submodule name is the attester's label and is never compared against policy.

## 7. Policy and reference values

Policy is a verifier input, never evidence:

```
VerifyPolicy {
  reference: { launch_measurement: [digest], registers: { slot -> [digest] }, slot_owners: { slot -> owner }?,
               pcrs: { pcr -> [digest] }?,   // the vtpm submodule's PCRs; Azure initdata is a pin on PCR 8
               host_data: bytes? }   // the value cvm_host_data must carry, zero-padded to the platform's length
  min_backing: Backing
  freshness: { key: Option<KeyBinding> }
  commitment: { header16: bytes, seed: bytes }
  tcb: { floors: { name -> TcbFloor }, default_floor: name?, tdx_allowed_status: [status],
         require_revocation: bool, require_signed_collateral: bool }
  policy_bits: { allow_debug: bool, allow_migration: bool, require_vmpl0: bool,
                 require_sept_ve_disable: bool, require_zero_reserved_attributes: bool, allow_service_td: bool }
  identity: { machines: [ { id: bytes, tcb_floor: name? } ] }?
  owner: { id_key_digests: [digest] }?
  gpu: NvidiaGpuParams (existing)
}

TcbFloor { snp: { min: { bootloader, tee, snp, microcode, fmc? },
                  values: [reported | current | committed | launch]? }?,   // all four when omitted
           tdx: { min_tee_tcb_svn: bytes16?, min_tcb_evaluation_data_number: int? }? }
```

Machine allowlists are first-class: `identity.machines[].id` is the submodule's `cvm_identity` value (SNP `chip_id`, TDX `ppid`, CCA `instance_id`, GPU `ueid`), authenticated by the hardware chain before it is compared. When `identity` is set, an identity absent from the list fails the appraisal (section 5.2); a machine that names a `tcb_floor` is held to that floor and every other machine to `default_floor`. Floors are named so a fleet carries one floor per generation and moves a machine between them without editing every policy.

An SNP floor bounds each TCB value it names, all four by default: `reported`, the TCB the VCEK that signed the report was derived for; `current`, the firmware running when the report was signed; `committed`, the anti-rollback floor SNP_COMMIT sets, below which the firmware cannot be loaded again; and `launch`, the current TCB when the guest was launched or imported. A floor on `reported` alone leaves a host free to roll the firmware back to its committed version between attestations, and a guest launched on vulnerable firmware keeps that exposure after a live update; the default closes both, and a policy narrows `values` only by naming the values it checks. A floor that names the FMC SPL fails a report without one, which is every generation before Turin. For TDX the Intel status and the floor are independent requirements: the status must be in `tdx_allowed_status` for every quote, and a named floor adds `tee_tcb_svn` componentwise and `tcbEvaluationDataNumber`. The evaluation number is what stops an older TCB Info, still inside its own validity window and validly signed, from reporting a status that a later TCB recovery changed.

Reference values come from confos manifests. confos publishes each manifest in two forms that carry the same values: the flat JSON deployments consume today, and a signed CoRIM (draft-ietf-rats-corim-11) whose CoMID reference triples carry the launch measurement in `digests` (measurement-values-map key 2) and the register reference values in `integrity-registers` (key 14), keyed by the slot index as an unsigned integer, with the digests typed by section 4.7's `alg`. The verifier ingests both into `reference` and treats them as one source, and a Veraison or Trustee deployment consumes the CoRIM without a translation.

## 8. Rust surface

The types are the profile, one to one, in `attestation::profile`; the code is the source of truth and the sketch below names the shape.

```rust
pub struct Evidence { pub eat_profile: String, pub eat_nonce: Bytes, pub cvm_version: u32, pub submods: BTreeMap<String, Submod> }
pub enum Submod { Cpu(CpuEvidence), CcaToken(NestedToken), Vtpm(VtpmEvidence), Device(GpuDeviceEvidence) }

pub struct CpuEvidence {
    pub cvm_platform: PlatformHint,
    pub cvm_report: CmwRecord,               // the SNP report or TD quote; on Azure the HCL report is in the vtpm submodule
    pub cvm_binding: Binding,                // pattern, mode and optional key (section 4.5)
    pub cvm_endorsements: Option<CmwCollection>,
    pub cvm_registers: Option<Vec<Register>>,
    pub cvm_log: Option<EventLog>,
    pub cvm_chain: Option<ChainInfo>,
    pub bootseed: Option<FixedBytes<32>>,
    pub dbgstat: Option<DebugStatus>,
}

pub struct Appraisal {                       // an EAR claims set (section 5)
    pub eat_profile: String, pub iat: i64, pub ear_verifier_id: VerifierId, pub eat_nonce: Bytes,
    pub ear_all_submods_bound: bool, pub submods: BTreeMap<String, SubmodAppraisal>,
}
pub struct SubmodAppraisal {
    pub ear_status: Tier, pub ear_trustworthiness_vector: TrustVector, pub ear_appraisal_policy_ids: Vec<String>,
    pub ear_attester_claims: AttesterClaims, pub ear_verifier_claims: VerifierClaims,
}

impl Verifier {
    pub async fn appraise(&self, evidence: &Evidence, policy: &VerifyPolicy) -> Result<Appraisal>;
    pub async fn appraise_json(&self, json: &[u8], policy: &VerifyPolicy) -> Result<Appraisal>;
    pub async fn appraise_legacy_json(&self, json: &[u8], nonce: &[u8], key: Option<KeyBinding>, policy: &VerifyPolicy) -> Result<Appraisal>;
}
```

The public surface is the verifier, the attester functions and the vocabulary; the per-platform parsers and verifiers are not part of it:

- `Verifier` appraises the profile (`appraise`, `appraise_json`, `appraise_legacy_json`) and keeps `verify` for the pre-profile envelope during the transition. `Verifier::with_clock` sets the evaluation time of section 14; every error carries its section 14.4 code through `AttestationError::refusal_code`. Its providers are set with `with_collateral`, `with_cert_provider`, `with_tdx_provider` and `with_nras_provider`.
- The attester side is `attest_profile`, with `attest` and `attest_with_nvidia_gpu` kept for the pre-profile envelope, and `detect` (Linux, `attest` feature).
- `profile` holds the evidence, policy and appraisal types and the section 4.5, 4.8 and 4.9 primitives. `collateral` holds the collateral keys, the cache and disk store, and every provider trait, NRAS included. `error` holds the errors, and `types` holds the pre-profile types, kept for two minor releases.
- `platforms` and the appraisal engine are private. The `unstable-internals` feature exposes `platforms` with no stability promise, for this repository's hardware tests and benches and for the wasm crate's pre-profile exports.

Collateral is one type with three transports (inline, cached, fetched), keyed by `CollateralKey`, with `valid_until` taken from each artifact, exactly as the sweep plan describes. The service is a router over the library cache.

Schemas: `schemas/cvm-evidence-v1.json`, `schemas/cvm-claims-v1.json` and `schemas/cvm-policy-v1.json` are generated from the Rust types (`attestation::profile::schema`) and committed; a library test fails on drift, and attestation-go and c8s-verify-js load them in CI and fail on drift. The test vectors of Appendix B are checked in as `docs/design/vectors/cvm_profile_vectors.json`, emitted by the same script, and every implementation consumes that file; the Rust test fails when a vector has no check. The WASM build exports `appraise(evidence_json, nonce, policy_json, snp_crl_der)`, `appraise_legacy`, and `appraise_with(evidence_json, policy_json, inputs_json)`, which takes the evaluation time, the issued nonce and the collateral the caller holds as inputs (section 14.2) and is the entry the conformance corpus runs; a refusal is a thrown `Error` whose `code` is the section 14.4 code. Its four per-platform exports stay for the transition and are removed with the pre-profile envelope.

## 9. Compatibility and migration

The current envelope `{platform, evidence, nvidia_gpu?}` maps mechanically: `platform` splits into `cvm_platform.tee` and `hosting`; `evidence` becomes `cvm_report` with the format chosen by platform and its byte encoding normalized to section 4.10; `nvidia_gpu.devices` become `gpu/<uuid>` submodules. The library accepts both forms for two minor releases: `appraise_json` takes the profile envelope, and `appraise_legacy_json` takes the old envelope together with the nonce the relying party expected as `report_data` (the profile's anchor with no key) and an optional key binding, since the old envelope carries neither. `attest_profile()` emits the profile from a nonce and an optional key binding, and `attest()` keeps the old envelope for its callers; the CLI emits the profile by default with `--format legacy` as the opt-out, and `POST /attest` emits the profile when the request carries `nonce` or `format: "cvm-v1"` and the old envelope otherwise, so a client that predates the profile keeps its response shape for one release; `POST /verify` accepts both, answering `appraisal` (EAR) for the profile and `result` for the old envelope, and every profile entry point (the service, the CLI, the WASM `appraise`) takes the relying party's nonce and refuses an envelope whose `eat_nonce` differs, since an appraisal bound only to the envelope's own nonce would accept a replay; the WASM build exports `appraise` and `appraise_legacy` beside the old entry points. The CLI's legacy expectation flags keep their meaning on a profile envelope: `--expected-report-data` is the nonce checked against `eat_nonce`, the launch, MRTD and RTMR pins narrow existing `reference` allowlists to the supplied value (a conflict is an error), and `--expected-init-data` pins `reference.pcrs[8]` to `SHA-256(zeros32 || initdata_hash)` on Azure or sets `reference.host_data` on other platforms, so a caller that changes only the evidence format loses no check. `VerificationResult` v1 is kept for one release as a projection of `Appraisal` and then removed.

The SNP register driver cannot ship before the verifiers understand the `commitment` mode; until then a report from that image fails every existing verifier's freshness check. Rollout order is therefore: library and WASM, attestation-go, c8s and c8s-verify-js, then the confos image.

c8s moves its EAR from profile 03 to 04 in the same release that adopts `appraise`, so no release emits both, and moves its private `launch_digest`, `tee_public_key` and `operator_keys_hash` claims into `ear_attester_claims` under the names here (`tee_public_key` stays a c8s extension inside `ear_attester_claims`). c8s also replaces its own `ExpectedReportData` derivation with `cvm_binding.key` of kind `spki-sha256`, so the verifier derives the anchor. The old Azure `expected_init_data_hash`, which compared PCR 8 against `SHA-256(zeros32 || initdata)`, becomes a pin on PCR 8 in `reference.pcrs`; on bare metal `reference.host_data` gates `HOST_DATA` and `MRCONFIGID` directly. Only the PCRs inside the quote's signed selection are appraised; an envelope that lists a PCR outside it is rejected.

## 10. Security considerations

- Everything outside a hardware signature is a hint or is bound before use (section 4.2). An implementation that reads `cvm_registers.value` without binding it has a fail-open bug by definition.
- Backing is a floor, never a downgrade path: policy states the minimum, the verifier reports the weakest seen, and a `kernel-service` register never satisfies a `hardware` requirement.
- Registers record what measured producers extend. A process that runs code through a path that does not extend a register leaves no trace; on SNP with the register driver this includes root inside the guest. The guarantee boundary is therefore "what the sanctioned producers recorded", and a deployment that needs "everything that ran" must either measure every execution into a slot (an IMA-style exec hook feeding a register) or remove the paths (no root, no exec outside the runtime). The profile carries `backing` and per-slot `replayed` so a relying party can tell which it got.
- The register document's kernel-service argument depends on a concrete restriction set (no module loading, no kexec, no `/dev/mem`, lockdown, eBPF and user namespaces, and every other kernel interface root can reach) that must be enumerated, measured into the launch digest, and checked by the verifier through the pinned image. Until that table exists and is pinned, `backing` for those registers is `virtualized`.
- Debug policy and VMPL are checked before any register claim is evaluated. With debug enabled the host reads guest memory and every register is meaningless.
- Nonces are at least 16 bytes. `report_data`, `extraData` and challenge comparisons are constant time over the full field.
- Collateral freshness is each artifact's own validity window (a CRL's `nextUpdate`, a certificate's `notAfter`, TCB Info's `nextUpdate`) evaluated against the current time. It is never a cache timer of our own: an artifact inside its window is served however long ago it was fetched, and an artifact past its window is rejected however recently it arrived. A body without its signing chain is rejected.
- The commitment header is pinned in full; an attacker cannot use it as 16 bytes of free choice next to the commitment. Domain tags separate the anchor, record, genesis, seed and commit hashes from each other and from the register values.
- Four findings from published audits of shipping confidential-inference systems are requirements here: the TCB used for policy is read from the endorsement certificate's extensions and cross-checked against the report, never from the report alone; a nonce is mandatory; a certificate-bound identity lives no longer than the CVM and the relying party bounds its age; any transparency or reference-value proof carries an age bound.

## 11. Changes to the two Notion documents

Standardizing Attestation:

- Replace the single JSON object with the two claim sets here: evidence (section 4) and result (section 5). `cert_chain` and `report` move to evidence; `launch_measurement`, `mr`, `tcb`, `host_data` move to results.
- `mr` becomes the register array with `index`, `alg`, `value`, `source`, `backing`, and the slot semantics of section 4.7.
- `host_data` is `32 or 48 or 64` by vendor and is a label; the Kata initdata case is the documented exception.
- `tcb` becomes the vendor-tagged union with all four SNP TCB values, and the floor moves to policy.
- `report_data` is replaced by `cvm_binding`, the mode table and the anchor derivation.
- Add the policy claims (debug bits per Yolan's comment) as `cvm_policy` and `dbgstat`.
- Remove `isSafe`; adopt `ear_status` and the vector.
- Cloud variants are the `vtpm` submodule with `privileged-service` backing, and Azure launch measurements are pinnable.
- `aael-cbor` becomes CEL, with the record layout of section 4.8.

SEV-SNP Measurement Registers:

- Add the restriction table Yolan asked for, with build, boot and runtime entries and how each is measured and verified.
- Resolve the module-loader contradiction (the NVIDIA open kernel modules are loadable modules).
- State the root-executes-unmeasured-code limit as the guarantee boundary, or add the exec hook.
- Name SVSM at VMPL0 as the target backing and keep the format independent of it.
- Replace the format block with section 4.9: the byte-exact genesis, extend and commit, the 16-byte header, `bootseed`, `caller_data = pad64(anchor)`, the constant genesis seed, deterministic CBOR for records, the atomicity of extend and commit, kernel-held log storage, slot claim records and owner authentication, and behavior past sixteen workloads.
- Add debug policy and VMPL to "what the verifier checks".

## 12. Decisions

All thirteen open items were closed on 2026-09-18. Each entry records the decision and where the normative text lives.

1. Genesis seed: the constant `SHA-384("ats-mr-v1/seed")` (section 4.9, Appendix B).
2. Slot ownership: the register service allocates slots 4 to 15 at first use, with a claim record as the slot's first extend; owner authentication belongs to the register document (section 4.9).
3. CEL content type: profile-private `cvm` = 200 through the CEL extension socket; a TCG registration request is filed in parallel (section 4.8).
4. `cvm_registers` is required whenever `cvm_log` is present (section 4.7).
5. c8s moves from EAR profile 03 to 04 in the same release that adopts `appraise` (section 9).
6. Naming stays `cvm_` and `tag:confidential.ai,2026:cvm#1`, with the media types under `application/vnd.confidential-ai.` (sections 4.3 and 4.4).
7. Fork-detection memory lives in attestation-api and ships with the SNP register driver; the library exposes the hook and holds no state (section 4.9).
8. SNP native names: the Trustee vocabulary is emitted verbatim as an `snp` compatibility object beside `cvm_*` (section 5.4).
9. Multi-attester binding: `ear_all_submods_bound` in v1, the composite-EAT detached-digest bundle in v2 (section 5.3).
10. Reference values: confos manifests are published as signed CoRIM beside the flat JSON, and machine allowlists with named TCB floors are a first-class policy input (section 7).
11. `cvm_workload_id`: name and key reserved, never emitted in v1 (section 5.1, Appendix A).
12. `tls-exporter`: kind name reserved for v2 and rejected by v1 verifiers (section 4.5).
13. `cvm_provenance`: claim and key reserved without v1 semantics (section 4.4, Appendix A).

## 13. Implementation plan

Each step is one reviewable PR in `attestation-rs` unless noted, in this order, after the open hotfixes (#89 to #93) merge.

1. `types`: `Evidence`, `Submod`, `Register`, `Backing`, `EventLog`, `Binding`, `Appraisal`, `VerifyPolicy`; schemas generated and committed; Appendix B vectors as fixtures; fail-closed expectations; `collateral_verified` and `*_match` removed from the new types.
2. `collateral`: `CollateralKey`, `Collateral` with `valid_until`, one fetcher, one cache with single flight, negative cache and validity-driven refresh; the service thinned to a router; typed collateral errors.
3. `verify`: `appraise` over the new types for SNP, TDX, Azure, GCP, dstack, GPU; the `snp` compatibility object; machine allowlists and named floors; CoRIM ingest into `reference`; envelope v1 accepted through the mapping in section 9; WASM `appraise` export; legacy exports deleted.
4. `platforms` to `pub(crate)` with a curated public surface.
5. `registers`: CEL parsing and replay, register establishment per source, claim records, `ats-mr-v1` commitment verification behind a feature until the driver ships; attestation-api's fork memory lands with the driver.
6. attestation-go and c8s-verify-js: schema pins, vectors, `appraise` parity; EAR 04 and the anchor derivation in c8s in the same release.
7. Arm CCA: nested token submodule and the CCA verification rules, when Vera Rubin hardware is available.
8. `tcg-cel` (`cel` on crates.io is the Common Expression Language): a standalone crate for CEL-CBOR and CEL-JSON encoding, parsing and replay, with ingest from TCG2 logs (TPM and CCEL), the attestation-agent entries a CCEL carries, and dstack JSON; no such library exists in any language, and the log half of this profile is only reusable if it does. On the design branch as `crates/tcg-cel`, without the CEL-TLV encoding.
9. NRAS: the provider is on `/v4/attest/gpu` and `/v4/attest/switch` with claims version 3.0, as NVIDIA's attestation SDK is. The request body is the v3 body; the difference that matters is that the overall token's `submods` digests are SHA-256 over the returned device tokens, which the verifier now checks along with `iss` and `x-nvidia-ver`. NVSwitch tokens carry `x-nvidia-switch-*` claims, which the verifier now maps (before this step every NVSwitch failed the nonce-match gate).

10. Conformance (section 14): the corpus, the Rust runner that generates and checks it, the Go and JavaScript harnesses that ship with the corpus, and the wasm build's run in continuous integration; attestation-go runs the Go harness once it has `appraise` (step 6). Every later change to a decision in sections 4 to 7 lands with its case.

Each PR carries the premises it rests on and how they were verified, per the review standard the hotfixes set.

## 14. Conformance

An implementation of this profile conforms when it passes the conformance corpus at the corpus version it declares. The corpus is the executable form of the normative statements in sections 4 to 7: the schemas of section 8 constrain the shape of evidence, policy and results, the vectors of Appendix B constrain the hash formulas, and the corpus constrains the decisions. A decision that has no case is not part of the contract, and a statement in sections 4 to 7 that has no case is a gap the corpus lists until it is closed.

### 14.1 Layout and versioning

The corpus lives in `conformance/` at the root of the attestation-rs repository, beside the schemas, and is consumed as data by every implementation:

```
conformance/
  VERSION            the corpus version
  README.md          how to run the corpus against an implementation
  UNCOVERED.md       the normative statements that have no case yet
  cases/<id>.json    one case per file
  inputs/            the evidence, policies, collateral and recorded NRAS exchanges the cases reference
  go.mod, *.go       the Go harness: the corpus embedded, its loader, the comparison rules, the runner
  package.json, index.mjs   the JavaScript harness, the same for Node
```

The harnesses are the corpus's own and carry no implementation: each loads the cases, checks them against the section 14.2 format, reads a case's inputs, applies the comparison rules of section 14.3 and reports one outcome per case, `pass`, `fail` (another decision) or `error` (no decision). An implementation supplies an appraiser, a function from a case's inputs to an appraisal or a refusal, and runs the harness in its own test suite. A Go implementation pins a corpus version by pinning the module `github.com/confidential-dot-ai/attestation-rs/conformance` at the tag `conformance/v<version>.0`, since the corpus is embedded in it; the wasm build runs the JavaScript harness from its own checkout in continuous integration, and a JavaScript package that wraps the wasm build inherits that run.

The corpus version is `<profile version>.<revision>`, `1.0` at the first publication. A change to any case, including a new case, raises the revision; a change that alters a decision in sections 4 to 7 lands in one commit with the case that shows it. A case id is never reused. An implementation states the corpus version it passes (`conforms to tag:confidential.ai,2026:cvm#1, corpus 1.<n>`) and pins that version in its continuous integration the way it pins the schemas.

The Rust library is the reference implementation: it generates the expected results and reviewers read them as part of the change. Every other implementation only checks. A case the reference implementation fails is a defect in the reference implementation or in the case, and the corpus is corrected before the implementation.

### 14.2 Case format

A case is one JSON object:

```
case = {
  "id": text,                         ; kebab-case, unique, permanent
  "rule": { "section": text, "statement": text },
  "now": text,                        ; RFC 3339 UTC: the evaluation time
  "evidence": path,                   ; the profile envelope, JSON
  ? "policy": path,                   ; the VerifyPolicy, JSON; absent means the section 7 default
  ? "collateral": { * collateral-key => (path / { "body": path, "signing_chain": path }) },
  ? "nras": [ * nras-exchange ],
  "expect": { "appraisal": path } / { "refusal": refusal-code },
}
path = text                           ; relative to conformance/inputs, forward slashes
collateral-key = text                 ; the text form of the collateral key (section 8)
nras-exchange = { "arch": text, "nonce": text, "response": path, "jwks": path }
```

`rule.section` names the section the case exercises and `rule.statement` quotes it, so a case is traceable to the text and the text to its cases. Every input is a file under `inputs/`, so a case is self-contained and identical for every implementation.

A case fixes everything a decision depends on:

- `now` is the evaluation time. Every validity window in the appraisal (certificate notBefore and notAfter, CRL thisUpdate and nextUpdate, TCB Info and QE Identity nextUpdate, NRAS token nbf and exp, the age bounds of section 4.5) is judged against it. A conforming verifier takes the evaluation time as an input; one that reads the wall clock cannot run the corpus.
- `collateral` is the whole collateral the appraisal may use, keyed as section 8 keys collateral (`snp_vcek/<generation>/<chip id>-<tcb>`, `snp_cert_chain/<generation>`, `snp_crl/<generation>`, `tdx_tcb_info/<fmspc>`, `tdx_qe_identity/td`, `tdx_pck_crl/<ca>`, `tdx_root_crl`, `nras_jwks/<url>`), each file the artifact's bytes as the source serves them, with signed Intel artifacts carrying their signing chain beside the body. A request for a key the case does not carry fails as unavailable collateral. The envelope's inline endorsements are inputs to the case like any other, and the provider-first rule of section 4.6 applies.
- `nras` holds the recorded exchange for each architecture batch the appraisal sends: the nonce it will send (section 4.5), the detached EAT NRAS returned and the JWKS that verifies it. A request the case does not carry fails as unavailable collateral. Nothing in the corpus reaches a network.
- `policy` is the complete policy; a case that omits it runs under the section 7 defaults, and its identifier (section 5.1) is the one the expected result carries.

A case exercises one statement. Where an input breaks several, the verification order of section 6 decides which refusal the case expects, and the case says so in `rule.statement`.

### 14.3 Comparison rules

For `expect.appraisal`, the runner produces the appraisal, encodes it as the section 5 JSON, and compares it with the expected file as parsed JSON values after removing, from both, the members that are the implementation's own and never part of the decision:

- `iat`;
- `ear_verifier_id`;
- `ear_raw_evidence`;
- `reason` inside every `cvm_collateral` entry.

Everything else must be equal: `eat_profile`, `eat_nonce`, `ear_all_submods_bound`, the set of submodule names, and for each submodule `ear_status`, `ear_trustworthiness_vector`, `ear_appraisal_policy_ids`, `ear_attester_claims` and `ear_verifier_claims` in full, `cvm_collateral` statuses, dates and `signed` included, since the case fixes the collateral and the clock. An implementation that emits an extra claim fails the case; the contract is the claim set of section 5.

For `expect.refusal`, the runner maps the implementation's error to one code of section 14.4 and compares codes. An implementation documents its mapping: the reference implementation's is `AttestationError::refusal_code`, the wasm build throws an `Error` whose `code` is that code, and a Go implementation returns the harness's `Refusal`. An error the mapping does not cover is no decision, reported as an error, never as a refusal. A refusal with another code is a different decision and fails the case, as does an appraisal where a refusal was expected or the reverse.

### 14.4 Refusal codes

A refusal names the rule family that failed, never the implementation's error type or message. The codes, with the section each belongs to:

| Code | Section | Meaning |
| --- | --- | --- |
| `envelope-invalid` | 4, 4.10, step 1 and 2 | the envelope, a submodule or a `cvm_*` object breaks a shape, encoding, size, version or consistency rule, including an attester hint that contradicts the signed report and a reserved kind or claim of section 12 |
| `policy-invalid` | 7 | the policy fails its own validation |
| `platform-unsupported` | 2 | the TEE or hosting is one this verifier does not implement |
| `report-invalid` | step 2 | the hardware report cannot be parsed, or its version is outside the supported range |
| `signature-invalid` | step 3 | a hardware or vendor signature does not verify: the report, the quote, the TPM quote, the HCL report |
| `chain-invalid` | step 3 | a certificate chain does not reach the pinned root, contradicts the report, or is outside its validity at `now`; a quoting enclave that is not the one Intel's QE Identity names |
| `machine-not-allowed` | step 3, 7 | the authenticated machine identity is missing from the policy's allowlist |
| `guest-policy` | step 4 | a guest policy bit, TD attribute, VMPL, debug state or lifecycle violates policy |
| `binding-mismatch` | step 5, 4.5 | the freshness binding of the submodule's mode does not hold |
| `collateral-unavailable` | step 6 | an artifact policy requires could not be obtained |
| `collateral-invalid` | step 6, 4.6 | an artifact fails its signature, its signing chain or its window at `now` (a CRL's thisUpdate and nextUpdate, TCB Info's and QE Identity's nextUpdate), cannot be parsed, or contradicts the provider's copy |
| `revoked` | step 6 | a certificate is revoked |
| `tcb-not-allowed` | step 6, 7 | a TCB status outside the allowed set, an advisory the policy refuses, a TCB value below its floor, or a QE TCB level the QE Identity revokes or does not list |
| `register-mismatch` | step 7 | an envelope register differs from the authoritative value, or is unauthenticated |
| `log-required` | 4.8, 4.9 | a log the mode requires is absent, or `chain_len` and the log disagree |
| `log-invalid` | 4.8 | the log cannot be parsed whole under its format's rules |
| `replay-mismatch` | step 8, 4.9 | a replay does not reproduce a register that must reproduce, a record digest does not reproduce, or a slot rule of section 4.9 is broken |
| `reference-mismatch` | step 9, 7 | a pinned launch measurement, register, PCR, host data or slot owner differs |
| `backing-below-minimum` | step 9, 7 | a register's backing is below the policy minimum |
| `device-required` | 7 | policy requires a device and the envelope carries none |
| `device-not-allowed` | 7 | a device's architecture is outside the allowed set, or the envelope carries more devices than the verifier accepts |
| `device-token-invalid` | 4.4 | NRAS answered with a token the verifier refuses: signature, issuer, claims version, `submods` digest, key identifier |
| `device-policy` | 7 | NRAS's overall result is false, or a per-device gate failed |
| `unsupported` | | a format or feature this release does not implement, such as the standalone `aael` log |

### 14.5 Coverage and change control

Every normative statement in sections 4 to 7 has at least one case, and every rule the verifier enforces has a case that shows the refusal. `UNCOVERED.md` lists the statements without one; the list shrinks and never grows without a stated reason. A pull request that changes a decision carries the case that shows the new decision, the doc change that states it, and the corpus revision; the reference implementation's runner refuses a corpus whose cases cite a section that does not exist.

The corpus is published with the profile. A relying party that reads a result token can ask which corpus version the verifier passes, and two implementations that pass the same version agree on every decision it covers.

## Appendix A. CBOR claim keys

Profile claims use integer keys in the CWT private-use range (RFC 8392 section 9.1, values below -65536). Standard claims keep their registered keys.

| Claim | Key |
| --- | --- |
| `cvm_version` | -70000 |
| `cvm_platform` | -70001 |
| `cvm_report` | -70002 |
| `cvm_binding` | -70003 |
| `cvm_endorsements` | -70004 |
| `cvm_registers` | -70005 |
| `cvm_log` | -70006 |
| `cvm_chain` | -70007 |
| `cvm_provenance` | -70008 (reserved, section 4.4) |
| `cvm_tpm_quote` | -70010 |
| `cvm_tpm_ak` | -70011 |
| `cvm_launch_measurement` | -70020 |
| `cvm_freshness` | -70021 |
| `cvm_host_data` | -70022 |
| `cvm_owner` | -70023 |
| `cvm_policy` | -70024 |
| `cvm_tcb` | -70025 |
| `cvm_identity` | -70026 |
| `cvm_workload_id` | -70027 (reserved, section 5.1) |
| `cvm_collateral` | -70030 |
| `cvm_reference` | -70031 |
| `cvm_backing_min` | -70032 |

Result tokens use the EAR labels of draft-ietf-rats-ear-04: `ear_status` 1000, `ear_trustworthiness_vector` 1001, `ear_raw_evidence` 1002, `ear_appraisal_policy_ids` 1003, `ear_verifier_id` 1004 (`developer` 0, `build` 1), `ear_attester_claims` 1005, `ear_verifier_claims` 1006, `ear_device_topology` 1007.

Compatibility objects (the `tdx_*` claims of section 5.3 and the `snp` object of section 5.4) keep text keys in both encodings, because the vocabularies they mirror define none. The reserved keys carry no v1 semantics: a v1 verifier ignores `cvm_provenance` as EAT extensibility requires for a whole claim, and never emits `cvm_workload_id`.

## Appendix B. Test vectors

All values hex. `nonce` is the 16 bytes `00 01 ... 0f`.

Anchor, no key: `anchor = nonce`.

Anchor with key `{kind: "spki-sha256", value: 0x11 repeated 32 times}`:

```
input  6174732d616e63686f722d7631 10 000102030405060708090a0b0c0d0e0f
       0b 73706b692d736861323536 0020 1111111111111111111111111111111111111111111111111111111111111111
anchor f98d63e4c2e788b0b92ce5d7d1f2609b191f2933f4e5e7884bfeafc4c7a16ed8e050bf2649e1e85ad4b6c89ae70e35d7
pad64  f98d63e4c2e788b0b92ce5d7d1f2609b191f2933f4e5e7884bfeafc4c7a16ed8e050bf2649e1e85ad4b6c89ae70e35d700000000000000000000000000000000
```

Anchor with key `{kind: "x509-tbs-sha256", value: 0x22 repeated 32 times}`:

```
anchor 6537d4a660c13227cc3c2a54a9d7ba6eef051ab942f0acf1d065ba279f01ab001d309f2dbb8d3c8e8cdc6cf966a45f04
```

NRAS nonce derivation from `nonce`:

```
gpu     a5db775022742960966c4ad77b3d903d6645eee00575a557cd18963d31251325
switch  84982aa6b0e69839ac5b84d62d2c16f30239baa2a99add9975d09aa439c47051
```

`ats-mr-v1` with the recommended constant seed:

```
seed          60cdcaeac3f15a96cb2a1b85d42c5a4d129fced65435044c9250fdffef98984cc3bd420972c3af58295e0f61ba21e4a7
R[0] genesis  edfcbed49c915465118143bd6ba1980e0fa6ccfe02242bc31676a275e31cd0081c9d8b9ba9d6f4ee70b94b030b1e04fa
R[3] genesis  befc3a5c2b1a1842ea1e7d330a9671c09afa59f2b2e775bd9b77b1a3a89d68e77ea5d2fafe5dfd3767f5ea515c30307a
R[15] genesis ca7955a6100998d9c4771d94e785098d878b66d2956c54a5f47e847694bfd246a251bb1dcd929fd945fa37de37b1c3b2
header16      4154532d4d522d31 01 01 10 00 00000000
```

Commit at genesis (all 16 registers at their genesis values, `chain_len = 0`, `caller_data = pad64(nonce)`):

```
C            22dadccfe3024c6dc4588664a00c9638ce36e10f153cf12a832a023c8f13b011a21e98ba4dab9034d02ddb5d596415c4
report_data  4154532d4d522d310101100000000000 22dadccfe3024c6dc4588664a00c9638ce36e10f153cf12a832a023c8f13b011a21e98ba4dab9034d02ddb5d596415c4
```

One extend at `seq` 0 into slot 3 with event bytes `a3006373386301706d73746172742d636f6e7461696e65720258300102` (any bytes serve for the vector; the profile's event is the CBOR map of section 4.8), then a commit with `chain_len = 1` and `caller_data = pad64(anchor with key)`:

```
d            fd21b47ecf576057b92765553b8e264949fcd74aae46c8cd023a2c34cba68233f765919d4405fdb9b4e5bc25b86235f5
R[3]         0553eb463cfb7cc8d4f0c5ae6d0e6023e6cef8d8624535567757d8b73d9dac8f83d682e26eae16f2a3f8aa23cd86df53
C            7290cc8b8f2476f8565f33573a72c37eb834e96f0684823ea5705a4f78cb734d98171c605eb73c47bdec78526f903101
report_data  4154532d4d522d310101100000000000 7290cc8b8f2476f8565f33573a72c37eb834e96f0684823ea5705a4f78cb734d98171c605eb73c47bdec78526f903101
```

The boot record of section 4.9 with `bootseed` = 0x33 repeated 32 times, as record 0 of the log in slot 3: `seq` 0 and `recnum` 0 (the event is an `a3` map of three: 0 `ats`, 1 `boot`, 2 `SHA-384(bootseed)`; no content entry):

```
content      a300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2d
d            74eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc
R[3]         fa415452924a55dba8c716598ebfa8abe0808e94cffa6ed4abf28db4c0f18999ffd0f2c14ff2b5b6130a343c63155d69
CEL record   a5 00 00 01 03 03 81 a2 00 0c 01 5830 <d> 09 18c8 0a a2 00 00 01 583f <event>
             a5000001030381a2000c01583074eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc0918c80aa2000001583fa300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2d
```

The claim record of section 4.9 for slot 4 with owner `c8s` and purpose `workload`, as record 1 of the log: `seq` 1, and `recnum` 0 as the first record of slot 4 (`R[3]` above is genesis(3) extended with the boot record alone; `R[4]` below is genesis(4) extended with the claim record alone):

```
claim body   a200636338730168776f726b6c6f6164
content      a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164
d            24be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c
R[4]         e314c1b137729a35436b11d4c0b77c17058b210a33c1bbe36a7682f0b222930db389c7dc22868f7bebf75934156a6d34
CEL record   a5 00 00 01 04 03 81 a2 00 0c 01 5830 <d> 09 18c8 0a a2 00 01 01 5852 <event>
             a5000001040381a2000c01583024be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c0918c80aa20001015852a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164
```

The log of those two records, as `tcg-cel-cbor` (the CDDL's array: `82`, then the two records above) and as `tcg-cel-json`:

```
82a5000001030381a2000c01583074eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc0918c80aa2000001583fa300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2da5000001040381a2000c01583024be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c0918c80aa20001015852a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164
```

```
[{"recnum":0,"pcr":3,"digests":[{"hashAlg":"sha384","digest":"74eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc"}],"content_type":"cvm","content":{"seq":0,"event":"a300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2d"}},{"recnum":0,"pcr":4,"digests":[{"hashAlg":"sha384","digest":"24be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c"}],"content_type":"cvm","content":{"seq":1,"event":"a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164"}}]
```

The identifier of the default policy (section 5.1). The canonical form is the JCS serialization of the effective default policy; any implementation that fills the defaults of section 7 and serializes with RFC 8785 reproduces it:

```
JCS          {"commitment":{"header16":"QVRTLU1SLTEBARAAAAAAAA","seed":"YM3K6sPxWpbLKhuF1CxaTRKfztZUNQRMklD9_--YmEzDvUIJcsOvWCleD2G6IeSn"},"freshness":{},"gpu":{"device_policy":{"allow_debug":false,"require_measres_success":true,"require_nonce_match":true,"require_secboot":true},"required":false},"min_backing":"hardware","policy_bits":{"allow_debug":false,"allow_migration":false,"allow_service_td":false,"require_sept_ve_disable":true,"require_vmpl0":true,"require_zero_reserved_attributes":true},"reference":{"launch_measurement":[],"pcrs":{},"registers":{},"slot_owners":{}},"tcb":{"floors":{},"require_revocation":true,"require_signed_collateral":true,"tdx_allowed_status":["UpToDate"]}}
SHA-384      a678b73c551d1a00857d906715789f89c0f89683086fe8a28a1dfb537a9271520c121a3da5ca0838fb9e0cc8b3d0dc10
id           ni:///sha-384;pni3PFUdGgCFfZBnFXificD4loMIb-iiih37U3qScVIMEho9pcoIOPueDMiz0NwQ
```

These vectors revise the unreleased v1 draft twice: content-only event digests are no longer accepted as `cvm` records, and the records follow CEL v1.1, with `recnum` counted per slot, the content under `content_type` 9 and `content` 10, the global sequence in the `cvm` content and the log as one CBOR array. The record digests are unchanged by the second revision. The pending driver and producers must adopt both together with the verifier.

The vectors were produced with SHA-384 and SHA-256 from a standard library over the exact byte strings written above; the generating script is committed beside the schemas so any implementation can regenerate them.
