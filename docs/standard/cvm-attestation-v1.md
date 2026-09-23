# CVM Attestation v1: Evidence, Runtime Measurements and Appraisal Results for Confidential Virtual Machines

| | |
| --- | --- |
| Profile | `tag:confidential.ai,2026:cvm#1` |
| Version | 1, draft of 2026-09-22 |
| Conformance corpus | 1.5 |
| Author | Mahmoud Shehata, Confidential AI (mahmoud@confidential.ai) |
| Status | Draft for publication |

## Abstract

Confidential virtual machines (CVMs) on AMD SEV-SNP, Intel TDX and Arm CCA, with or without a cloud paravisor and with or without attached NVIDIA GPUs, each prove their state in a different format and each prove a different set of facts. This document defines one attestation contract that covers all of them. It specifies an evidence envelope that carries the unmodified hardware reports as an Entity Attestation Token (EAT) profile; a single freshness and key-binding rule with one declared binding mode per attester; a runtime measurement register model in which every register carries its hash algorithm, its source and the strength of the mechanism that protects it; one replayable event log encoding based on the TCG Canonical Event Log; a construction that gives SEV-SNP guests extend-only runtime registers bound into hardware-signed reports; a normative verification procedure; attestation results as EAT Attestation Results (EAR) with normalized claims; a verifier policy; and a conformance corpus that turns the verifier's decisions into executable cases, with the statements it does not yet cover listed.

## Status of this document

This is the normative specification of the EAT profile `tag:confidential.ai,2026:cvm#1`. It is a draft published for review and implementation. The machine-readable companions are normative and are published with it: the CDDL module of Appendix C (`schemas/cvm-profile-v1.cddl`), the test vectors of Appendix B (`docs/standard/vectors/cvm_profile_vectors.json`) and the conformance corpus of Section 14 (`conformance/`). Where this text and a companion disagree, the disagreement is a defect in this document or in the companion, and conformance is judged against the corpus until the defect is corrected.

The profile identifier, the media types under `application/vnd.confidential-ai.` and the claim names in the `cvm_` namespace are controlled by Confidential AI. Changes that alter a decision in Sections 4 to 13 raise the corpus revision (Section 14.5); changes that alter the wire format define a new profile identifier.

## Table of contents

1. Introduction
2. Terminology
3. Architecture
4. Evidence
5. Freshness and binding
6. Measurement registers
7. Event logs
8. Software registers on SEV-SNP
9. Platform bindings
10. Endorsements
11. Verification procedure
12. Appraisal results
13. Verifier policy
14. Conformance
15. Security considerations
16. Privacy considerations
17. IANA considerations
18. Implementation status
19. References

Appendix A. CBOR claim keys. Appendix B. Test vectors. Appendix C. CDDL module. Appendix D. Examples. Appendix E. Trust anchors. Acknowledgments.

## 1. Introduction

### 1.1. Problem statement

A workload that relies on attestation, such as a key release service, a TLS client that verifies its peer, or an orchestrator that admits nodes, has to consume and verify evidence from every hardware vendor it runs on. AMD, Intel and Arm define different report formats, and out of the box they prove different things: Intel TDX reports hardware runtime measurement registers, AMD SEV-SNP has none, Arm CCA reports them with a width that follows a negotiated hash algorithm. Cloud providers add a further layer: Microsoft Azure wraps the hardware report behind a paravisor and a virtual TPM, so the freshness challenge lands in a TPM quote and the hardware report binds the TPM's key. Attached GPUs are attested by the GPU vendor's service with its own token format.

Without a common contract, every relying party re-implements vendor-specific checks, and guarantees written against one vendor's fields have to be rebuilt for the next. With this contract, a relying party writes one policy, receives one result format, and reads in that result exactly which facts were established and how strongly each is protected.

### 1.2. Scope

This document covers the following attesters, each specified in Section 9. Section 18 states which of them the reference implementation appraises today.

| Attester | TEE | Hosting | Hardware evidence | Binding mode |
| --- | --- | --- | --- | --- |
| AMD SEV-SNP guest | `sev-snp` | `bare`, `gcp`, `dstack` | SNP attestation report | `report-data` |
| AMD SEV-SNP guest with a register provider | `sev-snp` | `bare`, `gcp`, `dstack` | SNP attestation report whose report data is an `ats-mr-v1` commitment | `commitment` |
| Intel TDX guest | `tdx` | `bare`, `gcp`, `dstack` | TD quote, version 4 or 5 | `report-data` |
| Azure SEV-SNP confidential VM | `sev-snp` | `azure` | SNP report inside the HCL report, and a vTPM quote | `vtpm-extradata` |
| Azure TDX confidential VM | `tdx` | `azure` | TD quote over the HCL report's TD report, and a vTPM quote | `vtpm-extradata` |
| Arm CCA realm | `cca` | `bare` | CCA attestation token (platform and realm tokens) | `cca-challenge` |
| NVIDIA Hopper and Blackwell GPUs | device | any | SPDM evidence appraised by NVIDIA NRAS | `nras-nonce` |
| NVIDIA NVSwitch (LS10) | device | any | SPDM evidence appraised by NVIDIA NRAS | `nras-nonce` |

Out of scope for version 1: device assignment through TEE-IO (TDISP, TDX Connect, SEV-TIO), SGX enclaves, live migration of CVMs, availability, microarchitectural side channels, physical attacks, and the build-time supply chain of the measured images (which reference values address, Section 13.4).

### 1.3. Design principles

1. Three messages with three authorities. Evidence is what the attester sends. Policy is what the relying party requires. The appraisal is what the verifier established. A launch measurement in a result is always the value the verifier extracted from a signed report.
2. Only signed or bound bytes decide. Every field of the evidence is classified as signed, bound or hint (Section 3.4). A hint selects a parser and nothing else, and a hint that contradicts signed data is a refusal.
3. Fail closed. A check that cannot be performed is a failure unless the policy explicitly waives it, and a waived check is visible in the result.
4. Name the protection level. Every runtime register carries a `backing` that states what protects it, and the policy sets a minimum, so a guarantee cannot be silently downgraded from hardware to software.
5. One nonce, one declared binding per attester, one derivation of the binding input for every platform.
6. Preserve platform differences where they carry meaning (TCB values, host-set fields, register widths) and normalize where they do not (debug, migration, SMT).
7. Compose existing standards and define only what they leave open: RATS roles (RFC 9334), EAT (RFC 9711), unprotected claims sets (RFC 9781), conceptual message wrappers (RFC 9999), EAR (draft-ietf-rats-ear-04), AR4SI (draft-ietf-rats-ar4si-10), the TCG Canonical Event Log and CoRIM (draft-ietf-rats-corim-11).

### 1.4. Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.

### 1.5. Notation

- `||` is byte concatenation with no separator and no length prefix unless one is written explicitly.
- A quoted string such as `"ats-mr-v1/seed"` denotes its ASCII bytes with no terminator.
- `u8(n)` is one byte; `u16be(n)` is two bytes big-endian; `u16le(n)` two bytes little-endian; `u32le(n)` four bytes little-endian; `u64le(n)` eight bytes little-endian.
- `zeros48` is 48 zero bytes; `zeros32` is 32 zero bytes.
- `pad64(x)` is `x` followed by zero bytes to a length of 64 bytes; `x` MUST be at most 64 bytes.
- `SHA-256` and `SHA-384` are the functions of FIPS 180-4.
- `len(x)` is the length of `x` in bytes.
- Offsets in report layouts are byte offsets from the start of the structure, written in hexadecimal with a `0x` prefix; lengths are decimal byte counts.
- Hexadecimal byte strings are written in lowercase without separators unless spaces are shown for readability, in which case the spaces are not part of the value.
- CDDL is RFC 8610 with the control operators of RFC 9165 and RFC 9741.

## 2. Terminology

The roles Attester, Verifier, Relying Party, Endorser and Reference Value Provider, and the messages Evidence, Endorsements, Reference Values and Attestation Results, are used as defined in RFC 9334 section 4. In addition:

CVM: a virtual machine whose memory and register state the TEE protects from the host.

Hardware report: the structure the TEE signs: an SNP attestation report, a TD quote, a CCA token.

Launch measurement: the digest the TEE computes over the initial contents of the CVM before it runs: SNP `MEASUREMENT`, TDX `MRTD`, CCA Realm Initial Measurement (RIM).

Measurement register (register): an append-only value that can only be changed by extending it, `R' = H(R || d)`, where `d` is the digest of what is being recorded.

Slot: the index of a register within its source.

Source: the mechanism that holds a register: `tdx-rtmr`, `snp-vmr`, `vtpm-pcr`, `cca-rem` (Section 6.2).

Backing: the strength of the mechanism that protects a register against modification by code inside the CVM (Section 6.4).

Event log: the ordered records of what was extended into registers. Replay recomputes the registers from the log.

Measured producer: software, itself covered by a measurement, that extends registers and appends log records.

Register provider: the component that holds software registers and computes the commitment on SEV-SNP (Section 8).

Anchor: the verifier-derived binding input that combines the relying party's nonce with an optional key (Section 5.2).

Binding mode: where and how an attester's evidence binds the anchor (Section 5.4).

Submodule: one attester's claims inside the evidence envelope, in the sense of RFC 9711 section 4.2.18.

Collateral: the endorsements a verifier needs besides the evidence: certificates, certificate revocation lists, TCB status documents, token signing keys.

Evaluation time: the instant against which the verifier judges every validity window. It is an input to the appraisal (Sections 11 and 15.9).

Refusal: the outcome of an appraisal that fails; it carries one refusal code (Section 14.4).

## 3. Architecture

### 3.1. Roles

| Role | In this profile |
| --- | --- |
| Attester | an agent inside the CVM that collects the hardware report and builds the envelope; the TEE firmware that signs the report; the paravisor's vTPM on Azure; the Realm Management Monitor (RMM) for Arm realms; each NVIDIA GPU and NVSwitch |
| Verifier | a library or service that implements Section 11 |
| Relying party | the party that issued the nonce and consumes the appraisal |
| Endorser | AMD Key Distribution Service (KDS), Intel Provisioning Certification Service (PCS), NVIDIA Remote Attestation Service (NRAS), the Arm CCA platform vendor's verification service, the cloud provider for paravisor-held keys |
| Reference value provider | the publisher of the measured image, which publishes launch measurements and expected register values (Section 13.4) |

### 3.2. Message flow

```
 Relying party                 Attester (inside the CVM)             Verifier
      |                                  |                              |
      |------ nonce (16 to 64 bytes) --->|                              |
      |                                  | hardware reports bound to    |
      |                                  | the anchor (Section 5)       |
      |<------------- Evidence envelope (Section 4) --------------------|
      |                                                                 |
      |---- Evidence, nonce, presented certificate (if any), Policy --->|
      |                                                                 | Section 11, with
      |                                                                 | collateral (Section 10)
      |                                                                 | and reference values
      |<------------- Appraisal (Section 12) or refusal (Section 14.4) -|
```

In the challenge pattern the relying party gives the verifier the nonce it issued. In the certificate pattern it gives the verifier the nonce the evidence carries, since the attester chose it, together with the digest of the certificate it was presented (Section 5.5). In the certificate pattern the verifier MUST NOT take that digest from the evidence.

A verifier that runs as a separate service returns the appraisal over an authenticated channel or signs it as an EAR token; the appraisal format itself carries no signature (Section 12.1).

### 3.3. What an appraisal establishes

The facts a relying party needs, and the claims that carry them:

| Question | Claim | Notes |
| --- | --- | --- |
| Which image launched (L0) | `cvm_launch_measurement` | signed by the TEE; matched against reference values |
| What ran after launch (L1) | `cvm_registers`, each with `backing` and `replayed` | only what measured producers recorded (Section 15.3) |
| Is the evidence fresh (L2) | `cvm_freshness` | the binding of Section 5 passed |
| Is the hardware genuine, and is its firmware acceptable | `hardware` in the trustworthiness vector, `cvm_tcb`, `cvm_collateral` | chain to the vendor root; TCB against named floors |
| Is guest debug off, and are the other security settings acceptable | `cvm_policy`, `dbgstat`, `configuration` in the vector | debug is refused by default |
| Which machine is this | `cvm_identity`, `instance-identity` in the vector | authenticated by the hardware chain |
| Which host-set labels were present | `cvm_host_data` | a label, Section 3.5 |
| Did every attester answer this challenge | `ear_all_submods_bound` | same nonce; it does not prove co-location (Section 15.6) |

A relying party that needs a single decision uses this rule: the appraisal is acceptable when `ear_all_submods_bound` is `"true"`, the `cpu` submodule and every device submodule have `ear_status` `affirming` (or `warning`, where the relying party accepts the vendor-reported vulnerabilities its policy admitted), the `vtpm` submodule, when present, has `affirming` or `none` (the latter when the policy pins no PCR), and the policy identifier in `ear_appraisal_policy_ids` is one the relying party recognizes. A `contraindicated` submodule, which debug produces, is never acceptable under this rule. The profile defines no separate boolean because a boolean detached from the policy that produced it does not say which requirements were met: a genuine report can still describe an image or a firmware version the relying party does not accept.

### 3.4. Trust boundary inside the evidence

The envelope is unprotected (Section 4.1). Every field is one of:

- signed: bytes covered by a hardware or vendor signature: the SNP report, the TD quote, the HCL report's hardware report, the TPM quote, the CCA tokens, the NRAS tokens;
- bound: fields the verifier checks against signed bytes before use: registers against the report, the quote or the commitment; the log against the registers; the nonce against its binding; endorsements against pinned roots;
- hint: every other field. A hint selects a parser, and `hosting` also selects which report types and binding modes are admitted (Section 4.3); a hint never raises what a verifier concludes, because every admitted combination is verified in full.

`cvm_platform` is a hint. The verifier MUST re-derive the vendor, the TEE and the generation from signed data (Section 9) and MUST refuse evidence whose hint contradicts them. `hosting` cannot be derived from signed data, so every path it admits is verified in full on its own terms: in particular `azure` admits `vtpm-extradata`, whose freshness rests on the paravisor, and a verifier therefore refuses that mode unless the policy pins the launch measurement that establishes the paravisor (Section 9.4.4). A verifier that reads `cvm_registers[].value` without binding it has a fail-open defect by definition.

### 3.5. Host-set fields

Each TEE lets the host place a value in the signed report at launch that the launch measurement does not cover: SNP `HOST_DATA` (32 bytes), TDX `MRCONFIGID` (48 bytes), CCA Realm Personalization Value (RPV, 64 bytes). The host can choose a different value on every launch, so on its own such a field is a label, and the profile reports it as `cvm_host_data` with explicit semantics.

A host-set field becomes a guarantee when the measured image contains code that enforces a relationship with it: for example, a guest that refuses to start unless `HOST_DATA` equals the digest of the configuration it loads. Only then does pinning it (`reference.host_data`, Section 13.4) establish something about the workload, and the guarantee rests on the launch measurement pin that establishes the enforcing code.

## 4. Evidence

### 4.1. Envelope

Evidence is an EAT claims set (RFC 9711) under the profile `tag:confidential.ai,2026:cvm#1`, carried unprotected: as a UJCS in JSON and as a UCCS (CBOR tag 601) in CBOR (RFC 9781). On the wire it is labeled with the media types of RFC 9782:

```
application/eat-ucs+json; eat_profile="tag:confidential.ai,2026:cvm#1"
application/eat-ucs+cbor; eat_profile="tag:confidential.ai,2026:cvm#1"
```

The envelope carries no signature of its own. Every byte a verifier relies on is signed by the TEE, a vendor service or the vTPM, or is bound by the verifier to such bytes (Section 3.4). A signature by a key inside the guest would add nothing a verifier could rely on beyond what those signatures already establish. RFC 9781 sections 3 and 7 require a use of unprotected claims sets to state its security argument and the roles of the endpoints; this section and Section 3 are that statement.

Top-level claims:

| Claim | CBOR key | Requirement | Value |
| --- | --- | --- | --- |
| `eat_profile` | 265 | MUST | `tag:confidential.ai,2026:cvm#1` |
| `eat_nonce` | 10 | MUST | the relying party's nonce, a byte string of 16 to 64 bytes |
| `cvm_version` | -70000 | MUST | the integer 1 |
| `submods` | 266 | MUST | the submodules of Section 4.2 |

A verifier MUST refuse an envelope with another `eat_profile` or another `cvm_version`, and MUST refuse an envelope whose `eat_nonce` differs from the nonce the relying party supplied to it. Other top-level claims are ignored, whatever they hold.

### 4.2. Submodules

`submods` maps names to attester claims sets. Names are drawn from these forms and no other:

| Name | Count | Contents |
| --- | --- | --- |
| `cpu` | exactly one | the CPU TEE's claims (Section 4.3), or for Arm CCA the nested token (Section 4.6) |
| `vtpm` | present exactly when the `cpu` submodule's binding mode is `vtpm-extradata` | the vTPM's claims (Section 4.4) |
| `gpu/<ueid>` | zero or more | one NVIDIA GPU (Section 4.5) |
| `nvswitch/<ueid>` | zero or more | one NVIDIA NVSwitch (Section 4.5) |

`<ueid>` is the device's identifier as the NVIDIA SDK reports it: 1 to 128 printable ASCII characters (0x21 to 0x7E) excluding `/`. An envelope carries at most 66 submodules, of which at most 32 are device submodules (a verifier refuses more with `device-not-allowed`). A verifier MUST refuse an envelope with an unknown name, without a `cpu` submodule, with a `vtpm` submodule whose `cpu` does not bind through it, or with a `cpu` bound through `vtpm-extradata` and no `vtpm`.

### 4.3. The `cpu` submodule

| Claim | CBOR key | Requirement | Class | Value |
| --- | --- | --- | --- | --- |
| `cvm_platform` | -70001 | MUST | hint | `{vendor, tee, generation?, hosting}` |
| `cvm_report` | -70002 | MUST | signed | a CMW record carrying the raw hardware report |
| `cvm_binding` | -70003 | MUST | bound | `{pattern, mode, key?}` (Section 5) |
| `cvm_endorsements` | -70004 | MAY | bound | a CMW collection of collateral (Section 10) |
| `cvm_registers` | -70005 | MUST in `commitment` mode and whenever `cvm_log` is present; MAY on TDX; absent on SEV-SNP in the other modes | bound | the register array (Section 6) |
| `cvm_log` | -70006 | in `commitment` mode REQUIRED by appraisal (refused with `log-required` when absent); MAY on TDX; absent on SEV-SNP in the other modes | bound | `{format, data}` (Section 7) |
| `cvm_chain` | -70007 | MUST when the mode is `commitment`, absent otherwise | bound | `{chain_len}` with `chain_len` at least 1 (Section 8) |
| `bootseed` | 268 | MUST when the mode is `commitment`, absent otherwise | bound | 32 bytes (Section 8.2) |
| `dbgstat` | 263 | MAY | hint | RFC 9711 section 4.2.9 debug status |
| `cvm_provenance` | -70008 | MAY | reserved | ignored by version 1 verifiers |

`cvm_platform` members:

- `vendor`: `amd`, `intel` or `arm`, and MUST be the vendor of `tee`;
- `tee`: `sev-snp`, `tdx` or `cca`;
- `generation`: OPTIONAL. On `sev-snp` one of `Milan`, `Genoa`, `Turin`; on `tdx` the FMSPC as twelve lowercase hexadecimal digits. When present it MUST equal the generation the verifier derives from signed data (Section 9);
- `hosting`: `bare`, `azure`, `gcp` or `dstack`.

`cvm_report` is a CMW record (RFC 9999 section 3.1) `[type, value, indicator]`. `value` is the report bytes exactly as the TEE produced them. The indicator is REQUIRED and MUST be exactly 4 (bit 2, evidence). `type` is one of:

| Media type | Content | Accepted for |
| --- | --- | --- |
| `application/vnd.confidential-ai.sev-snp-report` | an SNP `ATTESTATION_REPORT`, 1184 bytes (Section 9.1) | `sev-snp` |
| `application/vnd.confidential-ai.tdx-quote` | a TD quote, version 4 or 5 (Section 9.2) | `tdx` |
| `application/vnd.veraison.tsm-report+json` | the Linux configfs-tsm report as JSON, whose `outblob` is one of the two above; accepted on ingest and never emitted | `sev-snp` and `tdx` with hosting `bare` or `gcp` |

`dbgstat`, when present, is the RFC 9711 text value in JSON (`enabled`, `disabled`, `disabled-since-boot`, `disabled-permanently`, `disabled-fully-and-permanently`) and the integer 0 to 4 in CBOR. A verifier derives the debug state from the signed report and MUST refuse a hint that disagrees with it on whether debug is enabled; the qualifier among the disabled values is the attester's.

The combinations a `cpu` submodule may take are fixed by the TEE and the hosting:

| TEE and hosting | Report types | Binding modes | Registers and log |
| --- | --- | --- | --- |
| `sev-snp`, `bare` or `gcp` | SNP report, tsm-report | `report-data`, `commitment` | only in `commitment` mode: all 16 `snp-vmr` slots, a log, `cvm_chain`, `bootseed` |
| `sev-snp`, `dstack` | SNP report | `report-data`, `commitment` | as above |
| `sev-snp`, `azure` | SNP report | `vtpm-extradata` | none on the `cpu` submodule; the vTPM carries them |
| `tdx`, `bare` or `gcp` | TD quote, tsm-report | `report-data` | OPTIONAL `tdx-rtmr` registers (each RTMR at most once) and a log |
| `tdx`, `dstack` | TD quote | `report-data` | as above |
| `tdx`, `azure` | TD quote | `vtpm-extradata` | as above |
| `cca`, `bare` | nested token (Section 4.6) | `cca-challenge` | carried in the realm token |

### 4.4. The `vtpm` submodule

| Claim | CBOR key | Requirement | Class | Value |
| --- | --- | --- | --- | --- |
| `cvm_tpm_quote` | -70010 | MUST | signed | `{message, signature, pcrs, bank}` |
| `cvm_tpm_ak` | -70011 | MUST | bound | `{method, data}` |
| `cvm_registers` | -70005 | MUST | bound | 1 to 24 registers of source `vtpm-pcr` |
| `cvm_log` | -70006 | MAY | bound | the vTPM's event log (Section 7) |

`cvm_tpm_quote.message` is the marshaled `TPMS_ATTEST` structure the TPM signed, `signature` the signature value over it (for the RSA attestation key of Section 9.4, the RSASSA-PKCS1-v1_5 signature bytes of the `TPMS_SIGNATURE_RSA`), `pcrs` the 24 PCR values of the quoted bank in PCR order, and `bank` the bank's TPM algorithm name (`sha256`, `sha384` or `sha512`, Section 6.1). `cvm_tpm_ak.method` is `hcl-report` and `data` is the Azure HCL report that carries the attestation key and binds it to the hardware report (Section 9.4).

Each register's `alg` MUST be the quoted bank, its `index` a PCR inside the quote's signed selection, its `value` equal to the entry of `pcrs` at that index, its `source` `vtpm-pcr` and its `backing` `privileged-service`. Each index appears at most once.

### 4.5. Device submodules

A `gpu/<ueid>` or `nvswitch/<ueid>` submodule carries the device evidence exactly as NVIDIA's SDK exchanges it with NRAS:

| Member | Requirement | Value |
| --- | --- | --- |
| `arch` | MUST | `HOPPER` or `BLACKWELL` under `gpu/`; `LS10` under `nvswitch/` |
| `uuid` | MUST | equal to the name's `<ueid>` |
| `evidence_b64` | MUST | NVIDIA's standard-alphabet base64 text, 1 byte to 1 MiB, passed to NRAS verbatim |
| `cert_chain_b64` | MUST | NVIDIA's standard-alphabet base64 text, 1 byte to 1 MiB, passed to NRAS verbatim |
| `cvm_binding` | MUST | `{"pattern": "challenge", "mode": "nras-nonce"}` |

The two base64 members keep NVIDIA's encoding because NRAS consumes them as text; they are the only byte-carrying members of the profile that do not follow Section 4.7. The attester obtains them from the device with the SPDM nonce of Section 5.4 (`nras-nonce`). A device submodule's binding names the challenge pattern because the device protocol always takes a nonce; the nonce is the envelope's, so under a `cpu` submodule in the certificate pattern the device evidence is as old as the certificate. Other members of a device submodule are ignored.

### 4.6. Nested Arm CCA token

For Arm CCA the `cpu` submodule is a nested token (RFC 9711 section 4.2.18.3): the CCA attestation token bytes exactly as the RMM returned them. In JSON it is the array `["CBOR", <token as base64url>]`; in CBOR it is the byte string. No `cvm_report` wrapper is used because the token is already an EAT, and the realm token's challenge carries the binding (Section 9.6).

### 4.7. Encoding rules

JSON (the primary encoding):

- Claim names are text; profile claims carry the `cvm_` prefix.
- Byte strings are base64url (RFC 4648 section 5) without padding and with zero trailing bits (RFC 4648 section 3.5), which is the strict `.b64u` of RFC 9741. A verifier MUST refuse the standard alphabet, padding and non-zero trailing bits.
- Integers are JSON numbers. No profile claim holds a floating-point value. Integers are written without a fraction or an exponent (`1`, never `1.0` or `1e0`), are at most 2^64 - 1, and are exact: an implementation parses the 64-bit members (`chain_len`, `seq`, `recnum`) without loss.
- Each value has exactly one encoding. An object with a duplicate member name is refused, in the envelope, in every `cvm_*` object and in every CMW collection. `null` is not a value: an optional member is absent or holds its type. An object is written as an object, never as the array of its members, and an enumerated value is its text, never an object naming it. An implementation whose JSON library admits any of these (keeping the last duplicate, reading `null` as absent, reading a struct from an array) MUST refuse them itself.
- Unknown claims at the top level and in a submodule claims set, device submodules included, are ignored whatever they hold, as EAT extensibility requires. An unknown member inside any `cvm_*` object is refused.
- A CMW record's indicator, where this document does not fix it, is 1 to 31 (RFC 9999 section 3.1).

Bounds. A verifier parses untrusted input without buffering it whole and within these bounds, and refuses input that exceeds them: at most 66 submodules; a CMW collection has at most 32 entries and one level of nesting; every byte string field is at most 1 MiB (1048576 bytes) after decoding; the whole envelope is at most 10 MiB (10485760 bytes).

CBOR: claim keys are the integers of Appendix A; names inside profile objects stay text; byte strings are byte strings; every map and string has a definite length; every object the attester produces uses deterministic encoding (RFC 8949 section 4.2.1).

### 4.8. EAT profile checklist

RFC 9711 section 6.3 lists the decisions a profile makes. For this profile:

| Item | Decision |
| --- | --- |
| 6.3.1 JSON, CBOR or both | both; JSON is primary; CBOR uses the keys of Appendix A |
| 6.3.2 map and array encoding | definite lengths only |
| 6.3.3 string encoding | definite lengths only |
| 6.3.4 preferred serialization | deterministic encoding (RFC 8949 section 4.2.1) for every CBOR object the attester produces |
| 6.3.5 CBOR tags | UCCS tag 601 when a CBOR envelope is written; no tags inside JSON |
| 6.3.6 COSE/JOSE protection | none at the envelope; Section 4.1 states the argument |
| 6.3.7 COSE/JOSE algorithms | inherited from each hardware report; the profile adds SHA-384 for registers, the anchor and the commitment, and SHA-256 for the vTPM key binding and the NRAS nonce |
| 6.3.8 detached EAT bundle support | not used in version 1 |
| 6.3.9 key identification | per submodule: VCEK or VLEK for SNP; the PCK chain for TDX; the HCL attestation key for the vTPM; the CCA platform and realm attestation keys; the NRAS key identifier (`kid`) |
| 6.3.10 endorsement identification | inline in `cvm_endorsements` or fetched by the verifier, anchored to pinned roots either way (Section 10) |
| 6.3.11 freshness | `eat_nonce` at the top, bound per submodule in a declared mode (Section 5) |
| 6.3.12 claims requirements | Sections 4.1 to 4.6 |

## 5. Freshness and binding

### 5.1. Patterns

`cvm_binding.pattern` names how the nonce was chosen:

- `challenge`: the relying party chose `eat_nonce` for this exchange. This is the pattern for every exchange with a live peer.
- `certificate`: the evidence is bound to an X.509 certificate that lives for the CVM's lifetime, as in attested TLS. The attester chose `eat_nonce` when it created the certificate, and binds the certificate through a key of kind `x509-tbs-sha256` (Section 5.3). The evidence is as fresh as the certificate: the relying party MUST check the certificate's validity window and bound its age. A version 1 verifier receives the certificate's digest (Section 5.5), and so does not report `not_before` and `not_after`; the members are defined for verifiers that receive the certificate itself.

`eat_nonce` is REQUIRED in both patterns and is at least 16 bytes. A binding without a nonce is not defined by this profile.

### 5.2. Anchor

The anchor is the value an attester binds. The verifier derives it from the nonce the relying party supplied and the key binding (Section 5.3):

```
without a key:  anchor = nonce
with a key:     anchor = SHA-384("ats-anchor-v1"
                                 || u8(len(nonce)) || nonce
                                 || u8(len(kind))  || kind
                                 || u16be(len(value)) || value)
```

`kind` is the key kind's ASCII name and `value` the key value of Section 5.3. When the policy names a key (`freshness.key`, Section 13.1), the evidence's `cvm_binding.key` MUST equal it, and the verifier refuses with `binding-mismatch` otherwise. When the policy names none, the verifier uses the evidence's key, if any, and reports it in `cvm_freshness.key`; a relying party that relies on that binding MUST compare the reported key with the key of its own channel. The certificate pattern requires the policy to name the key (Section 5.5). Vectors are in Appendix B.1.

### 5.3. Key kinds

`cvm_binding.key` is `{kind, value}`:

| Kind | Value | Pattern |
| --- | --- | --- |
| `spki-sha256` | the 32-byte SHA-256 of the DER `SubjectPublicKeyInfo` of the key being bound | `challenge` |
| `raw` | an opaque byte string the relying party chose, 0 to 65535 bytes | `challenge` |
| `x509-tbs-sha256` | the 32-byte SHA-256 of the DER `TBSCertificate` of the certificate being bound, which covers its public key, validity, subject and subject alternative names | `certificate` |
| `tls-exporter` | reserved for version 2: the 32-byte TLS exporter value (RFC 9266, label `EXPORTER-Channel-Binding`, empty context) | none; a version 1 verifier MUST refuse it |

A `challenge` binding carries no key or an `spki-sha256` or `raw` key. A `certificate` binding carries exactly an `x509-tbs-sha256` key.

### 5.4. Binding modes

`cvm_binding.mode` declares where the anchor is bound. The verifier computes the expected value and compares it with the signed field in constant time over the whole field; a mismatch is refused with `binding-mismatch`. The one exception is the device nonce match that NRAS reports (Section 9.7.3), which a policy may tolerate and which the appraisal then reports through `ear_all_submods_bound` `"false"`.

| Mode | Attesters | Rule |
| --- | --- | --- |
| `report-data` | SEV-SNP without a register provider, TDX, dstack | the report's 64-byte report data equals `pad64(anchor)` |
| `commitment` | SEV-SNP with a register provider | the report data equals `header16 \|\| C` of Section 8.1, with `caller_data = pad64(anchor)` |
| `vtpm-extradata` | Azure SEV-SNP and TDX | the TPM quote's `extraData` equals `anchor`, and the hardware report binds the quote's key (Section 9.4) |
| `cca-challenge` | Arm CCA | the realm token's challenge equals `pad64(anchor)` |
| `nras-nonce` | NVIDIA GPUs and NVSwitch | the device's SPDM nonce equals `SHA-256(nonce \|\| "NVIDIA-GPU-EAT-v1")` for a GPU and `SHA-256(nonce \|\| "NVIDIA-SWITCH-EAT-v1")` for an NVSwitch |

`extraData` is a `TPM2B_DATA`, which holds at most `sizeof(TPMT_HA)` bytes: 50 on a vTPM whose largest digest is SHA-384. An unkeyed nonce bound in `vtpm-extradata` mode is therefore 16 to 50 bytes, and a keyed anchor (48 bytes) always fits. The `nras-nonce` rule binds the nonce itself and ignores the key, because NRAS derives the device challenge from a nonce it is given. Device evidence therefore carries no key binding; it answers the same nonce as the `cpu` submodule, which is all `ear_all_submods_bound` states (Section 15.6).

The mode is constrained by the platform (Section 4.3): a verifier MUST refuse a mode that the TEE and hosting do not admit.

### 5.5. Certificate carriage

When evidence rides in an X.509 certificate, it is carried in the `id-pe-cmw` extension (RFC 9999 section 4.4, OID 1.3.6.1.5.5.7.1.35) as a CMW record whose type is `application/eat-ucs+json; eat_profile="tag:confidential.ai,2026:cvm#1"` and whose value is the envelope. The `x509-tbs-sha256` value is the SHA-256 of the certificate's DER `TBSCertificate` with every `id-pe-cmw` extension removed, since the extension cannot cover its own digest: the remaining extensions keep their order and encoding, the `Extensions` SEQUENCE and the `[3]` field that holds it are re-encoded with DER lengths, and the `[3]` field is omitted when no extension remains. For a certificate without the extension the value is the SHA-256 of its `TBSCertificate`. The relying party computes this value from the certificate it was presented and supplies it as `freshness.key`; without it the verifier MUST refuse the `certificate` pattern with `binding-mismatch`.

The dstack attested-TLS certificate extensions (private arc `1.3.6.1.4.1.62397.1`) are outside this profile.

## 6. Measurement registers

### 6.1. Register entries

`cvm_registers` is an array of entries:

| Member | Value |
| --- | --- |
| `index` | the slot, an integer 0 to 65535, interpreted within `source` (Section 6.2) |
| `alg` | the TPM 2.0 algorithm name: `sha256` (TPM_ALG_SHA256, 0x000B), `sha384` (TPM_ALG_SHA384, 0x000C) or `sha512` (TPM_ALG_SHA512, 0x000D) |
| `value` | the register value, exactly the digest length of `alg` |
| `source` | `tdx-rtmr`, `snp-vmr`, `vtpm-pcr` or `cca-rem` |
| `backing` | `hardware`, `privileged-service`, `kernel-service` or `virtualized` (Section 6.4) |

Each `(source, index)` appears at most once. `alg` is pinned per source: `sha384` for `tdx-rtmr` and `snp-vmr`; the quoted bank for `vtpm-pcr`; the realm hash algorithm (`sha256`, `sha384` or `sha512`) for `cca-rem`. The array is REQUIRED whenever `cvm_log` is present, so that a verifier without support for a log format can still pin register values.

### 6.2. Sources and index spaces

| Source | Index | Width | Held by |
| --- | --- | --- | --- |
| `tdx-rtmr` | RTMR ordinal 0 to 3 | 48 | the TDX module |
| `cca-rem` | REM ordinal 0 to 3 | 32, 48 or 64 | the RMM |
| `vtpm-pcr` | PCR number 0 to 23 | per bank | the paravisor's vTPM |
| `snp-vmr` | slot 0 to 15 | 48 | the register provider (Section 8) |

The launch measurement has its own claim, `cvm_launch_measurement`, and no register index denotes it.

Two conventions in use are offset by one and are converted on ingest: the UEFI `CC_EVENT` `MrIndex` (0 is MRTD, 1 to 4 are RTMR 0 to 3), so CCEL records map `MrIndex - 1` to the RTMR ordinal; and measurement files that list MRTD at index 0 and RTMR 0 to 3 at indexes 1 to 4. The TCG CEL `pcr` field carries this profile's index.

### 6.3. Slot semantics

Slots 0 to 3 carry the same meaning on every platform that has them, following the TDX RTMR assignment and the TCG PC Client firmware profile:

| Slot | Contents | PC Client analog |
| --- | --- | --- |
| 0 | firmware configuration | PCR 1 and 7 |
| 1 | what the firmware loads: boot loader, partition table | PCR 2 to 6 |
| 2 | kernel, command line, initial RAM disk and OS-loaded components | PCR 8 to 15 |
| 3 | runtime | none |
| 4 to 15 | workload slots, where the source has them; allocated at first use (Section 8.3) | none |

`vtpm-pcr` entries keep their PCR numbers and are distinguished by `source`: RTMR 3, PCR 3 and SNP slot 3 are different registers.

### 6.4. Backing

`backing` states what prevents code inside the CVM from rewriting a register. The levels, from strongest to weakest:

| Backing | Definition | Examples |
| --- | --- | --- |
| `hardware` | the TEE hardware or its firmware holds the register and reports its value inside the signed report | TDX RTMRs, CCA REMs |
| `privileged-service` | a component at a hardware-enforced privilege level above the guest operating system holds the register, and its code is covered by the launch measurement | a vTPM in the Azure paravisor; an SVSM at VMPL0 |
| `kernel-service` | the measured guest kernel holds the register, and the kernel restriction set of Section 8.6 keeps every user, root included, from rewriting it; a kernel compromise defeats it | the SNP register provider of Section 8 |
| `virtualized` | software without an enforced boundary against the most privileged user of the guest, or any register whose protection the verifier cannot establish | a userspace register service |

In evidence, `backing` is a hint constrained by `source`: `hardware` for `tdx-rtmr` and `cca-rem`; `privileged-service` for `vtpm-pcr`; never `hardware` for `snp-vmr`. A verifier MUST refuse evidence that violates these constraints.

In results, `backing` is what the verifier established. It MUST NOT be higher than the evidence claimed, and for `snp-vmr` it is the level Section 8.7 assigns. The policy sets a minimum (`min_backing`, Section 13.1) and the verifier reports the weakest backing it saw (`cvm_backing_min`, Section 12.3), so a downgrade from `hardware` to a software level fails visibly.

### 6.5. Authoritative values

The verifier never trusts `value` from the envelope:

- `tdx-rtmr`: the authoritative values are the RTMRs in the signed TD quote, and every envelope entry MUST equal them.
- `cca-rem`: the authoritative values are the REMs in the signed realm token, and every envelope entry MUST equal them.
- `vtpm-pcr`: the quote's signed PCR digest MUST reproduce from the 24 values of `cvm_tpm_quote.pcrs` over the signed selection, and every register MUST equal the value of its PCR.
- `snp-vmr`: the commitment in the signed report data MUST reproduce from the 16 register values (Section 8.1). `snp-vmr` registers therefore appear only with the `commitment` mode, and a verifier MUST refuse them in any other mode.

When a log is present it MUST also replay to these values (Section 7.4).

## 7. Event logs

### 7.1. Formats

`cvm_log` is `{format, data}`, `data` a byte string of at most 1 MiB. A log parses whole under its format's rules or the verifier refuses it with `log-invalid`; a verifier never uses the parsable prefix of a truncated log. The formats a submodule admits: on TDX, `tcg-cel-cbor`, `tcg-cel-json`, `tdx-ccel`, `dstack-json` and `aael` (refused, below); on SEV-SNP in `commitment` mode, `tcg-cel-cbor` and `tcg-cel-json`, where another format is refused with `log-required`; on the `vtpm` submodule, `tpm2-event-log`. A verifier refuses another format with `unsupported`. Hexadecimal in `tcg-cel-json` and `dstack-json` is lowercase when produced and case-insensitive when parsed.

| Format | Content |
| --- | --- |
| `tcg-cel-cbor` | TCG Canonical Event Log v1.1 records in deterministic CBOR: `data` is the CEL CDDL's `tcg-canonical-event-log`, one array of records, each the map `{0: recnum, 1: pcr, 3: digests, 9: content_type, 10: content}`. `recnum` counts each index's records from 0 (CEL section 4.2.2) and `pcr` carries this profile's index. This is the format producers SHOULD emit. |
| `tcg-cel-json` | the same records in CEL-JSON, a JSON array of `{recnum, pcr, digests: [{hashAlg, digest}], content_type, content}` with byte strings in hexadecimal; for inspection |
| `tdx-ccel` | the ACPI CCEL table's log as the guest exposes it, in the TCG2 binary format; `MrIndex` 1 to 4 become RTMR 0 to 3. The Confidential Containers attestation agent appends its entries to it as `EV_EVENT_TAG` records whose tagged event ID is 0x4141454C around the text `domain operation content`, with the digest of the whole tagged event and `MrIndex` 4 (RTMR 3) by default |
| `tpm2-event-log` | the vTPM's TCG2 binary log (PC Client PFP section 10) |
| `dstack-json` | dstack's event log, a JSON array of `{imr, event_type, digest, event, event_payload, version?, preimage?}` with `imr` the RTMR ordinal (Section 9.3) |
| `aael` | the Confidential Containers attestation agent's standalone log, used where the platform has no CCEL: a fixed 73-byte header followed by the records described for `tdx-ccel`. Version 1 verifiers MUST refuse it with `unsupported` |

### 7.2. Normalization to CEL

Every format becomes CEL records before replay. A TCG2 event becomes a `pcclient_std` record carrying all its digests; the TCG2 Spec ID header becomes an unmeasured record. A dstack runtime event becomes a `pcclient_std` record whose event data is the input of its digest, so the record verifies on its own. An attestation-agent entry keeps the tagged event as its event data.

A record's event type and tagged-event ID lie outside its digest, so a relabeled record still replays. A verifier therefore lists the entries or runtime events of a register only when every measured record in that register is one whose digest reproduces from its content.

### 7.3. The `cvm` content type

Runtime events recorded by measured producers under this profile use the CEL content type `cvm`, value 200:

```
$TPMS_CEL_EVENT-extension /= TPMS_CEL_EVENT<CVM, CVM_CONTENT>
CVM = JC<"cvm", 200>
CVM_CONTENT = { seq => uint, event => BYTEBUFFER }
seq = JC<"seq", 0>
event = JC<"event", 1>
```

A `cvm` record is:

- `recnum`: the record's number within its slot, from 0;
- `pcr`: the slot index;
- `digests`: exactly one entry, `hashAlg` 12 (TPM_ALG_SHA384) and `digest` `d`;
- `content_type`: 200;
- `content`: the map `{0: seq, 1: event}`, where `seq` is the record's position among the log's `cvm` records, from 0, and `event` is a byte string.

`event` is the deterministic CBOR encoding (RFC 8949 section 4.2.1) of the map `{0: domain (tstr), 1: operation (tstr), 2: content_digest (bstr), 3: content (bstr, OPTIONAL)}`, with `domain` and `operation` each 1 to 255 bytes of UTF-8. `content_digest` is 48 bytes. A verifier refuses with `replay-mismatch` an `event` that is not deterministically encoded, carries a duplicate or unknown key, or has trailing bytes, because such bytes do not authenticate one reading. The meaning of `content_digest` belongs to the producer, except in the records of Section 8.2 and 8.3, where it is fixed. The digest extended into the register is:

```
d = SHA-384("ats-mr-v1/record" || u64le(seq) || u16le(pcr) || event)
```

In CEL-CBOR a record is `{0: recnum, 1: slot, 3: [{0: 12, 1: d}], 9: 200, 10: {0: seq, 1: event}}`, with `event` stored as the exact bytes that were hashed; in CEL-JSON it is `{"recnum", "pcr", "digests", "content_type": "cvm", "content": {"seq", "event": hex}}`. The order across registers lives in the content because CEL keeps `recnum` per index (CEL section 4.2.2) and requires a record to carry what its digest covers (CEL section 4.2.1.2), and leaves how a digest derives from content to the content type (CEL section 4.2.5).

CEL v1.1 Table 2 assigns content types 4 to 10 and defines no private range. The value 200 is taken through the `$TPMS_CEL_EVENT-extension` socket that the CEL CDDL provides; Section 17.4 records the registration request. Vectors are in Appendix B.3.

### 7.4. Replay

The verifier replays every register a log covers, from that register's starting value, and marks each register `replayed: true` or `replayed: false` in the result:

- A register the log extends is replayed when its records, extended in order from the starting value, reproduce the authoritative value of Section 6.5. For `tcg-cel-cbor`, `tcg-cel-json`, `dstack-json` and `tpm2-event-log`, every register the log extends MUST reproduce, and one that does not is refused with `replay-mismatch`. For `tdx-ccel`, RTMR 0 to 2 MUST reproduce, and RTMR 3 is reported with `replayed` false when it does not, because agents that extend RTMR 3 after boot do not all append to the CCEL.
- A register the log never extends is replayed exactly when it still holds its starting value, since the log then accounts for every extend into it.
- Starting values: zero for an RTMR and a REM; for a PCR the PC Client starting value (PCRs 17 to 22 all ones; PCR 0 at the locality of a `StartupLocality` event, otherwise zero; every other PCR zero); for an `snp-vmr` slot its genesis value (Section 8.1).
- `EV_NO_ACTION` records are skipped. A `tpm2-event-log` is replayed in the quoted bank; version 1 verifiers require SHA-256 for it and refuse other banks with `unsupported`. A register never extended keeps `replayed` false when no log is present.
- A `cvm` record is replayed by requiring `seq` to count the log's `cvm` records from 0 without a gap and `recnum` to count its slot's records from 0 without a gap, recomputing `d` from `seq`, the record's index and the stored `event` bytes, requiring it to equal the recorded digest, and extending it. A record that breaks any of these is refused with `replay-mismatch`. The verifier never re-encodes content.
- dstack runtime events are replayed with the digest rules of Section 9.3, from zero, as `R = SHA-384(R || digest)`.

`replay_until_event`, under which the verified value would be the replay up to and including a named record, and a policy naming the slots that must replay, are not defined in version 1.

On an SNP `cpu` submodule in `commitment` mode the log is REQUIRED (refused with `log-required` when absent), every record MUST have content type `cvm`, `chain_len` MUST equal the number of records (refused with `log-required` otherwise), and Section 8 governs the replay from genesis.

## 8. Software registers on SEV-SNP

SEV-SNP provides a launch measurement and 64 bytes of report data that the requester chooses, and no runtime registers. This section defines `ats-mr-v1`: registers held by a register provider in the measured guest, committed into the report data of every report the guest can obtain, so that a verifier can replay a log against registers the hardware signature covers.

The construction does not make the registers hardware registers. Its guarantee rests on three facts the verifier establishes together: the launch measurement pins the exact image, and with it the provider; that image admits no path to a signed report other than through the provider (Section 8.5); and the provider always commits its true register state (Section 8.4). Section 8.7 states the backing a verifier reports.

### 8.1. Construction

```
seed:        seed = SHA-384("ats-mr-v1/seed")
genesis(i):  R[i] = SHA-384(zeros48 || "ats-mr-v1/genesis" || seed || u8(i))       for i in 0..15
extend:      R[i] = SHA-384(R[i] || d)                        d is the record digest of Section 7.3
commit:      C    = SHA-384("ats-mr-v1/commit" || R[0] || R[1] || ... || R[15]
                            || u64le(chain_len) || caller_data)
report_data: header16 || C                                    64 bytes exactly
```

- Every `R[i]` is 48 bytes; they are concatenated in index order.
- `seed` is a constant. Genesis values therefore need no firmware call and no report: a provider computes them at initialization and can accept its first extend before any report exists.
- `header16` is 16 bytes: `magic` = the 8 ASCII bytes `ATS-MR-1`; `version` = `u8(1)`; `alg` = `u8(1)`, meaning SHA-384; `reg_count` = `u8(16)`; `flags` = `u8(0)`, every bit reserved; `reserved` = 4 zero bytes. In hexadecimal: `4154532d4d522d31 01 01 10 00 00000000`. The verifier compares all 16 bytes with this value and refuses any difference, so no byte of the header is available for a caller to choose.
- `chain_len` counts every extension since genesis across all slots and is carried in `cvm_chain`.
- `caller_data` is 64 bytes the requester supplies, `pad64(anchor)` under this profile. It is not carried in the evidence; the verifier derives it from the nonce and the key (Section 5.2).

The verifier recomputes `C` from the registers established by replaying the log from genesis, `chain_len` and `pad64(anchor)`, and requires `header16 || C` to equal the report data. Vectors are in Appendix B.2.

### 8.2. Boot record

At initialization the provider draws `bootseed`, 32 bytes from the kernel's cryptographically secure random number generator, and extends into slot 3, as record 0 of the log (`seq` 0, `recnum` 0), a `cvm` event with `domain` `ats`, `operation` `boot`, `content_digest` `SHA-384(bootseed)` and no `content`. The seed itself travels in the `bootseed` claim, and the verifier checks the claim's digest against the record.

A valid chain therefore has `chain_len` at least 1 and the boot record at record 0 in slot 3. A verifier MUST refuse, with `replay-mismatch`, a `commitment` submodule that lacks either, and a log that carries a record with `domain` `ats` other than this boot record and the claim records of Section 8.3. A `bootseed` distinguishes the chains of one launch only for an honest kernel; Section 8.8 keys chain memory by the launch, which the kernel cannot choose.

### 8.3. Workload slots

Slots 4 to 15 are allocated at first use. The first record extended into a workload slot is its claim record: a `cvm` event with `domain` `ats`, `operation` `claim`, `content` the deterministic CBOR map `{0: owner (tstr), 1: purpose (tstr)}` with each string 1 to 255 bytes of UTF-8 (a verifier refuses content that is not deterministically encoded or carries another key, with `log-invalid`), and `content_digest` `SHA-384(content)`.

`owner` is the producer's identity as the provider authenticates it (Section 8.4). The provider refuses an extend into an unclaimed slot, a claim of a claimed slot, and an extend from any producer other than the slot's owner. A claim holds until the next boot. When all twelve workload slots are claimed, further claims are refused; a deployment with more than twelve producers groups them under shared owners, distinguished by `domain` and `operation`.

The verifier MUST refuse a log in which a workload slot that left genesis does not begin with a claim record, or in which a claim record appears anywhere else, reports `owner` and `purpose` for each workload slot, and applies `reference.slot_owners` (Section 13.4). Slots 0 to 3 take no claim record; which producers may extend them is the provider's to restrict and document (Section 8.4 item 6).

### 8.4. Register provider requirements

A register provider conforming to this profile:

1. Holds 16 registers of 48 bytes, initialized to their genesis values, in memory that guest userspace cannot write or read.
2. Implements extend as its only operation that changes a register. It implements no operation that sets, resets or truncates a register or the log.
3. Accepts from a producer a slot and the `event` bytes, and itself assigns `seq` from its global extension counter and `recnum` from the slot's counter, computes `d`, extends, and appends the record, all under one lock. A producer can supply neither counter nor a precomputed digest.
4. Stores the log in memory it controls, appends only, and exposes it read-only. When log storage is exhausted it refuses further extends; it never drops or overwrites a record.
5. Extends the boot record before it exposes any interface (Section 8.2).
6. Authenticates each producer's identity for slot claims and refuses extends as Section 8.3 states. The authentication mechanism is the provider's (for example, the Linux credentials or the cgroup of the calling process), and the provider documents it, because `owner` is only as meaningful as that mechanism.
7. Computes, for every report request, `C` over the register values and `chain_len` at that moment, under the same lock as extend, and places `header16 || C` in the request's report data. The caller supplies only `caller_data`, exactly 64 bytes, which the provider never interprets.
8. Returns with the report the register values, `chain_len` and the log prefix of exactly `chain_len` records captured under that lock, so the attester's evidence is consistent with the commitment.
9. Exposes register values read-only, for example through the Linux TSM measurement-register interface.

### 8.5. Report path exclusivity

The provider's commitment is worth something only if no software in the guest can obtain a signed report without it. On SEV-SNP a guest obtains a report by the guest request protocol, which requires all of:

- writing the GHCB MSR to start the protocol, an instruction that faults outside ring 0;
- encrypting the request with a VM platform communication key (VMPCK), which the firmware places in the SNP secrets page;
- a response only the AMD Secure Processor can produce, because the channel between the guest and the AMD Secure Processor is encrypted and integrity-protected with the VMPCK.

The host has one interface that produces a report for a running guest (`SNP_HV_REPORT_REQ`, ABI revision 1.56 and later). The firmware zero-fills that report's `REPORT_DATA` and sets its `VMPL` to 0xFFFFFFFF, so it binds no anchor, and a verifier refuses any report whose `VMPL` is above 3 (Section 9.1.5).

An image whose provider claims the guarantees of this section therefore MUST ensure that:

1. The only ring-0 code is the measured kernel and code the kernel verified against keys inside the measured image (Section 8.6).
2. The secrets page and every VMPCK are readable only by the kernel. A VMPCK disclosed to guest userspace can be handed to a colluding host, which can then obtain reports with report data of its choice; confidentiality of kernel memory is therefore as necessary as its integrity.
3. Every kernel path that produces a report request, including the character-device interface, the configfs-tsm interface and any extended-report variant, passes through the provider's computation of Section 8.4 item 7.
4. The kernel, its command line and its initial RAM disk are covered by the launch measurement (for example, by booting directly from a measured IGVM image), so no unmeasured boot configuration can alter items 1 to 3.

A verifier establishes these properties transitively: by pinning a launch measurement whose reference value provider publishes the build configuration that implements them.

### 8.6. Kernel restriction set

The table lists every interface through which guest root, or an unprivileged user who reaches root, obtains ring-0 execution or reads or writes kernel memory, with the configuration that removes it. Build configuration uses Linux Kconfig names. A provider that claims `kernel-service` backing (Section 8.7) MUST run in an image that satisfies every row marked MUST; rows marked SHOULD reduce the kernel attack surface that the residual risk of Section 15.4 depends on.

| Interface | Requirement | Build | Boot or runtime |
| --- | --- | --- | --- |
| loadable modules | MUST: no module loading, or loading only modules signed with a key generated for this build and discarded after it, whose public half is built into the measured kernel | `CONFIG_MODULES=n`, or `CONFIG_MODULE_SIG_FORCE=y` with an ephemeral `CONFIG_MODULE_SIG_KEY` | |
| kernel live patching | MUST be absent | `CONFIG_LIVEPATCH=n` | |
| kexec | MUST be absent | `CONFIG_KEXEC=n`, `CONFIG_KEXEC_FILE=n` | |
| physical and kernel memory devices | MUST be absent | `CONFIG_DEVMEM=n`, `CONFIG_DEVPORT=n`, `CONFIG_PROC_KCORE=n` | |
| kernel lockdown | MUST be forced to confidentiality mode from early boot; this also closes hibernation, MSR writes, I/O port access, PCI BAR access through sysfs, ACPI table override and custom methods, kprobes, and kernel memory reads through tracing, perf and BPF | `CONFIG_SECURITY_LOCKDOWN_LSM=y`, `CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`, `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y` | lockdown reads `confidentiality` before the first workload starts |
| BPF | MUST be absent | `CONFIG_BPF_SYSCALL=n` | |
| hibernation | MUST be absent | `CONFIG_HIBERNATION=n` | |
| kernel debuggers and dynamic probes | MUST be absent | `CONFIG_KGDB=n`, `CONFIG_KPROBES=n`, `CONFIG_DEBUG_FS=n` | |
| ACPI table upgrade | MUST be absent | `CONFIG_ACPI_TABLE_UPGRADE=n`, `CONFIG_ACPI_CUSTOM_METHOD=n` | |
| kernel command line and initial RAM disk | MUST be covered by the launch measurement | built into the measured image | |
| user namespaces | SHOULD be absent | `CONFIG_USER_NS=n` | |
| io_uring, userfaultfd, perf events | SHOULD be absent or restricted | `CONFIG_IO_URING=n`, `CONFIG_USERFAULTFD=n` | `kernel.perf_event_paranoid=3` |
| memory safety hardening | SHOULD be enabled | `CONFIG_KFENCE=y`, `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`, `CONFIG_INIT_ON_FREE_DEFAULT_ON=y`, `CONFIG_RANDOM_KMALLOC_CACHES=y`, `CONFIG_FORTIFY_SOURCE=y`, `CONFIG_LIST_HARDENED=y`, `CONFIG_BUG_ON_DATA_CORRUPTION=y` | |
| exploit attempts | SHOULD stop the node | | `kernel.panic_on_oops=1` |

Device DMA does not appear in the table: SEV-SNP's reverse map table keeps devices from writing private guest memory, and version 1 does not cover devices attested into the guest's trust boundary (Section 1.2). Drivers loaded as signed modules under the first row, such as a GPU driver, are ring-0 code and part of the attack surface; their versions are pinned by the launch measurement like the kernel's.

Each row is a property of the image, checked at build time and, for runtime rows, by the measured init before any workload runs. The reference value provider publishes the build configuration beside the launch measurement, and a relying party that pins the launch measurement pins the restriction set with it.

### 8.7. Backing assignment

A version 1 verifier reports every `snp-vmr` register with backing `virtualized`, whatever the evidence claims. Promotion requires a way for a reference value to state that an image satisfies Sections 8.4 to 8.6; a later revision of this profile defines it, and verifiers will then report `kernel-service` for such an image. A register provider implemented in an SVSM at VMPL0, with the same format, will be reported as `privileged-service` under the same mechanism.

Policies that accept SEV-SNP software registers under version 1 set `min_backing` to `virtualized` and pin the launch measurement.

### 8.8. Chain memory

The evidence cannot show on its own that a provider's history was rewritten after a kernel compromise. A verifier that keeps state MAY record, per `REPORT_ID` (the 32-byte identifier the AMD firmware generates at every launch and keeps for the guest's lifetime, report offset 0x140), the `bootseed`, the highest `chain_len` it appraised, and the register bank at that length. On a later appraisal with the same `REPORT_ID`, a different `bootseed` means the chain was restarted within one launch, and a log that is neither a prefix nor an extension of the recorded one is a fork: for a longer log, its first `n` records do not replay to the recorded bank at length `n`; for a shorter one, its bank differs from the recorded log's bank at its own length, which the verifier can check only when it recorded that bank. A shorter log that is a prefix is an earlier attestation appraised late. A verifier that detects a restart or a fork MUST refuse the appraisal with `replay-mismatch`. The ABI defines no guest reset short of a new launch; a deployment whose hypervisor reuses a guest context across a guest reboot sees that reboot reported as a restart. Chain memory is OPTIONAL in version 1 and a stateless verifier conforms.

## 9. Platform bindings

Each binding below specifies what the attester collects, how the verifier authenticates it and derives the platform from it, how the security settings normalize, where the anchor is bound, which registers and logs apply, which collateral is used, and where each normalized claim comes from. A verifier that does not implement a platform refuses its evidence with `platform-unsupported`.

### 9.1. AMD SEV-SNP

This binding covers SEV-SNP guests with hosting `bare`, `gcp` and `dstack`, with and without the register provider of Section 8, and supplies the hardware report for Azure SEV-SNP (Section 9.4).

#### 9.1.1. Evidence

The attester requests an attestation report through the guest kernel (the configfs-tsm report interface or the SEV guest device) with `REPORT_DATA` set to `pad64(anchor)`, or through the register provider in `commitment` mode (Section 8.4). It carries the report in `cvm_report` with type `application/vnd.confidential-ai.sev-snp-report`, and SHOULD carry the VEK the report names as `snp.vek` in `cvm_endorsements`, taken from the extended report's certificate table or from AMD KDS.

#### 9.1.2. Report layout

The `ATTESTATION_REPORT` (SNP-ABI) is exactly 1184 bytes; integers are little-endian. The fields this profile uses:

| Offset | Length | Field | Use |
| --- | --- | --- | --- |
| 0x000 | 4 | `VERSION` | 3 to 6; 2 only with hosting `azure` |
| 0x008 | 8 | `POLICY` | guest policy (Section 9.1.5) |
| 0x010 | 16 | `FAMILY_ID` | `cvm_owner.family_id` |
| 0x020 | 16 | `IMAGE_ID` | `cvm_owner.image_id` |
| 0x030 | 4 | `VMPL` | `cvm_policy.vmpl`; a value above 3 marks a report the host requested and is always refused |
| 0x034 | 4 | `SIGNATURE_ALGO` | MUST be 1 (ECDSA P-384 with SHA-384) |
| 0x038 | 8 | `CURRENT_TCB` | `cvm_tcb.current` |
| 0x040 | 8 | `PLATFORM_INFO` | bit 0 `SMT_EN`, bit 1 `TSME_EN` |
| 0x048 | 4 | key information | bit 0 `AUTHOR_KEY_EN`; bit 1 `MASK_CHIP_KEY`, MUST be 0; bits 4:2 `SIGNING_KEY`: 0 VCEK, 1 VLEK; every other value is refused in version 1 |
| 0x050 | 64 | `REPORT_DATA` | the binding (Section 9.1.6) |
| 0x090 | 48 | `MEASUREMENT` | `cvm_launch_measurement`, `alg` `sha384` |
| 0x0C0 | 32 | `HOST_DATA` | `cvm_host_data`, semantics `snp-host-data` |
| 0x0E0 | 48 | `ID_KEY_DIGEST` | `cvm_owner.id_key_digest`; `owner.id_key_digests` |
| 0x110 | 48 | `AUTHOR_KEY_DIGEST` | `cvm_owner.author_key_digest` |
| 0x180 | 8 | `REPORTED_TCB` | `cvm_tcb.reported`; VEK selection and cross-check |
| 0x188 | 1 | `CPUID_FAM_ID` | generation, versions 3 and later |
| 0x189 | 1 | `CPUID_MOD_ID` | generation, versions 3 and later |
| 0x1A0 | 64 | `CHIP_ID` | `cvm_identity.chip_id`; VCEK cross-check |
| 0x1E0 | 8 | `COMMITTED_TCB` | `cvm_tcb.committed` |
| 0x1F0 | 8 | `LAUNCH_TCB` | `cvm_tcb.launch` |
| 0x2A0 | 512 | `SIGNATURE` | `R` at 0x2A0 and `S` at 0x2E8, each 72 bytes |

Reserved fields that the ABI specification requires to be zero MUST be zero. Version 6 reports add extended TCB fields at 0x220, 0x240 and 0x260 for generations after Turin; a version 1 verifier does not interpret them for Milan, Genoa and Turin.

A TCB value (`TCB_VERSION`) is 8 bytes whose layout depends on the generation:

| Generation | Byte 0 | Byte 1 | Byte 2 | Byte 3 | Bytes 4 to 5 | Byte 6 | Byte 7 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Milan, Genoa | `BOOT_LOADER` | `TEE` | reserved | reserved | reserved | `SNP` | `MICROCODE` |
| Turin | `FMC` | `BOOT_LOADER` | `TEE` | `SNP` | reserved | reserved | `MICROCODE` |

#### 9.1.3. Generation

The generation is derived from signed data. For report versions 3 and later, from `CPUID_FAM_ID` and `CPUID_MOD_ID`:

| Family | Model | Generation |
| --- | --- | --- |
| 0x19 | 0x00 to 0x0F | Milan |
| 0x19 | 0x10 to 0x1F, and 0xA0 to 0xAF (Siena, which shares Genoa's roots) | Genoa |
| 0x1A | 0x00 to 0x1F | Turin |

A version 2 report carries no CPUID fields; the generation is the suffix (`-Milan`, `-Genoa`, `-Turin`) of the VEK issuer's common name, which Section 9.1.4 then authenticates through the generation's pinned root. Any other family or model is refused with `report-invalid`; this includes later generations, whose TCB layout this version does not define. The family and model ranges follow AMD's VCEK specification (publication 57230, section 1.5).

#### 9.1.4. Authentication

1. Roots. The verifier pins AMD's ARK, ASK and ASVK for each generation (Appendix E). An ARK is self-signed; the ARK signs the ASK and the ASVK; all three use RSA-4096 keys with RSASSA-PSS, SHA-384 and a 48-byte salt. ASK and ARK certificates supplied in the evidence are ignored.
2. Endorsement key. When `SIGNING_KEY` is 0 the report is signed by a VCEK, which the ASK signs; when it is 1, by a VLEK, which the ASVK signs. The VEK's issuer MUST agree with `SIGNING_KEY`. Every certificate in the chain MUST be inside its validity window at the evaluation time.
3. Report signature. The VEK's key is an ECDSA P-384 key. The signature covers bytes 0x000 to 0x29F of the report exactly as received. `R` and `S` are little-endian integers in the low 48 bytes of their 72-byte fields; the upper 24 bytes of each MUST be zero.
4. Endorsement cross-check. The VEK's extensions MUST equal the report: `1.3.6.1.4.1.3704.1.3.1` (bootloader SPL), `.3.2` (TEE SPL), `.3.3` (SNP SPL) and `.3.8` (microcode SPL) equal the components of `REPORTED_TCB`, and on Turin `.3.9` (FMC SPL) equals its FMC component; this holds for a VCEK and a VLEK alike. A VCEK's `1.3.6.1.4.1.3704.1.4` (hardware ID) equals `CHIP_ID`: all 64 bytes on Milan and Genoa; on Turin the hardware ID's 8 bytes equal the first 8 bytes of `CHIP_ID` and the remaining 56 bytes of `CHIP_ID` are zero. A VLEK carries no hardware ID, so under a VLEK the chip identifier rests on the firmware's signed report alone. A cross-check failure is refused with `chain-invalid`.
5. Revocation. AMD's CRL for the generation is signed by the ARK and MUST be inside its window at the evaluation time. The serial number of the ASK or ASVK in the chain MUST NOT appear in it. VCEK serial numbers are zero, so the CRL does not revoke an individual VCEK; a compromised chip is excluded through TCB floors and allowlists. The check is REQUIRED unless the policy sets `tcb.require_revocation` to false.
6. Allowlist. With a machine allowlist, the report's `CHIP_ID` MUST be on it. A report whose `CHIP_ID` is all zero (the host masked it) identifies no machine and is refused with `machine-not-allowed` when an allowlist is present (Section 13.3).

#### 9.1.5. Guest policy and normalized claims

| Claim | Source |
| --- | --- |
| `cvm_platform` | vendor `amd`, TEE `sev-snp`, generation from Section 9.1.3, hosting as reported |
| `cvm_policy.debug` | `POLICY` bit 19 (`DEBUG`); refused unless `allow_debug` |
| `cvm_policy.migratable` | `POLICY` bit 18 (`MIGRATE_MA`); refused unless `allow_migration` |
| `cvm_policy.smt` | `POLICY` bit 16 (`SMT`) |
| `cvm_policy.single_socket` | `POLICY` bit 20 (`SINGLE_SOCKET`) |
| `cvm_policy.vmpl` | `VMPL`; a value above 3 is refused whatever the policy says (Section 8.5), and a value other than 0 is refused under `require_vmpl0` |
| `dbgstat` | `enabled` when bit 19 is set, `disabled-since-boot` otherwise |
| `cvm_tcb` | `{reported, committed, current, launch}`, each `{bootloader, tee, snp, microcode, fmc?}` with `fmc` on Turin |
| `cvm_identity` | `{chip_id}`: `CHIP_ID` |
| `cvm_owner` | `{family_id, image_id, id_key_digest, author_key_digest}` |
| `cvm_host_data` | `{semantics: "snp-host-data", value: HOST_DATA}` |
| `snp` | the Trustee object (Section 12.7): `policy_abi_minor` bits 7:0 and `policy_abi_major` bits 15:8 of `POLICY`; `policy_smt_allowed` bit 16; `policy_migrate_ma` bit 18; `policy_debug_allowed` bit 19; `policy_single_socket` bit 20; `reported_tcb_*` from `REPORTED_TCB`; `platform_smt_enabled` and `platform_tsme_enabled` from `PLATFORM_INFO` bits 0 and 1; `measurement`, `report_data`, `init_data` (`HOST_DATA`) and `chip_id` in hexadecimal |

The TCB floor of Section 13.2 applies to the four TCB values. AMD runs no TCB status service, so the floor is the only TCB assessment; `hardware` is 2 when the chain, the signature and the cross-check hold, revocation was checked, and a TCB floor applied and is met, and carries no claim otherwise.

#### 9.1.6. Binding

| Mode | Rule |
| --- | --- |
| `report-data` | `REPORT_DATA == pad64(anchor)` |
| `commitment` | `REPORT_DATA == header16 \|\| C` (Section 8.1); the `cpu` submodule carries the 16 `snp-vmr` registers, the log, `cvm_chain` and `bootseed` |
| `vtpm-extradata` | Azure only: Section 9.4 |

#### 9.1.7. Collateral

`snp.vek` and `snp.crl` (Section 10.1). AMD KDS serves them at:

```
https://kdsintf.amd.com/vcek/v1/{Milan|Genoa|Turin}/{hwid}?blSPL={bl}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={ucode}[&fmcSPL={fmc}]
https://kdsintf.amd.com/vcek/v1/{Milan|Genoa|Turin}/cert_chain
https://kdsintf.amd.com/vcek/v1/{Milan|Genoa|Turin}/crl
```

`{hwid}` is `CHIP_ID` in lowercase hexadecimal (its first 8 bytes on Turin), the SPLs are the components of `REPORTED_TCB` in decimal, and `fmcSPL` is present exactly on Turin. A VLEK is issued to the cloud provider and carried inline; KDS serves its chain and CRL at `/vlek/v1/{product}/cert_chain` and `/vlek/v1/{product}/crl`, and the CRL is the same ARK-signed list as the VCEK path's.

### 9.2. Intel TDX

This binding covers TDX guests with hosting `bare`, `gcp` and `dstack`, and supplies the hardware quote for Azure TDX (Section 9.4).

#### 9.2.1. Evidence

The attester obtains a TD quote through the guest kernel (the configfs-tsm report interface or the TDX guest device and the host's quoting service) with `REPORTDATA` set to `pad64(anchor)`. It carries the quote in `cvm_report` with type `application/vnd.confidential-ai.tdx-quote`, MAY carry the RTMRs as `tdx-rtmr` registers and the ACPI CCEL as a `tdx-ccel` log (or a `tcg-cel-*` log), and MAY carry Intel collateral in `cvm_endorsements`.

#### 9.2.2. Quote layout

The quote header is 48 bytes, little-endian:

| Offset | Length | Field | Requirement |
| --- | --- | --- | --- |
| 0 | 2 | version | 4 or 5 |
| 2 | 2 | attestation key type | 2 (ECDSA-256 with P-256) |
| 4 | 4 | TEE type | 0x00000081 (TDX) |
| 12 | 16 | QE vendor ID | Intel's `939a7233f79c4ca9940a0db3957f0607` |
| 28 | 20 | user data | not used |

A version 4 quote carries the TD report body at offset 48. A version 5 quote carries a body type (2 bytes) at 48, a body size (4 bytes) at 50 and the body at 54; type 2 is a TDX 1.0 body of 584 bytes and type 3 a TDX 1.5 body of 648 bytes. Type 4 (TDX 1.5 with the extended feature set, 885 bytes) is refused with `report-invalid` in version 1. Offsets within the body:

| Body offset | Length | Field | Use |
| --- | --- | --- | --- |
| 0 | 16 | `TEE_TCB_SVN` | `cvm_tcb.tee_tcb_svn`; TCB level matching. Byte 0 is the TDX module's minor SVN, byte 1 its major version, byte 2 the microcode SVN |
| 16 | 48 | `MRSEAM` | `tdx_mrseam`; TDX module identity |
| 64 | 48 | `MRSIGNERSEAM` | `tdx_mrsignerseam`; TDX module identity |
| 112 | 8 | `SEAMATTRIBUTES` | TDX module identity |
| 120 | 8 | `TDATTRIBUTES` | guest policy (Section 9.2.5) |
| 128 | 8 | `XFAM` | `tdx_xfam` |
| 136 | 48 | `MRTD` | `cvm_launch_measurement`, `alg` `sha384` |
| 184 | 48 | `MRCONFIGID` | `cvm_host_data`, semantics `tdx-mrconfigid` |
| 232 | 48 | `MROWNER` | `cvm_owner.mr_owner` |
| 280 | 48 | `MROWNERCONFIG` | `cvm_owner.mr_owner_config` |
| 328, 376, 424, 472 | 48 each | `RTMR0` to `RTMR3` | `tdx-rtmr` registers 0 to 3 |
| 520 | 64 | `REPORTDATA` | the binding |
| 584 | 16 | `TEE_TCB_SVN2` | TDX 1.5 bodies |
| 600 | 48 | `MRSERVICETD` | TDX 1.5 bodies; `cvm_policy.service_td` is true when non-zero |

After the body: a 4-byte signature data length, then the quote signature (64 bytes, `r || s`), the attestation key (64 bytes, `x || y` of a P-256 point), and certification data of type 6 (QE report certification data): the QE report body (384 bytes), its signature (64 bytes), the QE authentication data (a 2-byte length and the data), and nested certification data of type 5 (the PEM PCK certificate chain).

#### 9.2.3. Authentication

1. Quote signature. The attestation key verifies the ECDSA P-256 SHA-256 signature over the header and the body (for version 5, including the body type and size).
2. Quoting enclave. The PCK leaf's key verifies the QE report signature over the 384-byte QE report body. The QE report's `REPORTDATA` (offset 320) equals `SHA-256(attestation key || QE authentication data) || zeros32`.
3. PCK chain. The chain is leaf, PCK Platform or Processor CA, and Intel SGX Root CA, whose key the verifier pins (Appendix E). Every certificate is inside its window at the evaluation time. The leaf is not on the PCK CRL of its issuing CA, and the intermediate is not on the Root CA CRL; each CRL is signed by its issuer and inside its window.
4. QE Identity. The TD QE Identity is signed by Intel's TCB signing certificate, which chains to the pinned root, has `id` `TD_QE`, and is inside its `nextUpdate`. The QE report's `MRSIGNER` and `ISVPRODID` equal its values, and `MISCSELECT` and `ATTRIBUTES` equal them under their masks. The QE's `ISVSVN` selects the first TCB level whose `isvsvn` it meets; a QE matching no level, or a `Revoked` level, is refused with `tcb-not-allowed`.
5. TCB Info. The TCB Info is signed by Intel's TCB signing certificate, has `id` `TDX` and version 3, carries the FMSPC and PCE identifier of the PCK leaf's SGX extensions, and has a `nextUpdate` after the evaluation time. The QE Identity has version 2. The verifier then evaluates the TCB as Intel's quote verification library does:
   1. TDX module identity. When `TEE_TCB_SVN[1]` is 0, `MRSIGNERSEAM` MUST equal the TCB Info's `tdxModule.mrsigner`, and `SEAMATTRIBUTES` MUST be zero and equal its `attributes`. When `TEE_TCB_SVN[1]` is greater than 0, the same checks use the `tdxModuleIdentities` entry whose `id` is `TDX_` followed by `TEE_TCB_SVN[1]` as two uppercase hexadecimal digits, and the module's status is that of the first of the entry's TCB levels, in descending `isvsvn` order, whose `isvsvn` is at most `TEE_TCB_SVN[0]`. A missing entry or level is refused with `tcb-not-allowed`.
   2. Platform level. The TCB levels are ordered descending by their SGX components, then PCESVN, then TDX components, compared lexicographically, and two levels equal under that order make the TCB Info invalid. The selected level is the first whose SGX components are each at most the PCK certificate's corresponding component, whose PCESVN is at most the certificate's PCESVN, and whose TDX components are each at most the corresponding byte of `TEE_TCB_SVN`, comparing from byte 2 when `TEE_TCB_SVN[1]` is greater than 0. No matching level is refused with `tcb-not-allowed`.
   3. Effective status. Start from the selected level's status. If the module status or the QE Identity level's status is `OutOfDate`, `UpToDate` and `SWHardeningNeeded` become `OutOfDate`, and `ConfigurationNeeded` and `ConfigurationAndSWHardeningNeeded` become `OutOfDateConfigurationNeeded`. If either is `Revoked`, the effective status is `Revoked`. The advisories are the selected level's, then the QE Identity level's, then the module's.
   4. The effective status MUST be in `tcb.tdx_allowed_status`; `Revoked` is always refused. For a TDX 1.5 body, version 1 evaluates `TEE_TCB_SVN` only; a module updated in place since launch is judged at its launch level.
6. Allowlist. With a machine allowlist, the PPID of the PCK leaf MUST be on it.

The PCK leaf's SGX extensions (PCK specification) supply: PPID (`1.2.840.113741.1.13.1.1`, 16 bytes), the TCB components and PCESVN (`.2.1` to `.2.17`), and FMSPC (`.4`, 6 bytes).

#### 9.2.4. Generation

The generation of a TDX platform is its FMSPC, from the PCK leaf, as twelve lowercase hexadecimal digits.

#### 9.2.5. Guest policy and normalized claims

`TDATTRIBUTES` is read as a 64-bit little-endian integer, with the bit assignments of the TDX Module ABI specification (348551-007, Table 3.22):

| Bits | Name | Rule |
| --- | --- | --- |
| 3:0 | TUD group (TD under debug); bit 0 is `DEBUG`, bits 3:1 reserved | any bit set puts the TD under debug; refused unless `allow_debug` |
| 6:4 | TD-under-profiling group: `HGS_PLUS_PROF`, `PERF_PROF`, `PMT_PROF` | any bit set lets the host profile the TD, which this profile treats as debug; refused unless `allow_debug` |
| 16 | `ICSSD` | permitted |
| 17 | `SERVTD_EXT` | permitted |
| 22:18 | `RESERVED_P` | ignored, as the ABI specification allows |
| 27 | `LASS` | permitted |
| 28 | `SEPT_VE_DISABLE` | MUST be set under `require_sept_ve_disable` |
| 29 | `MIGRATABLE` | refused unless `allow_migration` |
| 30 | `PKS` | permitted |
| 31 | `KL` (reserved in later ABI revisions) | permitted |
| 62 | `TPA` | permitted |
| 63 | `PERFMON` | permitted |
| 3:1, 15:7, 26:23, 61:32 | reserved, mask `0x3FFFFFFF0780FF8E` | MUST be zero under `require_zero_reserved_attributes` |

The TDX DCAP quote format document still shows an older attribute layout; the ABI specification governs.

A non-zero `MRSERVICETD` in a TDX 1.5 quote is refused unless `allow_service_td`.

| Claim | Source |
| --- | --- |
| `cvm_platform` | vendor `intel`, TEE `tdx`, generation the FMSPC, hosting as reported |
| `cvm_policy` | `{debug, migratable, sept_ve_disable, service_td?, reserved_bits_zero}`: `debug` when any of bits 6:0 is set, `migratable` bit 29, `sept_ve_disable` bit 28, `reserved_bits_zero` when the reserved mask is clear, and `service_td` (TDX 1.5 bodies only) when `MRSERVICETD` is not zero |
| `dbgstat` | `enabled` when any of bits 6:0 is set, `disabled-since-boot` otherwise |
| `cvm_tcb` | `{tee_tcb_svn, pck_tcb, pcesvn, fmspc, status?, advisories?}`: `TEE_TCB_SVN`; the PCK certificate's 16 TCB components and PCESVN; the FMSPC; and, when collateral was checked, the effective status and the advisories of Section 9.2.3 step 5 |
| `cvm_identity` | `{ppid}` |
| `cvm_owner` | `{mr_owner, mr_owner_config}` |
| `cvm_host_data` | `{semantics: "tdx-mrconfigid", value: MRCONFIGID}` |
| `tdx_*` | the compatibility claims of Section 12.6, in lowercase hexadecimal |

#### 9.2.6. Binding, registers and logs

The binding is `report-data`: `REPORTDATA == pad64(anchor)`; on Azure, `vtpm-extradata` (Section 9.4). The RTMRs are `tdx-rtmr` registers 0 to 3 with backing `hardware`. A `tdx-ccel` log maps `MrIndex` 1 to 4 to RTMR 0 to 3, skips records at `MrIndex` 0 (which describe `MRTD`), refuses any higher index, and replays in the SHA-384 bank from zero; a CEL log replays the same way.

#### 9.2.7. Collateral

`tdx.tcb_info`, `tdx.qe_identity`, `tdx.pck_crl` and `tdx.root_crl` (Section 10.1). Intel PCS serves them at:

```
https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc={fmspc}
https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity
https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca={platform|processor}
https://certificates.trustedservices.intel.com/IntelSGXRootCA.der
```

The TCB Info's issuer chain is in the `TCB-Info-Issuer-Chain` response header and the QE Identity's in `SGX-Enclave-Identity-Issuer-Chain`, percent-encoded PEM. The signature in each response covers the exact bytes of its `tcbInfo` or `enclaveIdentity` member.

### 9.3. dstack

dstack runs TDX and SEV-SNP guests whose guest agent returns the hardware report and, on TDX, an event log. Evidence and authentication are those of Section 9.1 or 9.2 with hosting `dstack`; the report is always the raw hardware report (the configfs-tsm JSON type is not accepted), and the binding is `report-data`, or `commitment` for an SEV-SNP guest with a register provider. The attester obtains the report from the guest agent with its report data set as the mode requires. The `dstack-json` log format applies to TDX guests only.

dstack's log is carried as `dstack-json` (Section 7.1): a JSON array of events `{imr, event_type, digest, event, event_payload, version?, preimage?}`, strictly parsed (a duplicate or unknown member is refused), with `imr` the RTMR ordinal 0 to 3 (no offset), `digest` 48 bytes in hexadecimal, and `event_payload` in hexadecimal.

- A boot event keeps the TCG digest it carries, and carries neither `version` nor `preimage`.
- A runtime event has `event_type` 0x08000001, and its digest is recomputed from its content under its `version`, absent meaning 1:
  - version 1: `SHA-384(u32le(0x08000001) || ":" || event || ":" || event_payload)`, where `event` is the UTF-8 name and `event_payload` the payload bytes; a name containing `:` is refused, so the hash input splits back into one name; `preimage` MUST be absent;
  - version 2: `SHA-384(p)`, where `p` is the JCS serialization (RFC 8785) of `{"name": event, "payload": <lowercase hexadecimal of event_payload>, "type": 134217729}`; the event's `preimage` member is REQUIRED, is the hexadecimal encoding of `p`, and MUST decode to `p` byte for byte.
- Replay is `R = SHA-384(R || digest)` from zero for each RTMR the log extends, and each MUST reproduce the signed RTMR.

### 9.4. Microsoft Azure confidential VMs

On Azure the guest runs above a paravisor (the HCL) that holds a vTPM. The relying party's anchor is bound in the TPM quote's `extraData`, and the hardware report binds the vTPM's attestation key (AK). The `cpu` submodule carries the hardware report with binding `vtpm-extradata`; the `vtpm` submodule carries the TPM quote, the HCL report and the PCRs.

#### 9.4.1. HCL report

The attester writes a 64-byte request to the vTPM's NV index 0x01400002 and reads the HCL report from NV index 0x01400001. Its layout, little-endian:

| Offset | Length | Field |
| --- | --- | --- |
| 0x000 | 4 | signature `HCLA` |
| 0x004 | 4 | version |
| 0x008 | 4 | report size |
| 0x00C | 4 | request type |
| 0x010 | 4 | status |
| 0x014 | 12 | reserved |
| 0x020 | 1184 | hardware report area: an SNP report (1184 bytes), or a TDX TD report (1024 bytes followed by zero bytes) |
| 0x4C0 | 4 | data size |
| 0x4C4 | 4 | version |
| 0x4C8 | 4 | report type: 2 SEV-SNP, 4 TDX |
| 0x4CC | 4 | report data hash type: 1 SHA-256 |
| 0x4D0 | 4 | variable data size |
| 0x4D4 | variable | variable data: a JSON object |

The report type MUST name the TEE of the `cpu` submodule, and the hash type MUST be 1. The variable data is exactly `variable data size` bytes. Its `keys` array holds the AK as the JWK whose `kid` is `HCLAkPub`, an RSA key (`kty` `RSA`, `n` and `e` in base64url) of 2048 bits. The paravisor creates the AK as a restricted signing key, so it signs only structures the TPM itself generated, which is what gives the `TPMS_ATTEST` `magic` check below its meaning; this profile relies on that property of the paravisor, which the pinned launch measurement covers.

#### 9.4.2. Key binding

The hardware report binds the variable data: `REPORT_DATA[0..32] == SHA-256(variable data)` for SEV-SNP, and `REPORTDATA[0..32] == SHA-256(variable data)` in the TD quote for TDX. The remaining 32 bytes carry no meaning in this profile.

For SEV-SNP the `cpu` submodule's report MUST be byte for byte the 1184-byte hardware area of the HCL report, authenticated by Section 9.1. Azure SNP reports can be version 2 (Section 9.1.3). The attester obtains the VCEK from Azure's instance metadata service (`http://169.254.169.254/metadata/THIM/amd/certification`) and carries it as `snp.vek`.

For TDX the TD report inside the HCL report is authenticated only by a platform MAC and is not evidence a remote verifier can check. The attester obtains a TD quote over it from Azure's quoting endpoint (`http://169.254.169.254/acc/tdquote`), and the `cpu` submodule carries that quote, authenticated by Section 9.2.

#### 9.4.3. TPM quote

1. The AK from the HCL report verifies the RSASSA-PKCS1-v1_5 SHA-256 signature over `cvm_tpm_quote.message`.
2. The message is a `TPMS_ATTEST` with `magic` `TPM_GENERATED_VALUE` (0xFF544347) and `type` `TPM_ST_ATTEST_QUOTE` (0x8018).
3. `extraData` equals `anchor` in length and value (Section 5.4).
4. The quoted `pcrDigest` equals the SHA-256 of the concatenation of the selected PCR values of the bank, in selection order (PCR `8i + b` for bit `b` of selection byte `i`), taken from `cvm_tpm_quote.pcrs`.
5. Each register of the `vtpm` submodule is a PCR inside the signed selection and equals its quoted value (Section 4.4).

Version 1 verifiers are REQUIRED to support the SHA-256 bank.

#### 9.4.4. Registers, logs and claims

The PCRs are `vtpm-pcr` registers with backing `privileged-service`. A `tpm2-event-log` replays into every PCR it extends from its PC Client starting value (Section 7.4). In version 1 the `vtpm` submodule's log is a `tpm2-event-log`; another format is refused with `unsupported`. The Azure launch measurement is the SNP `MEASUREMENT` or the TDX `MRTD` of the hardware report and covers the paravisor and firmware. The nonce reaches the hardware report only through the paravisor that holds the AK, so `vtpm-extradata` establishes freshness only when the paravisor is established: a verifier MUST refuse `vtpm-extradata` with `binding-mismatch` unless `reference.launch_measurement` is set. Without that rule a guest on other hardware could present a fabricated HCL report with its own AK, bind it once into a genuine report, and sign quotes for any nonce. Guest configuration delivered as Confidential Containers initdata is pinned through PCR 8, whose value is `SHA-256(zeros32 || d)` when initdata is the only extend into PCR 8, `d` being the 32-byte initdata digest the Confidential Containers runtime computes.

The `cpu` submodule's claims are those of Section 9.1.5 or 9.2.5 with hosting `azure`; the `vtpm` submodule's are `cvm_registers`, `cvm_freshness` and `cvm_tpm_ak`.

### 9.5. Google Cloud confidential VMs

Google Cloud SEV-SNP and TDX guests obtain the raw hardware report through the guest kernel, exactly as on bare metal, with hosting `gcp`. Evidence, authentication, binding and claims are those of Sections 9.1 and 9.2, and `gcp` admits the same report types and modes as `bare`.

### 9.6. Arm CCA

An Arm CCA realm is attested by a token the Realm Management Monitor (RMM) returns: a realm token signed by the Realm Attestation Key (RAK), and a platform token signed by the CCA Platform Attestation Key (CPAK) that binds the RAK. The `cpu` submodule carries the token as a nested token (Section 4.6), with hosting `bare`.

#### 9.6.1. Evidence

The realm calls `RSI_ATTESTATION_TOKEN_INIT` with the 64-byte challenge `pad64(anchor)` and reads the token with `RSI_ATTESTATION_TOKEN_CONTINUE` (RMM specification, section B5). Two top-level forms exist, and a verifier accepts exactly these two by allowlist:

| Form | Encoding | Emitted by |
| --- | --- | --- |
| collection under tag 907 | `#6.907({44234: [263, bytes .cbor COSE_Sign1<platform>], 44241: [263, bytes .cbor COSE_Sign1<realm>]})`, each value a CMW record whose type is CoAP content-format 263 (`application/eat+cwt`) | RMM specification 2.0 (in beta as 2.0-bet3) and draft-ffm-rats-cca-token-02 and later; the reference RMM firmware by default from its 0.9.0 release |
| collection under tag 399 | `#6.399({44234: bytes .cbor COSE_Sign1<platform>, 44241: bytes .cbor COSE_Sign1<realm>})` | RMM specification 1.0-rel0 and draft-ffm-rats-cca-token-00 and -01 |

Neither tag is assigned in the IANA CBOR Tags registry (Section 17.3). Both tokens are tagged COSE_Sign1 (RFC 9052).

#### 9.6.2. Profiles and binding

The platform token binds the realm token through the hash of the RAK: the hash, with the algorithm the realm token names in its public-key hash algorithm claim (44240), of the content bytes of the realm public key claim (44237), which is an encoded COSE_Key. The claim that carries the hash depends on the platform profile:

| Platform profile (claim 265) | Realm profile | Binding claim in the platform token |
| --- | --- | --- |
| `tag:arm.com,2023:cca_platform#1.0.0` | `tag:arm.com,2023:realm#1.0.0` | challenge (10) |
| `tag:arm.com,2024:cca_platform#2.0.0` | `tag:arm.com,2024:realm#2.0.0` | challenge (10) |
| `tag:arm.com,2026:cca_platform#2.0.0`, and its delegated variant (spelled `;delegated` in draft-ffm-rats-cca-token-04 and `#delegated` in the RMM specification 2.0-bet3) | `tag:arm.com,2026:realm#2.0.0` | workload binding (2408) |

Either top-level form may carry any of these profile pairs. A token with another profile, without a realm profile, or using the direct or HESRAK binding variants is refused with `unsupported` in version 1.

#### 9.6.3. Claims used

Realm token:

| Key | Claim | Use |
| --- | --- | --- |
| 10 | challenge, 64 bytes | MUST equal `pad64(anchor)` (`cca-challenge`) |
| 44235 | Realm Personalization Value, 64 bytes | `cvm_host_data`, semantics `cca-rpv` |
| 44236 | hash algorithm identifier, text | `alg` of the RIM and REMs: `sha-256`, `sha-384` or `sha-512` map to `sha256`, `sha384`, `sha512` |
| 44237 | RAK, an encoded COSE_Key | verifies the realm token; its hash binds the platform token |
| 44238 | Realm Initial Measurement | `cvm_launch_measurement` |
| 44239 | Realm Extensible Measurements, 4 values | `cca-rem` registers 0 to 3 |
| 44240 | RAK hash algorithm identifier, text | the binding hash |

Platform token:

| Key | Claim | Use |
| --- | --- | --- |
| 2396 | implementation ID, 32 bytes | `cvm_platform.generation`, in lowercase hexadecimal; selects the vendor's endorsements |
| 256 | instance ID, a 33-byte UEID whose first byte is 0x01 | `cvm_identity.instance_id`; selects the CPAK |
| 2395 | security lifecycle | guest policy (Section 9.6.5); `cvm_tcb.lifecycle` |
| 2399 | software components | `cvm_tcb.sw_components`: component type (1), measurement value (2), version (4), signer ID (5), hash algorithm (6) |
| 2400 | verification service, text | a hint for where the vendor's endorsements are served |
| 2402 | platform hash algorithm identifier | the algorithm of the software component measurements |

#### 9.6.4. Authentication

1. Endorsement. The verifier pins, per platform vendor, the key that signs the vendor's CoRIM (draft-ietf-rats-corim-11). The CoRIM for the implementation ID carries attestation-key triples that bind each instance ID to its CPAK, and reference-value triples for the platform software components. There is no single root for CCA platforms; the CoRIM is the endorsement, and it is REQUIRED: without it the platform token cannot be authenticated, and the verifier refuses with `collateral-unavailable` whatever the policy says.
2. Platform token. The CPAK the CoRIM binds to the token's instance ID verifies the platform token's COSE_Sign1 signature (ES256 or ES384, as its protected header names).
3. Realm token. The RAK of claim 44237 verifies the realm token's COSE_Sign1 signature (ES384).
4. Binding. The platform token's binding claim (Section 9.6.2) equals the hash of the RAK.
5. Platform software. Every software component's measurement and signer ID equals a reference value the CoRIM endorses for the implementation ID. This one check is waived when the policy sets `tcb.require_signed_collateral` to false; the waiver is reported as `cca_corim` `skipped` with a reason, and `hardware` then makes no claim.
6. Allowlist. With a machine allowlist, the instance ID MUST be on it.

#### 9.6.5. Guest policy and normalized claims

The security lifecycle's bits 15:8 name its state: 0x30 is secured; 0x40 (non-platform-RoT debug) and 0x50 (recoverable platform-RoT debug) are debug states; every other state (unknown, assembly and test, provisioning, decommissioned) is refused. A debug state is refused unless `allow_debug`, and is then reported with `configuration` 96. A realm cannot migrate under the RMM specification, so `migratable` is false.

| Claim | Source |
| --- | --- |
| `cvm_platform` | vendor `arm`, TEE `cca`, generation the implementation ID, hosting `bare` |
| `cvm_launch_measurement` | `{alg, value}`: the RIM under the realm hash algorithm |
| `cvm_registers` | REM 0 to 3 as `cca-rem`, backing `hardware`, `replayed` false |
| `cvm_host_data` | `{semantics: "cca-rpv", value: RPV}` |
| `cvm_policy` | `{debug, migratable}`: `debug` true in a debug lifecycle state |
| `dbgstat` | `enabled` in a debug lifecycle state, `disabled-since-boot` otherwise |
| `cvm_tcb` | `{lifecycle, sw_components}` |
| `cvm_identity` | `{instance_id}` |

Version 1 does not replay REMs. The RMM specification and its reference implementation define the REM extend input differently for extensions shorter than 64 bytes and for hash algorithms other than SHA-512, so a replay rule cannot yet be fixed; REMs are pinned by value (`reference.registers`) and reported with `replayed` false. A later revision defines REM replay from a CEL log once the extend function is settled.

#### 9.6.6. Collateral

The vendor's signed CoRIM, identified by the collateral key `cca_corim/<implementation id hex>` (Section 10.3). The platform token's verification service claim MAY tell the verifier where to fetch it.


### 9.7. NVIDIA GPUs and NVSwitch

NVIDIA devices are appraised by NRAS, which verifies each device's SPDM evidence and certificate chain against NVIDIA's reference values and returns signed claims. The verifier's role is to bind the devices to the nonce, authenticate NRAS's answer, and apply the device policy.

#### 9.7.1. Request

The verifier groups the device submodules by architecture and sends one request per architecture (in the order `HOPPER`, `BLACKWELL`, `LS10`), to `/v4/attest/gpu` for GPUs and `/v4/attest/switch` for NVSwitches at `https://nras.attestation.nvidia.com`:

```
{ "nonce": <the device nonce of Section 5.4, lowercase hexadecimal>,
  "evidence_list": [ { "evidence": <evidence_b64>, "certificate": <cert_chain_b64> }, ... ],
  "arch": "HOPPER" | "BLACKWELL" | "LS10",
  "claims_version": "3.0" }
```

#### 9.7.2. Response

NRAS answers with a detached EAT: `[["JWT", <overall token>], {<name>: <device token>, ...}]`. The verifier:

1. verifies every token as a JWS (RFC 7515) with `alg` `ES384`, a `kid`, and no `crit`, under a key from NRAS's JWKS (the endpoint's origin plus `/.well-known/jwks.json`) whose `x5c` chain is valid at the evaluation time and ends at the pinned NVIDIA attestation root (Appendix E); it checks `exp` and, when present, `nbf`;
2. requires the overall token's `iss` to be the endpoint's origin and `x-nvidia-ver` to be `3.0`, and its `x-nvidia-overall-att-result` to be true;
3. requires the overall token's `submods` to hold, for each device token, `["DIGEST", ["SHA-256", <hex>]]` equal to the SHA-256 of that device token's compact serialization, and the number of device tokens to equal the number of devices sent;
4. maps each device token back to its submodule by position: the verifier sends each batch's devices in ascending byte order of their submodule names, NRAS names the tokens `GPU-<i>` and `SWITCH-<i>` with `<i>` the device's position counted from 0, and the kind MUST match the endpoint;
5. requires each device token's `eat_nonce` (NVIDIA encodes it in hexadecimal) to equal the device nonce;
6. requires each device token's architecture, as its `hwmodel` claim names it, to be the batch's.

Failures are refused as follows: a token that fails steps 1 or 2 (other than the overall result), step 3's digests, step 4, or its key identifier, with `device-token-invalid`; a false overall result, a device count that differs, or a failed step 6, with `device-policy`; a device nonce that differs (step 5), with `binding-mismatch`; an NRAS or JWKS endpoint that cannot be reached, with `collateral-unavailable`.

#### 9.7.3. Device policy and claims

| Gate | Requirement |
| --- | --- |
| `allow_debug` false | the device token's `dbgstat` is `disabled` |
| `require_secboot` | `secboot` is true |
| `require_nonce_match` | `x-nvidia-gpu-attestation-report-nonce-match` (GPU) or `x-nvidia-switch-attestation-report-nonce-match` (NVSwitch) is true |
| `require_measres_success` | `measres` is `success` |

A failed gate is refused with `device-policy`.

| Claim | Source |
| --- | --- |
| `ear_attester_claims` | the device token's claims, verbatim, plus `cvm_identity` `{ueid}` from the signed `ueid`, and for a GPU `cvm_tcb` `{driver, vbios}` from `x-nvidia-gpu-driver-version` and `x-nvidia-gpu-vbios-version` when both are present |
| `ear_nvidia_evidence` | `signature_verified`, `parsed` and `nonce_match` from `x-nvidia-{gpu,switch}-attestation-report-signature-verified`, `-parsed` and `-nonce-match` |
| vector | `sourced-data` 2; `instance-identity` 2 when the signed `ueid` is on the machine allowlist |

The device's identity is the signed `ueid`. The `<ueid>` in the submodule name is the attester's label, is required to equal `uuid`, and is never compared against policy.


## 10. Endorsements

### 10.1. Inline endorsements

`cvm_endorsements` carries collateral inside the evidence, so a verifier can appraise offline and a vendor service outage does not stop a verifier that receives fresh collateral. It is a CMW collection (RFC 9999 section 3.3) whose `__cmwc_t` is `tag:confidential.ai,2026:cvm-endorsements#1`, with at least one entry besides `__cmwc_t`, no nested collections, and labels drawn only from this table. Each entry is a CMW record `[type, value, indicator]` whose indicator is 2 (bit 1, endorsements) or 1 (bit 0, reference values); version 1 gives both the same meaning, and defines no label that carries reference values.

| Label | Type | Content | TEE |
| --- | --- | --- | --- |
| `snp.vek` | `application/pkix-cert` | the VCEK or VLEK, DER | `sev-snp` |
| `snp.crl` | `application/pkix-crl` | AMD's CRL for the generation, DER | `sev-snp` |
| `tdx.tcb_info` | `application/vnd.confidential-ai.pcs-signed+json` | the TDX TCB Info, as the JSON object `{body, issuer_chain}` | `tdx` |
| `tdx.qe_identity` | `application/vnd.confidential-ai.pcs-signed+json` | the TD QE Identity, as `{body, issuer_chain}` | `tdx` |
| `tdx.pck_crl` | `application/pkix-crl` | Intel's PCK CRL for the issuing CA, DER | `tdx` |
| `tdx.root_crl` | `application/pkix-crl` | Intel's SGX Root CA CRL, DER | `tdx` |
| `nras.jwks` | `application/jwk-set+json` | NRAS's token signing keys | any `cpu` with devices |

In `application/vnd.confidential-ai.pcs-signed+json`, `body` is the exact bytes of Intel's PCS response body and `issuer_chain` the PEM issuer chain from the response header, both as base64url byte strings, so Intel's signature verifies over the bytes Intel produced. A label whose TEE is not the `cpu` submodule's TEE is refused.

### 10.2. Authority and precedence

Inline endorsements are inputs the verifier authenticates before use. A verifier:

1. anchors every certificate to the pinned vendor roots (Section 9) and every signed document to its signing chain, and refuses a body presented without its chain;
2. checks every validity window against the evaluation time before use: a certificate's `notBefore` and `notAfter`, a CRL's `thisUpdate` and `nextUpdate`, a TCB Info's or QE Identity's `nextUpdate`;
3. binds each artifact to the parameters that name it: a VEK to the report's chip identifier and reported TCB, a TCB Info to the PCK certificate's FMSPC, a CRL to its issuer;
4. prefers its own valid copy of a CRL or a TCB document, so an attester cannot substitute an older valid artifact for a newer one the verifier knows; a VEK is the same key from either source.

An inline artifact that fails its binding or its window is ignored as if absent: the verifier uses its own copy, and when it has none the check is unavailable (`collateral-unavailable`, or skipped under a waiver). An artifact the verifier itself obtained and that fails is refused with `collateral-invalid`.

Freshness of collateral is each artifact's own validity window evaluated at the evaluation time. An artifact inside its window is usable however long ago it was fetched, and an artifact outside it is refused however recently it arrived; the verifier's cache timers play no part.

### 10.3. Collateral keys

A verifier that holds collateral outside the evidence identifies each artifact by a key. The conformance corpus uses these text forms (Section 14.2):

| Key | Artifact |
| --- | --- |
| `snp_vcek/<generation>/<chip id hex>-<TCB hex>` | a VCEK: `<generation>` is `Milan`, `Genoa` or `Turin`; `<TCB hex>` is the reported bootloader, TEE, SNP and microcode SPLs as two uppercase hexadecimal digits each, followed by the FMC SPL on Turin |
| `snp_cert_chain/<generation>` | AMD's ASK and ARK for the generation |
| `snp_crl/<generation>` | AMD's CRL for the generation |
| `tdx_tcb_info/<fmspc>` | the TDX TCB Info for an FMSPC in lowercase hexadecimal, with its signing chain |
| `tdx_qe_identity/td` | the TD QE Identity, with its signing chain |
| `tdx_pck_crl/<ca>` | the PCK CRL, `<ca>` `platform` or `processor` |
| `tdx_root_crl` | the SGX Root CA CRL |
| `nras_jwks/<url>` | the NRAS JWKS served at `<url>` |
| `cca_corim/<implementation id hex>` | the platform vendor's signed CoRIM for an Arm CCA implementation: the CPAK of each instance and the reference values of the platform software (Section 9.6.4) |

## 11. Verification procedure

A verifier appraises evidence under a policy, with the relying party's nonce, the presented certificate in the certificate pattern, collateral, and an evaluation time. Every step fails closed: a failure is a refusal with the code of Section 14.4, and no appraisal is produced.

For the `cpu` submodule:

1. Parse. Parse the envelope within the bounds of Section 4.7. Refuse an unknown profile or `cvm_version` and any submodule name or combination Section 4.2 does not admit (`envelope-invalid`), and an `eat_nonce` that differs from the nonce the relying party supplied (`binding-mismatch`).
2. Identify. Select the parser from `cvm_report`'s media type, parse the hardware report, and re-derive the vendor, the TEE and the generation from it (Section 9). Refuse a report the parser does not accept and a `cvm_platform` or `dbgstat` hint that contradicts the report.
3. Authenticate. Verify the hardware chain to the pinned root and the report's signature, including every validity window at the evaluation time and the cross-checks Section 9 lists for the platform. When the policy carries a machine allowlist, the identity this step authenticated MUST be on it.
4. Guest policy. Enforce the normalized security settings (Section 13.1): debug disabled unless allowed; on SEV-SNP, a guest-requested report (VMPL at most 3), VMPL 0 and migration disallowed unless allowed; on TDX, `SEPT_VE_DISABLE` set, reserved attributes zero, and no migration-service TD unless allowed; on Arm CCA, the platform lifecycle in a secured state unless debug is allowed.
5. Freshness. Verify the binding of `cvm_binding.mode` (Section 5.4). For `commitment` the check is the recompute of Section 8.1 over the registers step 8 establishes.
6. Collateral. Check revocation, the TCB status and advisories, the TCB floor that applies to this machine (Section 13.2) and, on TDX, the QE Identity, each with its signing chain anchored and its window checked; record each outcome.
7. Registers. Establish the authoritative register values (Section 6.5) and refuse envelope values that differ.
8. Replay. Replay the log when present (Section 7.4), mark each register `replayed`, and apply the slot rules of Section 8 in `commitment` mode.
9. Reference values. Apply the reference values and the backing minimum (Section 13), then produce the claims and the trustworthiness vector (Section 12).

Steps 3, 4 and 6 operate on authenticated data and are independent of one another; a verifier MAY run them in any order. No step uses a value that a later step establishes, except the `commitment` recompute of step 5, which runs with steps 7 and 8. When evidence fails more than one check, a verifier MAY refuse with the code of any failing step; each conformance case exercises one failing statement (Section 14.2).

For the `vtpm` submodule, which is appraised before the `cpu` submodule that binds it: step 3 is the attestation key's signature over the quote and the checks of Section 9.4; step 5 is `extraData == anchor`; step 7 projects the quoted PCRs; step 8 replays the vTPM's log. The `cpu` submodule's step 5 is then the key binding of Section 9.4.

For device submodules: the verifier sends one NRAS request per architecture with every device of that architecture, and appraises the answer as Section 9.7 states.

A verifier MUST appraise every submodule the envelope carries. It MUST refuse the whole envelope when any submodule fails.

## 12. Appraisal results

### 12.1. Result envelope

The appraisal is an EAR claims set (draft-ietf-rats-ear-04) with `eat_profile` `tag:ietf.org,2026:rats/ear#04`:

| Claim | CBOR key | Value |
| --- | --- | --- |
| `eat_profile` | 265 | `tag:ietf.org,2026:rats/ear#04` |
| `iat` | 6 | the appraisal time, the evaluation time when one was given |
| `ear_verifier_id` | 1004 | `{developer, build}` naming the verifier implementation |
| `eat_nonce` | 10 | the nonce that was bound |
| `ear_all_submods_bound` | text | `"true"` or `"false"` (Section 12.6) |
| `ear_raw_evidence` | 1002 | OPTIONAL: a CMW record of type `application/cmw+json` whose value is a CMW collection carrying the envelope as appraised (indicator 4) and the endorsements the verifier used (indicator 2), so the decision can be re-verified after a vendor withdraws collateral |
| `submods` | 266 | one entry per evidence submodule, with the same names |

Each submodule entry:

| Claim | CBOR key | Value |
| --- | --- | --- |
| `ear_status` | 1000 | the AR4SI tier of the submodule (Section 12.4) |
| `ear_trustworthiness_vector` | 1001 | Section 12.4 |
| `ear_appraisal_policy_ids` | 1003 | exactly two identifiers: the profile URI `tag:confidential.ai,2026:cvm#1`, which names the verification procedure, and the policy's own identifier (Section 12.5) |
| `ear_attester_claims` | 1005 | the normalized claims of Section 12.2 |
| `ear_verifier_claims` | 1006 | the verifier claims of Section 12.3 |

The appraisal carries no signature. A verifier that hands an appraisal across a trust boundary signs it as an EAR token, a JWT or CWT (draft-ietf-rats-ear-04 section 3), or delivers it over an authenticated channel; the field names alone make nothing verifiable. A failed appraisal produces no appraisal: the verifier returns the refusal code. A relying party that records failures MAY express them with the AR4SI contraindicated values; this profile does not.

### 12.2. Normalized attester claims

`ear_attester_claims` of a `cpu` submodule:

| Claim | CBOR key | Value |
| --- | --- | --- |
| `cvm_platform` | -70001 | `{vendor, tee, generation, hosting}`: vendor, TEE and generation derived from signed data (Section 9); `hosting` as the attester reported it, a label |
| `cvm_launch_measurement` | -70020 | `{alg, value}`: the launch measurement and its algorithm |
| `cvm_registers` | -70005 | the verified registers of Section 6 with `backing` as established and `replayed`; workload slots add `owner` and `purpose` from their claim records |
| `cvm_freshness` | -70021 | `{pattern, mode, key?, not_before?, not_after?}` as bound; present only because the binding passed |
| `cvm_host_data` | -70022 | `{semantics, value}` with semantics `snp-host-data` (32 bytes), `tdx-mrconfigid` (48) or `cca-rpv` (64); a label (Section 3.5) |
| `cvm_owner` | -70023 | SEV-SNP `{family_id, image_id, id_key_digest, author_key_digest}`; TDX `{mr_owner, mr_owner_config}`; absent on Arm CCA |
| `cvm_policy` | -70024 | normalized security settings: `debug` and `migratable` on every TEE; `smt`, `single_socket` and `vmpl` on SEV-SNP; `sept_ve_disable`, `service_td` (TDX 1.5 quotes only) and `reserved_bits_zero` on TDX |
| `dbgstat` | 263 | `enabled` when the TEE's guest-debug facility is enabled, `disabled-since-boot` otherwise (CBOR 0 and 2) |
| `cvm_tcb` | -70025 | vendor-specific firmware versions (Section 9) |
| `cvm_identity` | -70026 | the authenticated hardware identifier: SEV-SNP `chip_id`, TDX `ppid`, Arm CCA `instance_id` |
| `cvm_chain` | -70007 | in `commitment` mode, `{chain_len}` |
| `bootseed` | 268 | in `commitment` mode, the chain's boot seed |

`dbgstat` covers the TEE's guest-debug facility, through which the host can read and write guest state: the SEV-SNP policy DEBUG bit, the TDX debug attributes, the Arm CCA platform lifecycle. It makes no statement about the chip's hardware debug interfaces. The policy is fixed at launch, so a disabled facility is reported as `disabled-since-boot`.

`cvm_workload_id` (CBOR key -70027) is reserved for a derived workload identifier and is never emitted by a version 1 verifier.

`ear_attester_claims` of a `vtpm` submodule: `cvm_registers` (the verified PCRs), `cvm_freshness` and `cvm_tpm_ak`.

`ear_attester_claims` of a device submodule: NRAS's signed device claims verbatim, with `cvm_identity` `{ueid}` and, for a GPU whose token carries both versions, `cvm_tcb` `{driver, vbios}` beside them (Section 9.7).

### 12.3. Verifier claims

`ear_verifier_claims` records what the verifier checked:

| Claim | CBOR key | Value |
| --- | --- | --- |
| `cvm_collateral` | -70030 | per check (`snp_crl`, `tdx_pck_crl`, `tdx_root_crl`, `tdx_tcb_info`, `tdx_qe_identity`, `nras_jwks`, `cca_corim`): `{status, reason?, this_update?, next_update?, signed?}` with `status` `checked`, `skipped` (the policy waived it; Section 13.1) or `not-applicable` (the evidence gives it nothing to check) |
| `cvm_reference` | -70031 | which reference values were applied: `launch_measurement` true when a launch measurement pin matched and false when none was configured, and `registers` listing each pinned slot, which matched |
| `cvm_backing_min` | -70032 | `{required, weakest_seen}` |
| `ear_nvidia_evidence` | text | device submodules: `{signature_verified, parsed, nonce_match}` from NRAS's signed claims (Section 9.7) |

A check the policy waived is reported as `skipped` with its reason. A configured expectation that fails is a refusal; a `false` in `cvm_reference` means only that nothing was pinned.

### 12.4. Trustworthiness vector and status

The vector uses the AR4SI categories and values (draft-ietf-rats-ar4si-10 section 2.3). A category the verifier makes no assertion about is absent.

| Category | Value and condition |
| --- | --- |
| `instance-identity` | 2 when the policy carries a machine allowlist and the authenticated identity is on it; absent without an allowlist. An identity absent from the allowlist is a refusal |
| `configuration` | 2 when the security settings of Section 13.1 hold; 96 when debug is enabled (which the policy allowed), or on SEV-SNP a VMPL other than 0. Other settings a policy admits (migration, a waived `SEPT_VE_DISABLE`, non-zero reserved attributes, a service TD) leave it at 2; the policy identifier records the waiver |
| `executables` | 2 when the launch measurement is pinned and matched and every register the policy pins matched; 3 when the launch measurement is pinned and matched and no register is pinned; absent when the launch measurement is not pinned, since nothing then vouches for the code the registers were measured by |
| `hardware` | 2 when the chain anchors, every signature verifies, revocation was checked, and the TCB was assessed and is acceptable: on TDX the vendor status from TCB Info, on SEV-SNP a TCB floor that applied (AMD runs no status service), on Arm CCA the endorsed platform software; 32 when the vendor reports a status with known vulnerabilities that the policy accepts (on TDX any accepted status other than `UpToDate`); absent when the TCB was not assessed or a revocation check was waived. Revocation is a refusal |
| `runtime-opaque` | 2 for every `cpu` submodule that appraises with debug disabled: the runtime executes inside the TEE, encrypted and opaque to the host; 96 when debug is enabled, since the host can then read guest memory. Nothing is claimed about isolation between processes inside the guest |
| `file-system`, `storage-opaque` | absent in version 1 |
| `sourced-data` | device submodules: 2 when NRAS affirmed the device and every device gate held |

The `vtpm` submodule's vector carries `executables` alone: 2 when the policy pins at least one PCR and every pinned PCR matched (the launch measurement pin that `vtpm-extradata` requires vouches for the paravisor that measured them); 0 (no assertion) when the policy pins none, because AR4SI requires a vector to carry at least one category. The vTPM's hardware, configuration and runtime claims belong to the `cpu` submodule that binds its key. A device submodule's vector carries `sourced-data` and, with an allowlist, `instance-identity`.

`executables` 2 asserts that every register the policy pins holds an approved value. A policy that pins a subset of the registers obtains that assertion over the subset only; a relying party that needs the full AR4SI meaning (only approved code during and after boot) pins every register the platform exposes.

`ear_status` is the worst tier the vector reaches, where each value's tier is: -1 to 1 none; 2 to 31 and -32 to -2 affirming; 32 to 95 and -96 to -33 warning; 96 to 127 and -128 to -97 contraindicated; with none < affirming < warning < contraindicated.

### 12.5. Policy identifier

The second entry of `ear_appraisal_policy_ids` names the effective policy: `ni:///sha-384;<base64url>` (RFC 6920), the SHA-384 of the JCS serialization (RFC 8785) of the policy in which every member that has a default is present with its value or its default, and no member is null. The members without a default (`freshness.key`, `tcb.default_floor`, `identity`, `owner`, `gpu.expected_archs`) appear only when set; every other object appears, empty or not, as in Appendix B.4, which shows the effective default policy in full. Two appraisals carry the same identifier exactly when their effective policies serialize to the same bytes; reordering an array changes the identifier without changing the requirements. The identifier of the default policy is in Appendix B.4.

### 12.6. Composition with the TDX confidential-GPU EAR profile

draft-kykdxy-rats-tdx-cgpu-ear-profile-02 defines EAR claims for TDX guests with confidential GPUs. This profile composes with it:

- a TDX `cpu` submodule carries, beside the `cvm_*` claims, the Intel Trust Authority names that draft reuses, as lowercase hexadecimal text: `tdx_mrtd`, `tdx_rtmr0` to `tdx_rtmr3`, `tdx_mrconfigid`, `tdx_mrowner`, `tdx_mrownerconfig`, `tdx_td_attributes`, `tdx_tee_tcb_svn`, `tdx_xfam`, `tdx_mrseam`, `tdx_mrsignerseam`;
- device submodules carry NRAS's claim names unchanged, and `ear_nvidia_evidence` in `ear_verifier_claims`;
- `ear_all_submods_bound` is the draft's text claim. The verifier emits `"true"` or `"false"` and never `"unknown"`, since it checks every binding. A binding that fails is a refusal, so the claim is `"false"` only when a device's signed nonce match is false and the policy (`gpu.device_policy.require_nonce_match`) tolerates it.

A relying party written against that draft reads these appraisals without a mapping.

### 12.7. Composition with Confidential Containers Trustee

For an SEV-SNP `cpu` submodule the verifier emits an `snp` object in `ear_attester_claims`, beside the `cvm_*` claims, carrying the names the Confidential Containers Trustee verifier emits, with Trustee's types: `policy_abi_major`, `policy_abi_minor` (integers), `policy_smt_allowed`, `policy_migrate_ma`, `policy_debug_allowed`, `policy_single_socket` (booleans), `reported_tcb_bootloader`, `reported_tcb_tee`, `reported_tcb_snp`, `reported_tcb_microcode` (integers), `platform_tsme_enabled`, `platform_smt_enabled` (booleans), and `measurement`, `report_data`, `init_data` (Trustee's name for `HOST_DATA`) and `chip_id` (lowercase hexadecimal text). A policy written against Trustee's annotated evidence reads this object unchanged. The object is compatibility output: the `cvm_*` claims are normative, the `snp` object repeats a subset of their content, and its keys stay text in both encodings.

## 13. Verifier policy

### 13.1. Shape and defaults

The policy is a verifier input, chosen by the relying party. It is a JSON object under the encoding rules of Section 4.7 (a `null` member, an object written as an array, or an unknown member fails its validation with `policy-invalid`). Every member is optional and every default fails closed:

| Member | Default | Meaning |
| --- | --- | --- |
| `reference` | all empty | reference values, Section 13.4 |
| `min_backing` | `hardware` | the minimum backing of every verified register |
| `freshness.key` | absent | the key binding the relying party requires (Section 5.2) |
| `commitment.header16` | `QVRTLU1SLTEBARAAAAAAAA` | the `ats-mr-v1` header, base64url; any other value fails validation |
| `commitment.seed` | `YM3K6sPxWpbLKhuF1CxaTRKfztZUNQRMklD9_--YmEzDvUIJcsOvWCleD2G6IeSn` | the `ats-mr-v1` seed, base64url; any other value fails validation |
| `tcb.floors` | `{}` | named TCB floors, Section 13.2 |
| `tcb.default_floor` | absent | the floor applied to machines without their own |
| `tcb.tdx_allowed_status` | `["UpToDate"]` | the accepted Intel TCB statuses; `Revoked` can never be listed |
| `tcb.require_revocation` | `true` | revocation MUST be checked. When false, an SEV-SNP CRL that cannot be obtained is skipped; on TDX the collateral checks run together, and are skipped only when no collateral is available and both waivers are set |
| `tcb.require_signed_collateral` | `true` | the vendor TCB assessment MUST be made from signed collateral. When false, and on TDX together with `require_revocation` false, a TDX appraisal without collateral skips the PCK and Root CA CRLs, the TCB Info and the QE Identity check of Section 9.2.3 step 4 (the binding of the attestation key to the PCK certificate, step 2, always runs); on Arm CCA it waives only the platform software reference values (Section 9.6.4). A production policy SHOULD NOT waive it |
| `policy_bits.allow_debug` | `false` | admit a guest whose debug facility is enabled |
| `policy_bits.allow_migration` | `false` | admit a migratable guest |
| `policy_bits.require_vmpl0` | `true` | SEV-SNP: the report's VMPL is 0 |
| `policy_bits.require_sept_ve_disable` | `true` | TDX: `SEPT_VE_DISABLE` is set |
| `policy_bits.require_zero_reserved_attributes` | `true` | TDX: every reserved TD attribute bit is zero |
| `policy_bits.allow_service_td` | `false` | TDX 1.5: admit a non-zero `MRSERVICETD` |
| `identity.machines` | absent | machine allowlist, Section 13.3 |
| `owner.id_key_digests` | absent | SEV-SNP: the accepted ID key digests (48 bytes each) |
| `gpu` | Section 13.5 | device requirements |

A pin that nothing in the evidence can satisfy is refused with `reference-mismatch`: PCR pins without a `vtpm` submodule, slot owners without workload slots, a register pin for a register the appraisal does not report, `owner.id_key_digests` on a TD quote.

### 13.2. TCB floors

A floor is named, so a fleet carries one floor per generation and moves a machine between floors without editing every policy. A floor constrains at least one platform:

```
TcbFloor = {
  ? snp: { min: { bootloader, tee, snp, microcode, ? fmc },
           ? values: [ 1*4 ("reported" / "current" / "committed" / "launch") ] },
  ? tdx: { ? min_tee_tcb_svn: bytes16, ? min_tcb_evaluation_data_number: uint }
}
```

An SEV-SNP floor bounds each TCB value it names, componentwise, and all four when `values` is omitted: `reported`, the TCB the VEK was derived for; `current`, the firmware running when the report was signed; `committed`, the anti-rollback floor below which the firmware cannot be loaded again; `launch`, the TCB the firmware recorded when the guest was launched or imported. A floor on `reported` alone leaves a host free to roll firmware back to its committed version between attestations, and a guest launched on vulnerable firmware keeps that exposure after a live update; the default closes both. A floor that names the FMC SPL fails a report without one, which is every generation before Turin. `values` names each value at most once.

On TDX, the Intel status and the floor are independent requirements: the status MUST be in `tdx_allowed_status` for every quote, and a floor adds `tee_tcb_svn` componentwise and the TCB Info's `tcbEvaluationDataNumber`. The evaluation number is what stops an older TCB Info, still inside its validity window and validly signed, from reporting a status that a later TCB recovery changed.

`default_floor` and every machine's `tcb_floor` MUST name a floor in `floors`.

### 13.3. Machine allowlists

`identity.machines` is a non-empty array of `{id, tcb_floor?}`. `id` is the submodule's `cvm_identity` value (SEV-SNP `chip_id`, TDX `ppid`, Arm CCA `instance_id`, and for a device the UTF-8 bytes of its `ueid`), 1 to 128 bytes, compared after the hardware chain authenticated it. When the allowlist is present, an identity absent from it is refused with `machine-not-allowed`. A machine that names a `tcb_floor` is held to that floor and every other machine to `default_floor`. An SEV-SNP report endorsed by a VLEK, or whose `CHIP_ID` is all zero (a host that masks the chip identity produces one), identifies no machine and never matches an allowlist entry.

### 13.4. Reference values

| Member | Value |
| --- | --- |
| `reference.launch_measurement` | an array of `{alg, value}` digests; when non-empty the launch measurement MUST equal one of them |
| `reference.registers` | slot (decimal text) to a non-empty array of digests; each named register MUST equal one of them |
| `reference.pcrs` | PCR number 0 to 23 (decimal text) to a non-empty array of digests, for the `vtpm` submodule |
| `reference.slot_owners` | workload slot to the `owner` its claim record MUST name |
| `reference.host_data` | 1 to 48 bytes that `cvm_host_data.value` MUST equal after zero-padding to the platform's length. A pin longer than the platform's field (32 bytes on SEV-SNP) is refused with `reference-mismatch`; on Arm CCA a pin covers the first 48 bytes of the RPV and requires the remaining 16 to be zero |
| `owner.id_key_digests` | SEV-SNP: `ID_KEY_DIGEST` MUST equal one of them |

On SEV-SNP the `cvm_owner` fields are authenticated by the guest owner's ID block only when `ID_KEY_DIGEST` is pinned (`owner.id_key_digests`); without a pin they are host-chosen. Version 1 offers no pin for `AUTHOR_KEY_DIGEST`. On TDX `MROWNER` and `MROWNERCONFIG` are host-set labels.

Reference values come from the image publisher. A publisher SHOULD publish each image's values in two forms that carry the same values: flat JSON as above, and a signed CoRIM (draft-ietf-rats-corim-11) whose CoMID reference-value triples carry the launch measurement in `digests` (measurement-values-map key 2) and register values in `integrity-registers` (key 14), keyed by the slot index as an unsigned integer and typed by Section 6.1's `alg`. A verifier that ingests both treats them as one source.

### 13.5. Device policy

| Member | Default | Meaning |
| --- | --- | --- |
| `gpu.required` | `false` | refuse evidence without a device submodule (`device-required`) |
| `gpu.expected_archs` | absent | the architectures admitted; a device of another is refused (`device-not-allowed`) |
| `gpu.device_policy.allow_debug` | `false` | admit a device whose `dbgstat` is not `disabled` |
| `gpu.device_policy.require_secboot` | `true` | the device token's `secboot` is true |
| `gpu.device_policy.require_nonce_match` | `true` | NRAS's signed nonce-match claim is true. When false, device evidence NRAS could not bind to this nonce is accepted and reported as `ear_all_submods_bound` `"false"`; such evidence can be a replay, and a production policy SHOULD NOT waive the check |
| `gpu.device_policy.require_measres_success` | `true` | the device token's `measres` is `success` |

## 14. Conformance

This section defines verifier conformance. A verifier conforms to this profile when it reproduces the decision of every case of the conformance corpus at the corpus version it declares, and meets the requirements of Sections 4 to 13 and 15.9 that the corpus does not yet cover (`UNCOVERED.md`). The CDDL module constrains shapes, the vectors of Appendix B constrain formulas, and the corpus constrains decisions. An attester conforms when it produces evidence under Sections 4, 5 and 9 that a conforming verifier appraises; a register provider conforms to Sections 7.3 and 8.1 to 8.6. Version 1 publishes no corpus for attesters or register providers.

### 14.1. Layout

```
conformance/
  VERSION            the corpus version
  README.md          how to run the corpus
  UNCOVERED.md       the normative statements that have no case yet
  cases/<id>.json    one case per file
  inputs/            the evidence, policies, collateral and recorded NRAS exchanges the cases reference
```

The corpus is data. Each implementation runs it with its own runner and pins it by the revision it was taken from.

### 14.2. Case format

```
case = {
  "id": text,                         ; kebab-case, unique, never reused
  "rule": { "section": text, "statement": text },
  "now": text,                        ; RFC 3339 UTC: the evaluation time
  "evidence": path,                   ; the evidence envelope, JSON
  ? "policy": path,                   ; absent means the Section 13.1 defaults
  ? "collateral": { * collateral-key => (path / { "body": path, "signing_chain": path }) },
  ? "nras": [ * nras-exchange ],
  "expect": { "appraisal": path } / { "refusal": refusal-code },
}
path = text                           ; relative to conformance/inputs, forward slashes
collateral-key = text                 ; Section 10.3
nras-exchange = { "arch": "HOPPER" / "BLACKWELL" / "LS10", "nonce": text, "response": path, "jwks": path }
```

`rule.section` names the section of this document the case exercises and `rule.statement` states the rule, so a case traces to the text. An input whose path ends in `.gz` is stored gzip-compressed (RFC 1952) and is its decompressed content; only inputs over 1 MiB are compressed.

A case fixes everything a decision depends on:

- `now` is the evaluation time. Every validity window in the appraisal is judged against it. A conforming verifier takes the evaluation time as an input.
- `collateral` is the whole collateral available to the appraisal, each file the artifact's bytes as the source serves them, with signed Intel artifacts carrying their signing chain beside the body. A request for a key the case does not carry fails as unavailable collateral. The envelope's inline endorsements are inputs like any other, and Section 10.2 applies.
- `nras` holds the recorded exchange for each architecture batch: the nonce the verifier will send, NRAS's detached EAT, and the JWKS that verifies it. Nothing in the corpus reaches a network.
- the policy is complete; a case without one runs under the defaults, and its identifier (Section 12.5) is the one the expected appraisal carries.

A case exercises one statement. Where an input cannot avoid breaking several, `rule.statement` names the refusal expected.

### 14.3. Comparison

For `expect.appraisal`, the runner encodes the implementation's appraisal as the JSON of Section 12 and compares it with the expected file as parsed JSON values after removing, from both, the members that are the implementation's own: `iat`; `ear_verifier_id`; `ear_raw_evidence`; `reason` inside every `cvm_collateral` entry. Everything else must be equal. An implementation that emits an extra claim fails the case.

For `expect.refusal`, the runner maps the implementation's error to one code of Section 14.4 and compares codes. An error that maps to no code is no decision and fails the case, as does a refusal with another code, or an appraisal where a refusal was expected, or the reverse.

### 14.4. Refusal codes

A refusal names the rule family that failed:

| Code | Sections | Meaning |
| --- | --- | --- |
| `envelope-invalid` | 3.4, 4, 5.3, 5.4, 6.1, 6.4, 6.5, 8.1, 10.1, 11 step 1 | the envelope, a submodule or a `cvm_*` object breaks a shape, encoding, size, version or consistency rule, including a hint that contradicts the signed report, a backing or source the register's source does not admit, `snp-vmr` registers outside `commitment` mode, envelope values that disagree with each other (a vTPM register and its quoted PCR), and a reserved kind or claim |
| `policy-invalid` | 13 | the policy fails its own validation |
| `platform-unsupported` | 9 | the TEE or hosting is one this verifier does not implement |
| `report-invalid` | 11 step 2 | the hardware report cannot be parsed, or its version is outside the supported range |
| `signature-invalid` | 11 step 3 | a hardware or vendor signature does not verify: the report, the quote, the TPM quote |
| `chain-invalid` | 9.1.4, 9.2.3, 11 steps 3 and 6 | a certificate chain does not reach the pinned root, contradicts the report, or is outside its validity at the evaluation time; a quoting enclave that is not the one Intel's QE Identity names |
| `machine-not-allowed` | 13.3 | the authenticated machine identity is not on the allowlist |
| `guest-policy` | 11 step 4 | a guest policy bit, TD attribute, VMPL, host-requested report, debug state or lifecycle violates policy |
| `binding-mismatch` | 4.1, 5, 9.4, 9.7.2 | the binding of the submodule's mode does not hold (including the HCL report's key binding), the envelope's `eat_nonce` differs from the relying party's nonce, a device token's nonce differs, a key binding the policy requires is absent or different, the certificate pattern without `freshness.key`, or `vtpm-extradata` without a pinned launch measurement |
| `collateral-unavailable` | 10, 11 step 6 | an artifact the policy requires could not be obtained, including an NRAS or JWKS endpoint that cannot be reached and a missing CCA CoRIM |
| `collateral-invalid` | 10, 11 step 6 | an artifact fails its signature, its signing chain, its binding or its window at the evaluation time, or cannot be parsed |
| `revoked` | 11 step 6 | a certificate is revoked |
| `tcb-not-allowed` | 9.2.3, 13.2 | a TCB status outside the allowed set, a TCB value below its floor, a TDX module identity or TCB level that matches no entry, or a QE TCB level the QE Identity revokes or does not list |
| `register-mismatch` | 6.5 | an envelope register differs from the authoritative value |
| `log-required` | 7.4, 8 | a log the mode requires is absent, or `chain_len` and the log disagree |
| `log-invalid` | 7.1 | the log cannot be parsed whole under its format's rules |
| `replay-mismatch` | 7.3, 7.4, 8 | a replay does not reproduce a register that must reproduce, a record digest does not reproduce, a `cvm` event or claim is not deterministically encoded, a slot or `ats` record rule is broken, or chain memory detects a restart or a fork |
| `reference-mismatch` | 13.4 | a pinned launch measurement, register, PCR, host data, owner key or slot owner differs |
| `backing-below-minimum` | 13.1 | a register's backing is below the policy minimum |
| `device-required` | 13.5 | the policy requires a device and the envelope carries none |
| `device-not-allowed` | 13.5 | a device's architecture is outside the allowed set, or the envelope carries more than 32 device submodules |
| `device-token-invalid` | 9.7.2 | NRAS answered with a token the verifier refuses: signature, issuer, claims version, `submods` digest, key identifier, or a token that maps to no device |
| `device-policy` | 9.7.2, 9.7.3, 13.5 | NRAS's overall result is false, the device count differs, a device token is of another architecture, or a device gate failed |
| `unsupported` | 7.1, 7.4, 9.4.4, 9.6.2 | a format or feature this version does not implement: the `aael` log, a log format the submodule does not admit, a TPM bank other than SHA-256, a CCA profile or binding variant outside Section 9.6.2 |

### 14.5. Versioning and change control

The corpus version is `<profile version>.<revision>`, `1.0` at first publication. A change to any case, including a new case, raises the revision. A change that alters a decision in Sections 4 to 13 lands together with the case that shows it. An implementation states the version it passes (for example, "conforms to `tag:confidential.ai,2026:cvm#1`, corpus 1.5") and pins that version in its continuous integration.

The reference implementation generates the expected results (Section 18). A case the reference implementation fails is a defect in the implementation or in the case, and the corpus is corrected first. Where a requirement the corpus does not cover differs from what the reference implementation does, Section 18 lists the difference and the text governs.

## 15. Security considerations

### 15.1. Unprotected evidence

The envelope carries no signature (Section 4.1), so every decision rests on the classification of Section 3.4. A verifier that uses a hint to make a decision, or reads a bound field before binding it, fails open. The profile constrains every hint by the signed field it describes (a register's `backing` by its `source`, `cvm_platform` by the report, `dbgstat` by the debug bit) so that a free choice by the attester never widens what a verifier accepts.

### 15.2. Backing is a floor

A policy states the minimum backing, and the verifier reports the weakest backing it saw. A `kernel-service` or `virtualized` register never satisfies a `hardware` requirement, and a verifier never reports a backing higher than either the evidence's claim or what the verifier established. A relying party that accepts software registers does so by lowering `min_backing` explicitly, and its policy identifier records that choice.

### 15.3. Measurement coverage

Registers record what measured producers extend. Code that runs through a path that extends no register leaves no trace. On every platform this includes guest root executing a program the runtime did not measure, and on SEV-SNP with a register provider root can additionally extend registers (visibly, in the log). The guarantee is therefore "what the sanctioned producers recorded". A deployment that needs "everything that ran" either measures every execution into a slot (an exec hook feeding a register) or removes the paths (no interactive root, no exec outside the measured runtime). `backing` and per-slot `replayed` let a relying party see which it received.

### 15.4. Software registers on SEV-SNP

Section 8's construction is secure against every guest user, root included, when the image satisfies Sections 8.4 to 8.6. It is not secure against code executing in the guest kernel: a kernel exploit can rewrite registers, patch the provider, and compute commitments over fabricated state. This residual is why such registers are never `hardware` and why version 1 reports them as `virtualized` (Section 8.7). The mitigations are the hardening rows of Section 8.6, panic on oops so that attempts stop the node, chain memory (Section 8.8) so that a rewritten history shows as a restart or a fork, and deterministic reference values for images whose register values are known in advance.

The commitment header is pinned in full, so an attacker cannot use its 16 bytes as free choice next to the commitment. The domain tags `ats-anchor-v1`, `ats-mr-v1/seed`, `ats-mr-v1/genesis`, `ats-mr-v1/record` and `ats-mr-v1/commit` separate every hash in this profile from the others and from register values.

### 15.5. Debug and privileged configuration

With the TEE's guest-debug facility enabled, the host reads and writes guest memory and every other claim is meaningless. Verifiers refuse debug by default and check debug, VMPL, TD attributes and lifecycle before any register claim is evaluated. A setting that cannot be checked is treated as unsafe.

### 15.6. Multiple attesters

`ear_all_submods_bound` states that every submodule answered the same nonce. It does not establish that a GPU is physically attached to the CPU that reported it, that the data path between them is protected, or that the devices share a host. An attacker with a genuine GPU elsewhere can answer the same nonce. Device assignment into the TEE's trust boundary (TDISP and its vendor implementations) is out of scope for version 1. A relying party that needs co-location establishes it through the deployment.

### 15.7. Freshness

The nonce is at least 16 bytes and chosen by the relying party. The verifier compares the envelope's nonce with the one the relying party gave it, because an appraisal bound only to the envelope's own nonce accepts a replay. Every comparison of a binding value is constant time over the full field. In the certificate pattern the evidence is as fresh as the certificate: the relying party bounds its age, and the certificate lives no longer than the CVM.

### 15.8. Collateral

The TCB a verifier evaluates is read from the endorsement (the VCEK's extensions, the PCK certificate's) and cross-checked against the report. A TCB Info older than one the verifier has seen can still be inside its validity window; `tcbEvaluationDataNumber` floors close that gap. A verifier prefers its own valid collateral to the attester's (Section 10.2).

### 15.9. Evaluation time

The evaluation time is an input so that decisions are reproducible and conformance is testable. A verifier deployed as a service MUST take the evaluation time from its own clock; accepting it from an untrusted caller lets that caller revive expired collateral. Re-verifying a recorded appraisal with its recorded time and its `ear_raw_evidence` establishes what was decided then; whether it still holds takes a fresh appraisal.

### 15.10. Parsing

Evidence is attacker-controlled. The bounds of Section 4.7 are enforced before a value is buffered; the one-encoding rules close parser differentials in which two implementations read different values from the same bytes; every binary length is converted with overflow checks so that the same bytes parse identically on 32-bit and 64-bit targets; and a binary log parses whole or is refused.

### 15.11. Delegated appraisal

Two parts of the appraisal are delegated. NVIDIA devices are appraised by NRAS, and the verifier relies on NRAS's signed result and device claims; a compromise of NRAS or its signing keys defeats device appraisal. On Azure, the paravisor that hosts the vTPM is part of the trusted computing base: its code is covered by the hardware launch measurement, which a relying party pins, and the vTPM's attestation key is bound by the hardware report (Section 9.4).

### 15.12. Reference values

Reference values carry the security of Section 8.6 and of every launch measurement pin. A relying party obtains them from a source it authenticates (a signed CoRIM, a signed manifest), and any transparency or freshness proof that accompanies them carries an age bound the relying party checks.

### 15.13. Results

An appraisal is a statement by the verifier. Across a trust boundary it is signed or delivered over an authenticated channel (Section 12.1), and the relying party authenticates the verifier. An appraisal's policy identifier tells the relying party which requirements were applied; a relying party that accepts appraisals produced under policies it did not choose accepts those policies.

### 15.14. Settings version 1 does not normalize

Some signed settings are carried in the raw report and neither normalized nor enforced by version 1: on SEV-SNP, `POLICY` bits 21 to 25 (`CXL_ALLOW`, `MEM_AES_256_XTS`, `RAPL_DIS`, `CIPHERTEXT_HIDING_DRAM`, `PAGE_SWAP_DISABLE`) and `PLATFORM_INFO` bits 2 to 7 (`ECC_EN`, `RAPL_DIS`, `CIPHERTEXT_HIDING_DRAM_EN`, `ALIAS_CHECK_COMPLETE`, `IOMMU_WRITE_SAFE`, `TIO_EN`); on TDX, `TEE_TCB_SVN2`. Two of these bear directly on isolation: `ALIAS_CHECK_COMPLETE` reports that the firmware checked the memory configuration for aliased addresses, which defends against memory-aliasing attacks on SEV-SNP integrity, and `CXL_ALLOW` admits CXL-attached memory into the guest. A relying party that depends on them reads them from `ear_raw_evidence` until a later version adds policy members for them.

## 16. Privacy considerations

`cvm_identity` carries stable hardware identifiers: the SEV-SNP chip identifier, the TDX PPID, the Arm CCA instance identifier and the GPU UEID. Each identifies one physical machine or device for its lifetime and can correlate a workload across relying parties and over time. `ear_raw_evidence` carries the same identifiers inside the raw reports and certificates. A verifier SHOULD omit the OPTIONAL `ear_raw_evidence` when the relying party does not need it, and a deployment that forwards appraisals to parties that do not need identity SHOULD remove `cvm_identity` before forwarding; conformance compares appraisals as the verifier produces them. A relying party that keeps appraisals keeps these identifiers with them.

An SEV-SNP host can mask the chip identifier, and the report then carries zeros that identify no machine (Section 13.3). A VLEK, the key a cloud provider holds, removes the chip identifier from the endorsement certificate but leaves it in the report. The identifiers also appear outside `cvm_identity`: in the `snp` compatibility object (`chip_id`) and in the NRAS device claims (`ueid`), so a deployment that removes identity before forwarding removes those as well, and forwards the appraisal outside any signature made over the original.

Event logs record what producers measured: container image digests, configuration digests, and in claim records the producer names. A relying party that receives the log learns the workload's composition. Deployments that treat the composition as confidential deliver evidence only to relying parties entitled to it.

The nonce is chosen by the relying party and carries no information about the attester. Host-set fields (Section 3.5) can carry deployment labels chosen by the host, which a relying party sees.

## 17. IANA considerations

### 17.1. Media types

This document requests registration of the following media types in the vendor tree (RFC 6838 section 3.2). Change controller for all three: Confidential AI, contact mahmoud@confidential.ai.

`application/vnd.confidential-ai.sev-snp-report`

- Type name: application
- Subtype name: vnd.confidential-ai.sev-snp-report
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary
- Security considerations: the content is an AMD SEV-SNP attestation report signed by the AMD Secure Processor; it is authentic only after its signature is verified to AMD's root (Section 9.1 of this document). It contains a stable chip identifier (Section 16).
- Interoperability considerations: the content is exactly 1184 bytes as the firmware produced it
- Published specification: this document, Section 9.1, and AMD's SEV Secure Nested Paging Firmware ABI Specification
- Applications that use this media type: attestation verifiers and attesters for confidential virtual machines
- Fragment identifier considerations: none
- Additional information: magic number none; file extension none
- Intended usage: COMMON
- Restrictions on usage: none

`application/vnd.confidential-ai.tdx-quote`

- Type name: application
- Subtype name: vnd.confidential-ai.tdx-quote
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary
- Security considerations: the content is an Intel TDX quote; it is authentic only after its signature, its quoting enclave report and its PCK chain are verified to Intel's root (Section 9.2). The PCK certificate it embeds identifies the platform (Section 16).
- Interoperability considerations: quote versions 4 and 5
- Published specification: this document, Section 9.2, and Intel's TDX DCAP quote format
- Applications that use this media type: attestation verifiers and attesters for confidential virtual machines
- Fragment identifier considerations: none
- Additional information: magic number none; file extension none
- Intended usage: COMMON
- Restrictions on usage: none

`application/vnd.confidential-ai.pcs-signed+json`

- Type name: application
- Subtype name: vnd.confidential-ai.pcs-signed+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: 8bit; a JSON object (RFC 8259) `{"body": <base64url>, "issuer_chain": <base64url>}`
- Security considerations: `body` is a document signed by Intel PCS and `issuer_chain` the PEM chain that verifies it; the content is authentic only after that signature is verified to Intel's root (Section 10.1)
- Interoperability considerations: the +json suffix applies (RFC 6839)
- Published specification: this document, Section 10.1
- Applications that use this media type: attestation verifiers that carry Intel collateral offline
- Fragment identifier considerations: as for application/json
- Additional information: none
- Intended usage: COMMON
- Restrictions on usage: none

### 17.2. CWT and EAT claims

The profile's claims use CBOR keys in the private-use range of the CWT Claims registry (RFC 8392 section 9.1.1, keys below -65536), listed in Appendix A. No registration is requested for version 1. A later version published through a standards body would request registration of the `cvm_` claims in the CWT Claims and JWT Claims registries and replace the private keys.

### 17.3. CBOR tags

This document defines no CBOR tags. It uses tag 601 (UCCS, RFC 9781). It accepts the Arm CCA token under tags 399 and 907, which are not assigned in the IANA CBOR Tags registry at the time of writing; a verifier accepts exactly those two by allowlist (Section 9.6).

### 17.4. TCG Canonical Event Log content type

The CEL content type `cvm` with value 200 (Section 7.3) is outside the values the TCG CEL specification assigns. A registration request is made to the Trusted Computing Group; until it is granted, 200 is used through the CEL extension socket and a registry assignment would replace it in a new profile version.

### 17.5. EAT profile

The profile identifier `tag:confidential.ai,2026:cvm#1` is a tag URI (RFC 4151) and needs no registration.

## 18. Implementation status

This section records the status of known implementations at the time of writing, in the manner of RFC 7942.

attestation-rs (Confidential AI, Apache-2.0, Rust, native and WebAssembly) is the reference implementation. It generates the expected results of the conformance corpus and passes corpus 1.5 (150 cases), natively and through its WebAssembly entry point. It implements Sections 4 to 7 and 10 to 14 for SEV-SNP (bare metal, GCP, dstack), TDX (bare metal, GCP, dstack), Azure SEV-SNP and TDX, and NVIDIA GPUs and NVSwitch; the `ats-mr-v1` verification of Section 8; the independent generator of the Appendix B vectors; and a CDDL checker for the subset of RFC 8610, RFC 9165 and RFC 9741 that Appendix C uses, with a test that holds the CDDL module, the published JSON Schemas and its parsers to one another on every corpus input.

Not implemented at the time of writing: Arm CCA appraisal (refused with `platform-unsupported`); the SEV-SNP register provider of Section 8, which is a kernel component and exists only as this specification; the CBOR encoding of evidence; `replay_until_event`; appraisal of the standalone `aael` log; chain memory; parsing of the `id-pe-cmw` extension (the certificate pattern works when the relying party supplies the certificate's digest); emitting `ear_raw_evidence`. The library's `appraise` entry takes the envelope's own nonce; its service, CLI and WebAssembly entry points take the relying party's nonce and compare it with `eat_nonce`, as Section 4.1 requires of a verifier, so a program that calls the library directly makes that comparison itself.

Requirements of Section 9 that the reference implementation does not yet enforce, each tracked for correction:

- SEV-SNP: a VEK cross-check failure is refused with `tcb-not-allowed`, and on Turin a VCEK without the FMC extension passes when the report's FMC is 0.
- Azure: the HCL report's variable data is hashed after trailing zero bytes are removed, which agrees with hashing exactly its declared size for every report Azure produces; the SEV-SNP `cpu` report is not compared with the HCL report's hardware area, and the HCL report's hash type is not checked.
- NVIDIA: a device token's architecture is not compared with its batch.
- `cvm` records: `ats` records other than the boot and claim records are not refused.

The corpus does not yet exercise these requirements; `conformance/UNCOVERED.md` lists the statements without a case.

## 19. References

### 19.1. Normative references

- [RFC1952] Deutsch, P., "GZIP file format specification version 4.3", RFC 1952, May 1996.
- [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC3339] Klyne, G. and C. Newman, "Date and Time on the Internet: Timestamps", RFC 3339, July 2002.
- [RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006.
- [RFC5280] Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and W. Polk, "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile", RFC 5280, May 2008.
- [RFC6920] Farrell, S., Kutscher, D., Dannewitz, C., Ohlman, B., Keranen, A., and P. Hallam-Baker, "Naming Things with Hashes", RFC 6920, April 2013.
- [RFC7515] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515, May 2015.
- [RFC7517] Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.
- [RFC7519] Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
- [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- [RFC8392] Jones, M., Wahlstroem, E., Erdtman, S., and H. Tschofenig, "CBOR Web Token (CWT)", RFC 8392, May 2018.
- [RFC8610] Birkholz, H., Vigano, C., and C. Bormann, "Concise Data Definition Language (CDDL): A Notational Convention to Express Concise Binary Object Representation (CBOR) and JSON Data Structures", RFC 8610, June 2019.
- [RFC8785] Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- [RFC8949] Bormann, C. and P. Hoffman, "Concise Binary Object Representation (CBOR)", STD 94, RFC 8949, December 2020.
- [RFC9052] Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and Process", STD 96, RFC 9052, August 2022.
- [RFC9165] Bormann, C., "Additional Control Operators for the Concise Data Definition Language (CDDL)", RFC 9165, December 2021.
- [RFC9334] Birkholz, H., Thaler, D., Richardson, M., Smith, N., and W. Pan, "Remote ATtestation procedureS (RATS) Architecture", RFC 9334, January 2023.
- [RFC9711] Lundblade, L., Mandyam, G., O'Donoghue, J., and C. Wallace, "The Entity Attestation Token (EAT)", RFC 9711, April 2025.
- [RFC9741] Bormann, C., "Concise Data Definition Language (CDDL): Additional Control Operators for the Conversion and Processing of Text", RFC 9741, March 2025.
- [RFC9781] Birkholz, H., O'Donoghue, J., Cam-Winget, N., and C. Bormann, "A Concise Binary Object Representation (CBOR) Tag for Unprotected CBOR Web Token Claims Sets (UCCS)", RFC 9781, May 2025.
- [RFC9782] Lundblade, L., Birkholz, H., and T. Fossati, "Entity Attestation Token (EAT) Media Types", RFC 9782, May 2025.
- [RFC9999] Birkholz, H., Smith, N., Fossati, T., and H. Tschofenig, "Remote ATtestation procedureS (RATS) Conceptual Message Wrapper (CMW)", RFC 9999, July 2026.
- [EAR] Fossati, T., Voit, E., Trofimov, S., and H. Birkholz, "EAT Attestation Results", Work in Progress, Internet-Draft, draft-ietf-rats-ear-04, 26 May 2026.
- [AR4SI] Voit, E., Birkholz, H., Hardjono, T., Fossati, T., and V. Scarlata, "Attestation Results for Secure Interactions", Work in Progress, Internet-Draft, draft-ietf-rats-ar4si-10, 18 May 2026.
- [CCA-TOKEN] Frost, S., Fossati, T., and G. Mandyam, "Arm's Confidential Compute Architecture Reference Attestation Token", Work in Progress, Internet-Draft, draft-ffm-rats-cca-token-04, 7 September 2026.
- [CEL] Trusted Computing Group, "TCG Canonical Event Log Format", Version 1.1, Revision 11, 9 October 2025.
- [PFP] Trusted Computing Group, "TCG PC Client Platform Firmware Profile Specification", Level 00 Version 1.06 Revision 52, 4 December 2023.
- [PTP] Trusted Computing Group, "TCG PC Client Platform TPM Profile Specification for TPM 2.0", Version 1.05 Revision 14, 4 September 2020.
- [TPM2] Trusted Computing Group, "Trusted Platform Module Library, Part 1: Architecture" and "Part 2: Structures", Family 2.0, Level 00 Revision 01.83, 25 January 2024.
- [SNP-ABI] AMD, "SEV Secure Nested Paging Firmware ABI Specification", publication 56860, Revision 1.59, August 2026. Section 7.3, Table 27, and Appendix B.
- [VCEK] AMD, "Versioned Chip Endorsement Key (VCEK) Certificate and KDS Interface Specification", publication 57230, Revision 1.05, September 2026. Section 1.5.
- [TDX-DCAP] Intel, "Intel Trust Domain Extensions Data Center Attestation Primitives (Intel TDX DCAP): Quote Generation Library and Quote Verification Library", Revision 0.91, September 2026; and Intel's quote verification library, intel/confidential-computing.tee.dcap.qvl.
- [TDX-ABI] Intel, "Intel Trust Domain Extensions (Intel TDX) Module Architecture Application Binary Interface (ABI) Reference Specification", document 348551-007, September 2025. Section 3.4.1, Table 3.22.
- [PCK] Intel, "Intel SGX PCK Certificate and Certificate Revocation List Profile Specification", Revision 1.5, 26 January 2022.
- [PCS] Intel, "Intel Provisioning Certification Service for ECDSA Attestation", API version 4.
- [RMM] Arm, "Realm Management Monitor specification", DEN0137, version 1.0-rel0, and version 2.0-bet3 (beta). Section B5.
- [NRAS] NVIDIA, "NVIDIA Remote Attestation Service", API version 4 (Attest GPU V4, `POST /v4/attest/gpu`, and Attest Switch V4, `POST /v4/attest/switch`).
- [FIPS180-4] National Institute of Standards and Technology, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

### 19.2. Informative references

- [RFC4151] Kindberg, T. and S. Hawke, "The 'tag' URI Scheme", RFC 4151, October 2005.
- [RFC6838] Freed, N., Klensin, J., and T. Hansen, "Media Type Specifications and Registration Procedures", BCP 13, RFC 6838, January 2013.
- [RFC6839] Hansen, T. and A. Melnikov, "Additional Media Type Structured Syntax Suffixes", RFC 6839, January 2013.
- [RFC7942] Sheffer, Y. and A. Farrel, "Improving Awareness of Running Code: The Implementation Status Section", BCP 205, RFC 7942, July 2016.
- [RFC8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- [RFC9266] Whited, S., "Channel Bindings for TLS 1.3", RFC 9266, July 2022.
- [CORIM] Birkholz, H., Fossati, T., Deshpande, Y., Smith, N., and W. Pan, "Concise Reference Integrity Manifest", Work in Progress, Internet-Draft, draft-ietf-rats-corim-11, 6 July 2026.
- [TDX-CGPU] Kostal, G., et al., "EAT Attestation Result (EAR) profile for Intel Trust Domain Extensions (TDX) + Confidential GPU (C-GPU) composite attestation", Work in Progress, Internet-Draft, draft-kykdxy-rats-tdx-cgpu-ear-profile-02, 19 July 2026.
- [COMPOSITE] Sun, X., Krishnamurthy, R., and R. Golizadeh Mojarad, "An EAT Profile for Composite Platform Attestation", Work in Progress, Internet-Draft, draft-sun-rats-composite-eat-00, 1 September 2026.
- [TRUSTEE] Confidential Containers, "Trustee", attestation service and key broker service.
- [LOCKDOWN] The Linux kernel, "Kernel lockdown" security module documentation.
- [TSM] The Linux kernel, "Trusted Security Module" report and measurement-register interfaces.

## Appendix A. CBOR claim keys

Profile claims use integer keys in the CWT private-use range (RFC 8392 section 9.1.1, keys below -65536). Standard claims keep their registered keys.

| Claim | Key | Defined in |
| --- | --- | --- |
| `cvm_version` | -70000 | Section 4.1 |
| `cvm_platform` | -70001 | Sections 4.3, 12.2 |
| `cvm_report` | -70002 | Section 4.3 |
| `cvm_binding` | -70003 | Section 5 |
| `cvm_endorsements` | -70004 | Section 10.1 |
| `cvm_registers` | -70005 | Section 6 |
| `cvm_log` | -70006 | Section 7 |
| `cvm_chain` | -70007 | Section 8 |
| `cvm_provenance` | -70008 | reserved, Section 4.3 |
| `cvm_tpm_quote` | -70010 | Section 4.4 |
| `cvm_tpm_ak` | -70011 | Section 4.4 |
| `cvm_launch_measurement` | -70020 | Section 12.2 |
| `cvm_freshness` | -70021 | Section 12.2 |
| `cvm_host_data` | -70022 | Section 12.2 |
| `cvm_owner` | -70023 | Section 12.2 |
| `cvm_policy` | -70024 | Section 12.2 |
| `cvm_tcb` | -70025 | Section 12.2 |
| `cvm_identity` | -70026 | Section 12.2 |
| `cvm_workload_id` | -70027 | reserved, Section 12.2 |
| `cvm_collateral` | -70030 | Section 12.3 |
| `cvm_reference` | -70031 | Section 12.3 |
| `cvm_backing_min` | -70032 | Section 12.3 |

Result claims use the EAR labels of draft-ietf-rats-ear-04: `ear_status` 1000, `ear_trustworthiness_vector` 1001, `ear_raw_evidence` 1002, `ear_appraisal_policy_ids` 1003, `ear_verifier_id` 1004 (`developer` 0, `build` 1), `ear_attester_claims` 1005, `ear_verifier_claims` 1006, `ear_device_topology` 1007 (unused in version 1).

The compatibility claims (the `tdx_*` claims of Section 12.6 and the `snp` object of Section 12.7) keep text keys in both encodings, because the vocabularies they mirror define none. So do `ear_all_submods_bound` and `ear_nvidia_evidence`, which draft-kykdxy-rats-tdx-cgpu-ear-profile-02 defines with JSON names and no CBOR keys. A version 1 verifier ignores `cvm_provenance`, as EAT extensibility requires for a whole claim, and never emits `cvm_workload_id`.

## Appendix B. Test vectors

All values are hexadecimal. The vectors are published machine-readably in `docs/standard/vectors/cvm_profile_vectors.json`, generated by an implementation of the formulas that shares no code with any verifier, and checked against the reference implementation. Reproducing them establishes agreement on the formulas; conformance additionally requires the corpus of Section 14.

Inputs used throughout:

```
nonce              000102030405060708090a0b0c0d0e0f
spki-sha256 value  1111111111111111111111111111111111111111111111111111111111111111
x509-tbs value     2222222222222222222222222222222222222222222222222222222222222222
bootseed           3333333333333333333333333333333333333333333333333333333333333333
```

### B.1. Anchor and device nonces (Sections 5.2 and 5.4)

Without a key, `anchor = nonce`.

With the key `{kind: "spki-sha256", value: 0x11 repeated 32 times}`:

```
input  6174732d616e63686f722d7631 10 000102030405060708090a0b0c0d0e0f
       0b 73706b692d736861323536 0020 1111111111111111111111111111111111111111111111111111111111111111
anchor f98d63e4c2e788b0b92ce5d7d1f2609b191f2933f4e5e7884bfeafc4c7a16ed8e050bf2649e1e85ad4b6c89ae70e35d7
pad64  f98d63e4c2e788b0b92ce5d7d1f2609b191f2933f4e5e7884bfeafc4c7a16ed8e050bf2649e1e85ad4b6c89ae70e35d700000000000000000000000000000000
```

With the key `{kind: "x509-tbs-sha256", value: 0x22 repeated 32 times}`:

```
anchor 6537d4a660c13227cc3c2a54a9d7ba6eef051ab942f0acf1d065ba279f01ab001d309f2dbb8d3c8e8cdc6cf966a45f04
```

NRAS nonces derived from `nonce`:

```
gpu     a5db775022742960966c4ad77b3d903d6645eee00575a557cd18963d31251325
switch  84982aa6b0e69839ac5b84d62d2c16f30239baa2a99add9975d09aa439c47051
```

### B.2. ats-mr-v1 (Section 8.1)

```
seed          60cdcaeac3f15a96cb2a1b85d42c5a4d129fced65435044c9250fdffef98984cc3bd420972c3af58295e0f61ba21e4a7
R[0] genesis  edfcbed49c915465118143bd6ba1980e0fa6ccfe02242bc31676a275e31cd0081c9d8b9ba9d6f4ee70b94b030b1e04fa
R[3] genesis  befc3a5c2b1a1842ea1e7d330a9671c09afa59f2b2e775bd9b77b1a3a89d68e77ea5d2fafe5dfd3767f5ea515c30307a
R[15] genesis ca7955a6100998d9c4771d94e785098d878b66d2956c54a5f47e847694bfd246a251bb1dcd929fd945fa37de37b1c3b2
header16      4154532d4d522d31 01 01 10 00 00000000
```

Commit at genesis: all 16 registers at their genesis values, `chain_len = 0`, `caller_data = pad64(nonce)`:

```
C            22dadccfe3024c6dc4588664a00c9638ce36e10f153cf12a832a023c8f13b011a21e98ba4dab9034d02ddb5d596415c4
report_data  4154532d4d522d310101100000000000 22dadccfe3024c6dc4588664a00c9638ce36e10f153cf12a832a023c8f13b011a21e98ba4dab9034d02ddb5d596415c4
```

One extend with `seq` 0 into slot 3 of the event bytes `a3006373386301706d73746172742d636f6e7461696e65720258300102` (arbitrary bytes, deliberately not a well-formed event and not the boot record Section 8.2 requires at this position: the formulas hash bytes without parsing them, and B.3 gives well-formed records), then a commit with `chain_len = 1` and `caller_data = pad64(anchor)` for the `spki-sha256` key of B.1:

```
d            fd21b47ecf576057b92765553b8e264949fcd74aae46c8cd023a2c34cba68233f765919d4405fdb9b4e5bc25b86235f5
R[3]         0553eb463cfb7cc8d4f0c5ae6d0e6023e6cef8d8624535567757d8b73d9dac8f83d682e26eae16f2a3f8aa23cd86df53
C            7290cc8b8f2476f8565f33573a72c37eb834e96f0684823ea5705a4f78cb734d98171c605eb73c47bdec78526f903101
report_data  4154532d4d522d310101100000000000 7290cc8b8f2476f8565f33573a72c37eb834e96f0684823ea5705a4f78cb734d98171c605eb73c47bdec78526f903101
```

### B.3. Boot and claim records (Sections 7.3, 8.2 and 8.3)

The boot record with `bootseed` above, as record 0 of the log in slot 3 (`seq` 0, `recnum` 0). Its event is the map of three entries: 0 `ats`, 1 `boot`, 2 `SHA-384(bootseed)`, with no content entry:

```
event        a300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2d
d            74eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc
R[3]         fa415452924a55dba8c716598ebfa8abe0808e94cffa6ed4abf28db4c0f18999ffd0f2c14ff2b5b6130a343c63155d69
CEL record   a5 00 00 01 03 03 81 a2 00 0c 01 5830 <d> 09 18c8 0a a2 00 00 01 583f <event>
             a5000001030381a2000c01583074eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc0918c80aa2000001583fa300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2d
```

The claim record for slot 4 with owner `c8s` and purpose `workload`, as record 1 of the log: `seq` 1, and `recnum` 0 as the first record of slot 4. `R[3]` above is genesis(3) extended with the boot record alone, and `R[4]` below is genesis(4) extended with the claim record alone:

```
claim body   a200636338730168776f726b6c6f6164
event        a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164
d            24be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c
R[4]         e314c1b137729a35436b11d4c0b77c17058b210a33c1bbe36a7682f0b222930db389c7dc22868f7bebf75934156a6d34
CEL record   a5 00 00 01 04 03 81 a2 00 0c 01 5830 <d> 09 18c8 0a a2 00 01 01 5852 <event>
             a5000001040381a2000c01583024be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c0918c80aa20001015852a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164
```

The log of those two records as `tcg-cel-cbor` (the CDDL's array: `82`, then the two records) and as `tcg-cel-json`:

```
82a5000001030381a2000c01583074eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc0918c80aa2000001583fa300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2da5000001040381a2000c01583024be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c0918c80aa20001015852a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164
```

```
[{"recnum":0,"pcr":3,"digests":[{"hashAlg":"sha384","digest":"74eac4e31aa02917318e64502f19cac2a9e697616db8d148ba354a1fd8dc18d09badf0d9423a1992bf546665ea9050cc"}],"content_type":"cvm","content":{"seq":0,"event":"a300636174730164626f6f740258300882b143067956839b834603cd65b929551eae6a4aefe361d53937d7f2fcfa43a0b4aaafb3aad845169ab0330f387d2d"}},{"recnum":0,"pcr":4,"digests":[{"hashAlg":"sha384","digest":"24be378097eefe891969c7403ac933f7f79868cb1f373d8590f1f01f8a859909b4f9caa21deb1b255007e1fea1fabe8c"}],"content_type":"cvm","content":{"seq":1,"event":"a400636174730165636c61696d025830f6e17ac51d9c616de63de2dfb5c51361c9695e04df0d04455c20b5c0400bfb486c8d8fcc541b2e30d99474866777ddba0350a200636338730168776f726b6c6f6164"}}]
```

### B.4. Policy identifier (Section 12.5)

The identifier of the default policy. The canonical form is the JCS serialization of the effective default policy; an implementation that fills the defaults of Section 13.1 and serializes with RFC 8785 reproduces it:

```
JCS          {"commitment":{"header16":"QVRTLU1SLTEBARAAAAAAAA","seed":"YM3K6sPxWpbLKhuF1CxaTRKfztZUNQRMklD9_--YmEzDvUIJcsOvWCleD2G6IeSn"},"freshness":{},"gpu":{"device_policy":{"allow_debug":false,"require_measres_success":true,"require_nonce_match":true,"require_secboot":true},"required":false},"min_backing":"hardware","policy_bits":{"allow_debug":false,"allow_migration":false,"allow_service_td":false,"require_sept_ve_disable":true,"require_vmpl0":true,"require_zero_reserved_attributes":true},"reference":{"launch_measurement":[],"pcrs":{},"registers":{},"slot_owners":{}},"tcb":{"floors":{},"require_revocation":true,"require_signed_collateral":true,"tdx_allowed_status":["UpToDate"]}}
SHA-384      a678b73c551d1a00857d906715789f89c0f89683086fe8a28a1dfb537a9271520c121a3da5ca0838fb9e0cc8b3d0dc10
id           ni:///sha-384;pni3PFUdGgCFfZBnFXificD4loMIb-iiih37U3qScVIMEho9pcoIOPueDMiz0NwQ
```

### B.5. dstack runtime events (Section 9.3)

A runtime event (type 0x08000001) with name `app-id` and payload `deadbeef`:

```
name          6170702d6964
payload       deadbeef
v1 digest     67b4be4efed0893cfa2bb1d35dca209ad8348b4c97f980807bcde8b9a0f26398dd0923d6eccb5aa2096d98046da8740f
v2 preimage   7b226e616d65223a226170702d6964222c227061796c6f6164223a226465616462656566222c2274797065223a3133343231373732397d
              {"name":"app-id","payload":"deadbeef","type":134217729}
v2 digest     baf3bcd15a9ffbd5d96a054080db0d029d44a88cdb7ea9f9ca5953bf7a1d8d91f9a16c6de05de1034f41295e8cec53dc
```

The version 1 digest is `SHA-384(01000008 || 3a || name || 3a || payload)`; the version 2 digest is the SHA-384 of the preimage, which the event carries in hexadecimal.

## Appendix C. CDDL module

The wire definition of Sections 4, 12 and 13, as published in `schemas/cvm-profile-v1.cddl`; a test fails when this copy and the file differ. The module uses the subset of RFC 8610, RFC 9165 and RFC 9741 that the reference implementation's CDDL checker implements (Section 18), and the `JC<>` convention of RFC 9711 appendix D, so each rule states both encodings.

```cddl
; CVM attestation profile v1 (tag:confidential.ai,2026:cvm#1): the wire
; definition of docs/standard/cvm-attestation-v1.md, normative for the
; evidence envelope (section 4), the appraisal (section 12) and the verifier
; policy (section 13). Three roots: cvm-evidence, cvm-appraisal, cvm-policy.
;
; JSON is the primary encoding. CBOR carries the same values with the claim
; keys of Appendix A, through the JC<> generic of RFC 9711 appendix D; names
; inside profile objects stay text in both encodings. Byte strings are
; RFC 9741 .b64u text in JSON (strict: URL-safe alphabet, no padding, zero
; trailing bits) and byte strings in CBOR. The policy is a verifier input and
; JSON only.
;
; Rules prefixed eat., ear., ar4si. and cmw. are copied from RFC 9711,
; draft-ietf-rats-ear-04, draft-ietf-rats-ar4si-10 and RFC 9999 with their
; import prefixes, unchanged. A rule is prose when CDDL cannot state it
; (uniqueness, equality between two members, duplicate member names in the
; encoding); section 4.7 states those rules.

; ===================================================================
; Evidence (section 4)
; ===================================================================

cvm-evidence = {
  eat.profile-label ^ => cvm-profile-uri,
  eat.nonce-label ^ => cvm-nonce,
  cvm-version-label ^ => 1,
  eat.submods-label ^ => cvm-submods,
  * unknown-claim
}

cvm-profile-uri = "tag:confidential.ai,2026:cvm#1"

; The relying party's challenge, 16 to 64 bytes (section 4.1).
cvm-nonce = bytes-of<bytes .size (16..64)>

; Unknown claims are ignored, whatever they hold (section 4.7). Every known
; claim is written with a cut (^), so a known name with a wrong value fails
; and is never taken for an unknown claim.
unknown-claim = ( JC<text, (int / text)> => any )

; cpu (exactly one), vtpm (only when the cpu binds through it) and one entry
; per device; at most 66 submodules in all (sections 4.2, 4.7).
cvm-submods = submod-shapes .within ({ 1*66 text => any })

submod-shapes = {
                  "cpu" ^ => cpu-azure,
                  "vtpm" ^ => cvm-vtpm,
                  device-entries,
                }
              / {
                  "cpu" ^ => cpu-direct / cca-token,
                  device-entries,
                }

device-entries = (
  * gpu-name ^ => gpu-device,
  * switch-name ^ => switch-device,
)

; <ueid> is printable ASCII without "/", 1 to 128 characters.
gpu-name = text .regexp "gpu/[!-.0-~]{1,128}"
switch-name = text .regexp "nvswitch/[!-.0-~]{1,128}"
device-ueid = text .regexp "[!-.0-~]{1,128}"

; --- cpu claims sets (section 4.3), one shape per platform and mode ---

; Azure binds through the vTPM's extraData (section 5.4).
cpu-azure = snp-azure / tdx-azure

; Everywhere else the report binds the anchor directly.
cpu-direct = snp-report-data<("bare" / "gcp"), (snp-report-type / tsm-report-type)>
           / snp-report-data<"dstack", snp-report-type>
           / snp-commitment<("bare" / "gcp"), (snp-report-type / tsm-report-type)>
           / snp-commitment<"dstack", snp-report-type>
           / tdx-report-data<("bare" / "gcp"), (tdx-quote-type / tsm-report-type)>
           / tdx-report-data<"dstack", tdx-quote-type>

snp-azure = {
  cvm-platform-label ^ => platform<"amd", "sev-snp", "azure", snp-generation>,
  cvm-report-label ^ => report-record<snp-report-type>,
  cvm-binding-label ^ => cpu-binding<"vtpm-extradata">,
  ? cvm-endorsements-label ^ => snp-endorsements,
  no-snp-registers,
  cpu-hints,
  * unknown-claim
}

snp-report-data<H, R> = {
  cvm-platform-label ^ => platform<"amd", "sev-snp", H, snp-generation>,
  cvm-report-label ^ => report-record<R>,
  cvm-binding-label ^ => cpu-binding<"report-data">,
  ? cvm-endorsements-label ^ => snp-endorsements,
  no-snp-registers,
  cpu-hints,
  * unknown-claim
}

; snp-vmr registers bind only through the commitment (sections 6.5, 8).
; Appraisal requires the log (log-required); the envelope may omit it.
snp-commitment<H, R> = {
  cvm-platform-label ^ => platform<"amd", "sev-snp", H, snp-generation>,
  cvm-report-label ^ => report-record<R>,
  cvm-binding-label ^ => cpu-binding<"commitment">,
  ? cvm-endorsements-label ^ => snp-endorsements,
  cvm-registers-label ^ => [16*16 snp-register],   ; slots 0 to 15, each once
  ? cvm-log-label ^ => cvm-log,
  cvm-chain-label ^ => { "chain_len" ^ => uint .ge 1 },
  eat.boot-seed-label ^ => bytes-of<bytes .size 32>,
  cpu-hints,
  * unknown-claim
}

no-snp-registers = (
  ? cvm-registers-label ^ => absent,
  ? cvm-log-label ^ => absent,
  no-commitment-claims,
)

tdx-azure = {
  cvm-platform-label ^ => platform<"intel", "tdx", "azure", fmspc>,
  cvm-report-label ^ => report-record<tdx-quote-type>,
  cvm-binding-label ^ => cpu-binding<"vtpm-extradata">,
  ? cvm-endorsements-label ^ => tdx-endorsements,
  tdx-registers-and-log,
  no-commitment-claims,
  cpu-hints,
  * unknown-claim
}

tdx-report-data<H, R> = {
  cvm-platform-label ^ => platform<"intel", "tdx", H, fmspc>,
  cvm-report-label ^ => report-record<R>,
  cvm-binding-label ^ => cpu-binding<"report-data">,
  ? cvm-endorsements-label ^ => tdx-endorsements,
  tdx-registers-and-log,
  no-commitment-claims,
  cpu-hints,
  * unknown-claim
}

; A log needs registers to replay into (section 6.1).
tdx-registers-and-log = (
  cvm-registers-label ^ => [1*64 tdx-register],    ; each RTMR at most once
  ? cvm-log-label ^ => cvm-log
  //
  ? cvm-registers-label ^ => absent,
  ? cvm-log-label ^ => absent,
)

no-commitment-claims = (
  ? cvm-chain-label ^ => absent,
  ? eat.boot-seed-label ^ => absent,
)

cpu-hints = (
  ? eat.debug-status-label ^ => eat.debug-status-type,
  ? cvm-provenance-label ^ => any,                 ; reserved, ignored in v1
)

; Matches nothing: the member it types must be absent.
absent = uint .lt 0

; generation, when present, names what the verifier derives from the report
; and must agree with it (section 3.4).
platform<V, T, H, G> = {
  "vendor" ^ => V,
  "tee" ^ => T,
  ? "generation" ^ => G,
  "hosting" ^ => H,
}

snp-generation = "Milan" / "Genoa" / "Turin"

snp-report-type = "application/vnd.confidential-ai.sev-snp-report"
tdx-quote-type = "application/vnd.confidential-ai.tdx-quote"
tsm-report-type = "application/vnd.veraison.tsm-report+json"   ; ingest only

; A CMW record whose indicator is exactly 4, evidence (RFC 9999 section 3.1).
report-record<T> = [ T, bytes-of<field-bytes>, 4 ]

; The certificate pattern binds exactly an x509-tbs-sha256 key; the challenge
; pattern binds no key or an spki-sha256 or raw key (section 5.3).
cpu-binding<M> = {
  "pattern" ^ => "challenge",
  "mode" ^ => M,
  ? "key" ^ => challenge-key
  //
  "pattern" ^ => "certificate",
  "mode" ^ => M,
  "key" ^ => certificate-key,
}

challenge-key = { "kind" ^ => "spki-sha256", "value" ^ => bytes-of<bytes .size 32> }
              / { "kind" ^ => "raw", "value" ^ => bytes-of<bytes .size (0..65535)> }
certificate-key = { "kind" ^ => "x509-tbs-sha256", "value" ^ => bytes-of<bytes .size 32> }
key-binding = challenge-key / certificate-key

; --- registers (section 6) ---

tdx-register = {
  "index" ^ => 0..3,
  "alg" ^ => "sha384",
  "value" ^ => bytes-of<bytes .size 48>,
  "source" ^ => "tdx-rtmr",
  "backing" ^ => "hardware",
}

snp-register = {
  "index" ^ => 0..15,
  "alg" ^ => "sha384",
  "value" ^ => bytes-of<bytes .size 48>,
  "source" ^ => "snp-vmr",
  "backing" ^ => "virtualized" / "kernel-service" / "privileged-service",
}

vtpm-register<A, N> = {
  "index" ^ => 0..23,
  "alg" ^ => A,
  "value" ^ => bytes-of<bytes .size N>,
  "source" ^ => "vtpm-pcr",
  "backing" ^ => "privileged-service",
}

; --- event log (section 7) ---

cvm-log = {
  "format" ^ => "tcg-cel-cbor" / "tcg-cel-json" / "tdx-ccel"
              / "tpm2-event-log" / "dstack-json" / "aael",
  "data" ^ => bytes-of<field-bytes>,
}

; --- endorsements (section 10) ---

snp-endorsements = endorsement-collection<{
  "__cmwc_t" ^ => endorsements-collection-type,
  ? "snp.vek" ^ => endorsement<"application/pkix-cert">,
  ? "snp.crl" ^ => endorsement<"application/pkix-crl">,
  ? "nras.jwks" ^ => endorsement<"application/jwk-set+json">,
}>

tdx-endorsements = endorsement-collection<{
  "__cmwc_t" ^ => endorsements-collection-type,
  ? "tdx.tcb_info" ^ => endorsement<pcs-signed-type>,
  ? "tdx.qe_identity" ^ => endorsement<pcs-signed-type>,
  ? "tdx.pck_crl" ^ => endorsement<"application/pkix-crl">,
  ? "tdx.root_crl" ^ => endorsement<"application/pkix-crl">,
  ? "nras.jwks" ^ => endorsement<"application/jwk-set+json">,
}>

endorsements-collection-type = "tag:confidential.ai,2026:cvm-endorsements#1"

; At least one entry beside __cmwc_t (RFC 9999 section 3.3).
endorsement-collection<M> = M .within ({ "__cmwc_t" => any, + text => any })

; {body, issuer_chain} as JSON, each a .b64u byte string (section 10.1).
pcs-signed-type = "application/vnd.confidential-ai.pcs-signed+json"

; Indicator 2 (endorsements) or 1 (reference values shipped inline).
endorsement<T> = [ T, bytes-of<field-bytes>, 1 / 2 ]

; --- vtpm submodule (section 4.4) ---

; Registers are in the quoted bank, each equal to the quoted PCR of its
; index and inside the quote's signed selection.
cvm-vtpm = vtpm<"sha256", 32> / vtpm<"sha384", 48> / vtpm<"sha512", 64>

vtpm<A, N> = {
  cvm-tpm-quote-label ^ => {
    "message" ^ => bytes-of<field-bytes>,
    "signature" ^ => bytes-of<field-bytes>,
    "pcrs" ^ => [24*24 bytes-of<bytes .size N>],
    "bank" ^ => A,
  },
  cvm-tpm-ak-label ^ => tpm-ak,
  cvm-registers-label ^ => [1*24 vtpm-register<A, N>],
  ? cvm-log-label ^ => cvm-log,
  * unknown-claim
}

tpm-ak = { "method" ^ => "hcl-report", "data" ^ => bytes-of<field-bytes> }

; --- Arm CCA (section 4.6): the token as the RMM emits it ---

cca-token = JC<[ "CBOR", text .b64u field-bytes ], field-bytes>

; --- device submodules (section 4.5) ---

; NVIDIA's device evidence as its SDK exchanges it with NRAS: evidence_b64
; and cert_chain_b64 keep NVIDIA's standard base64 text and are passed to
; NRAS verbatim. uuid equals the <ueid> of the submodule name.
gpu-device = device<("HOPPER" / "BLACKWELL")>
switch-device = device<"LS10">

device<A> = {
  "arch" ^ => A,
  "uuid" ^ => device-ueid,
  "evidence_b64" ^ => text .size (1..1048576),
  "cert_chain_b64" ^ => text .size (1..1048576),
  cvm-binding-label ^ => { "pattern" ^ => "challenge", "mode" ^ => "nras-nonce" },
  * unknown-claim
}

; ===================================================================
; Appraisal (section 12): an EAR draft-ietf-rats-ear-04 claims set
; ===================================================================

cvm-appraisal = {
  eat.profile-label ^ => "tag:ietf.org,2026:rats/ear#04",
  eat.iat-claim-label ^ => ~eat.time-int,
  ear.verifier-id-label ^ => ar4si.verifier-id,
  eat.nonce-label ^ => cvm-nonce,
  ? ear.raw-evidence-label ^ => raw-evidence,
  all-submods-bound-label ^ => "true" / "false",
  eat.submods-label ^ => {
    "cpu" ^ => appraisal<cpu-claims>,
    ? "vtpm" ^ => appraisal<vtpm-claims>,
    * gpu-name ^ => appraisal<device-claims>,
    * switch-name ^ => appraisal<device-claims>,
  },
}

; draft-kykdxy-rats-tdx-cgpu-ear-profile-02 defines this claim with a text
; value and no CBOR key, so its key is text in both encodings. It is "false"
; only for a device whose signed nonce match is false under a policy that
; tolerates it; a binding that fails is otherwise a refusal (section 12.6).
all-submods-bound-label = "ear_all_submods_bound"

; The envelope as appraised and the endorsements used, as a CMW collection
; in a record of type application/cmw+json (section 12.1).
raw-evidence = [ "application/cmw+json", bytes-of<bytes>, ? cmw-ind ]

; ear_status is the worst tier the vector reaches (section 12.4). The two
; policy ids are the profile and the policy's ni name (section 12.5).
appraisal<C> = {
  ear.status-label ^ => ar4si.trustworthiness-tier,
  ear.trustworthiness-vector-label ^ => ar4si.trustworthiness-vector,
  ear.appraisal-policy-ids-label ^ => [ cvm-profile-uri, policy-ni-uri ],
  ear.attester-claims-label ^ => C,
  ear.verifier-claims-label ^ => verifier-claims,
}

; RFC 6920: the SHA-384 of the JCS serialization of the effective policy.
policy-ni-uri = text .regexp "ni:///sha-384;[A-Za-z0-9_-]{64}"

; --- attester claims (section 12.2) ---

cpu-claims = snp-claims / tdx-claims / cca-claims

snp-claims = {
  cvm-platform-label ^ => verified-platform<"amd", "sev-snp", snp-generation>,
  cvm-launch-measurement-label ^ => digest<"sha384", 48>,
  ? cvm-registers-label ^ => [+ verified-register],
  cvm-freshness-label ^ => freshness,
  cvm-host-data-label ^ => { "semantics" ^ => "snp-host-data", "value" ^ => bytes-of<bytes .size 32> },
  cvm-owner-label ^ => {
    "family_id" ^ => bytes-of<bytes .size 16>,
    "image_id" ^ => bytes-of<bytes .size 16>,
    "id_key_digest" ^ => bytes-of<bytes .size 48>,
    "author_key_digest" ^ => bytes-of<bytes .size 48>,
  },
  cvm-policy-label ^ => {
    "debug" ^ => bool,
    "migratable" ^ => bool,
    "smt" ^ => bool,
    "single_socket" ^ => bool,
    "vmpl" ^ => uint .le 255,
  },
  eat.debug-status-label ^ => eat.ds-enabled / eat.disabled-since-boot,
  cvm-tcb-label ^ => {
    "reported" ^ => snp-tcb,
    "committed" ^ => snp-tcb,
    "current" ^ => snp-tcb,
    "launch" ^ => snp-tcb,
  },
  cvm-identity-label ^ => { "chip_id" ^ => bytes-of<bytes .size 64> },
  ? cvm-chain-label ^ => { "chain_len" ^ => uint .ge 1 },
  ? eat.boot-seed-label ^ => bytes-of<bytes .size 32>,
  "snp" ^ => trustee-snp,
}

tdx-claims = {
  cvm-platform-label ^ => verified-platform<"intel", "tdx", fmspc>,
  cvm-launch-measurement-label ^ => digest<"sha384", 48>,
  cvm-registers-label ^ => [+ verified-register],
  cvm-freshness-label ^ => freshness,
  cvm-host-data-label ^ => { "semantics" ^ => "tdx-mrconfigid", "value" ^ => bytes-of<bytes .size 48> },
  cvm-owner-label ^ => {
    "mr_owner" ^ => bytes-of<bytes .size 48>,
    "mr_owner_config" ^ => bytes-of<bytes .size 48>,
  },
  cvm-policy-label ^ => {
    "debug" ^ => bool,
    "migratable" ^ => bool,
    "sept_ve_disable" ^ => bool,
    ? "service_td" ^ => bool,
    "reserved_bits_zero" ^ => bool,
  },
  eat.debug-status-label ^ => eat.ds-enabled / eat.disabled-since-boot,
  cvm-tcb-label ^ => {
    "tee_tcb_svn" ^ => bytes-of<bytes .size 16>,
    "pck_tcb" ^ => bytes-of<bytes .size 16>,
    "pcesvn" ^ => uint .le 65535,
    "fmspc" ^ => fmspc,
    ? "status" ^ => tdx-tcb-status,
    ? "advisories" ^ => [+ text],
  },
  cvm-identity-label ^ => { "ppid" ^ => bytes-of<bytes .size 16> },
  tdx-compat-claims,
}

fmspc = text .regexp "[0-9a-f]{12}"

verified-platform<V, T, G> = {
  "vendor" ^ => V,
  "tee" ^ => T,
  "generation" ^ => G,
  "hosting" ^ => "bare" / "azure" / "gcp" / "dstack",   ; as reported (section 3.4)
}

freshness = {
  "pattern" ^ => "challenge" / "certificate",
  "mode" ^ => "report-data" / "commitment" / "vtpm-extradata" / "cca-challenge" / "nras-nonce",
  ? "key" ^ => key-binding,
  ? "not_before" ^ => rfc3339,
  ? "not_after" ^ => rfc3339,
}

verified-register = verified-register-in<"sha256", 32>
                  / verified-register-in<"sha384", 48>
                  / verified-register-in<"sha512", 64>

verified-register-in<A, N> = {
  "index" ^ => uint .le 65535,
  "alg" ^ => A,
  "value" ^ => bytes-of<bytes .size N>,
  "source" ^ => "tdx-rtmr" / "snp-vmr" / "vtpm-pcr" / "cca-rem",
  "backing" ^ => backing,
  "replayed" ^ => bool,
  ? "owner" ^ => text .size (1..255),
  ? "purpose" ^ => text .size (1..255),
}

digest<A, N> = { "alg" ^ => A, "value" ^ => bytes-of<bytes .size N> }

snp-tcb = {
  "bootloader" ^ => uint .le 255,
  "tee" ^ => uint .le 255,
  "snp" ^ => uint .le 255,
  "microcode" ^ => uint .le 255,
  ? "fmc" ^ => uint .le 255,
}

tdx-tcb-status = "UpToDate" / "SWHardeningNeeded" / "ConfigurationNeeded"
               / "ConfigurationAndSWHardeningNeeded" / "OutOfDate"
               / "OutOfDateConfigurationNeeded" / "Revoked"

; The Confidential Containers Trustee names for an SNP report (section 12.7).
trustee-snp = {
  "policy_abi_major" ^ => uint .le 255,
  "policy_abi_minor" ^ => uint .le 255,
  "policy_smt_allowed" ^ => bool,
  "policy_migrate_ma" ^ => bool,
  "policy_debug_allowed" ^ => bool,
  "policy_single_socket" ^ => bool,
  "reported_tcb_bootloader" ^ => uint .le 255,
  "reported_tcb_tee" ^ => uint .le 255,
  "reported_tcb_snp" ^ => uint .le 255,
  "reported_tcb_microcode" ^ => uint .le 255,
  "platform_tsme_enabled" ^ => bool,
  "platform_smt_enabled" ^ => bool,
  "measurement" ^ => hex48,
  "report_data" ^ => hex64,
  "init_data" ^ => hex32,
  "chip_id" ^ => hex64,
}

; The Intel Trust Authority names for a TD quote (section 12.6).
tdx-compat-claims = (
  "tdx_mrtd" ^ => hex48,
  "tdx_rtmr0" ^ => hex48,
  "tdx_rtmr1" ^ => hex48,
  "tdx_rtmr2" ^ => hex48,
  "tdx_rtmr3" ^ => hex48,
  "tdx_mrconfigid" ^ => hex48,
  "tdx_mrowner" ^ => hex48,
  "tdx_mrownerconfig" ^ => hex48,
  "tdx_td_attributes" ^ => hex8,
  "tdx_tee_tcb_svn" ^ => hex16,
  "tdx_xfam" ^ => hex8,
  "tdx_mrseam" ^ => hex48,
  "tdx_mrsignerseam" ^ => hex48,
)

hex8 = text .regexp "[0-9a-f]{16}"
hex16 = text .regexp "[0-9a-f]{32}"
hex32 = text .regexp "[0-9a-f]{64}"
hex48 = text .regexp "[0-9a-f]{96}"
hex64 = text .regexp "[0-9a-f]{128}"

; Arm CCA (section 9.6): the RIM, the REMs and the RPV from the realm token;
; the implementation, the instance, the lifecycle and the software components
; from the platform token. Version 1 does not replay REMs.
cca-claims = cca-claims-in<"sha256", 32>
           / cca-claims-in<"sha384", 48>
           / cca-claims-in<"sha512", 64>

cca-claims-in<A, N> = {
  cvm-platform-label ^ => verified-platform<"arm", "cca", cca-implementation-id>,
  cvm-launch-measurement-label ^ => digest<A, N>,
  cvm-registers-label ^ => [4*4 cca-register<A, N>],
  cvm-freshness-label ^ => freshness,
  cvm-host-data-label ^ => { "semantics" ^ => "cca-rpv", "value" ^ => bytes-of<bytes .size 64> },
  cvm-policy-label ^ => { "debug" ^ => bool, "migratable" ^ => false },
  eat.debug-status-label ^ => eat.ds-enabled / eat.disabled-since-boot,
  cvm-tcb-label ^ => {
    "lifecycle" ^ => uint .le 65535,
    "sw_components" ^ => [+ cca-sw-component],
  },
  cvm-identity-label ^ => { "instance_id" ^ => bytes-of<bytes .size 33> },
}

cca-implementation-id = text .regexp "[0-9a-f]{64}"

cca-register<A, N> = {
  "index" ^ => 0..3,
  "alg" ^ => A,
  "value" ^ => bytes-of<bytes .size N>,
  "source" ^ => "cca-rem",
  "backing" ^ => "hardware",
  "replayed" ^ => false,
}

; A platform software component (claim 2399), keys as text.
cca-sw-component = {
  ? "component_type" ^ => text,
  "measurement_value" ^ => bytes-of<bytes .size (32..64)>,
  ? "version" ^ => text,
  "signer_id" ^ => bytes-of<bytes .size (32..64)>,
  ? "hash_alg" ^ => text,
}

vtpm-claims = {
  cvm-registers-label ^ => [+ verified-register],
  cvm-freshness-label ^ => freshness,
  cvm-tpm-ak-label ^ => tpm-ak,
}

; NRAS's signed device claims verbatim, with cvm_identity and cvm_tcb beside
; them (section 9.7.3).
device-claims = ear.claims-map-type

; --- verifier claims (section 12.3) ---

verifier-claims = ar4si.non-empty<{
  ? cvm-collateral-label ^ => { + collateral-check => collateral-outcome },
  ? cvm-reference-label ^ => reference-outcome,
  ? cvm-backing-min-label ^ => { "required" ^ => backing, "weakest_seen" ^ => backing },
  ? "ear_nvidia_evidence" ^ => {
    ? "signature_verified" ^ => bool,
    ? "parsed" ^ => bool,
    ? "nonce_match" ^ => bool,
  },
}>

collateral-check = "snp_crl" / "tdx_pck_crl" / "tdx_root_crl"
                 / "tdx_tcb_info" / "tdx_qe_identity" / "nras_jwks" / "cca_corim"

collateral-outcome = {
  "status" ^ => "checked" / "skipped" / "not-applicable",
  ? "reason" ^ => text,
  ? "this_update" ^ => rfc3339,
  ? "next_update" ^ => rfc3339,
  ? "signed" ^ => bool,
}

reference-outcome = ar4si.non-empty<{
  ? "launch_measurement" ^ => bool,
  ? "registers" ^ => { + register-index => bool },
}>

register-index = JC<text .base10 (0..65535), 0..65535>

rfc3339 = text .regexp "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})"

; ===================================================================
; Policy (section 13): a verifier input, JSON only. Every member is optional
; and takes the default shown, and every default fails closed.
; ===================================================================

cvm-policy = {
  ? "reference" ^ => reference-values,
  ? "min_backing" ^ => backing .default "hardware",
  ? "freshness" ^ => { ? "key" ^ => key-binding },
  ? "commitment" ^ => {
    ? "header16" ^ => "QVRTLU1SLTEBARAAAAAAAA",
    ? "seed" ^ => "YM3K6sPxWpbLKhuF1CxaTRKfztZUNQRMklD9_--YmEzDvUIJcsOvWCleD2G6IeSn",
  },
  ? "tcb" ^ => tcb-policy,
  ? "policy_bits" ^ => {
    ? "allow_debug" ^ => bool .default false,
    ? "allow_migration" ^ => bool .default false,
    ? "require_vmpl0" ^ => bool .default true,
    ? "require_sept_ve_disable" ^ => bool .default true,
    ? "require_zero_reserved_attributes" ^ => bool .default true,
    ? "allow_service_td" ^ => bool .default false,
  },
  ? "identity" ^ => { "machines" ^ => [+ machine-entry] },
  ? "owner" ^ => { "id_key_digests" ^ => [+ bytes-of<bytes .size 48>] },
  ? "gpu" ^ => gpu-policy,
}

reference-values = {
  ? "launch_measurement" ^ => [* policy-digest],
  ? "registers" ^ => { * register-index => [+ policy-digest] },
  ? "pcrs" ^ => { * pcr-index => [+ policy-digest] },
  ? "slot_owners" ^ => { * register-index => text .size (1..255) },
  ? "host_data" ^ => bytes-of<bytes .size (1..48)>,
}

pcr-index = text .base10 (0..23)

policy-digest = digest<"sha256", 32> / digest<"sha384", 48> / digest<"sha512", 64>

; A named floor must constrain something; default_floor and every machine's
; tcb_floor name one of the floors.
tcb-policy = {
  ? "floors" ^ => { * text => tcb-floor },
  ? "default_floor" ^ => text,
  ? "tdx_allowed_status" ^ => [+ allowed-tdx-status],   ; default ["UpToDate"]
  ? "require_revocation" ^ => bool .default true,
  ? "require_signed_collateral" ^ => bool .default true,
}

; Revoked can never be allowed.
allowed-tdx-status = "UpToDate" / "SWHardeningNeeded" / "ConfigurationNeeded"
                   / "ConfigurationAndSWHardeningNeeded" / "OutOfDate"
                   / "OutOfDateConfigurationNeeded"

tcb-floor = ar4si.non-empty<{
  ? "snp" ^ => {
    "min" ^ => snp-tcb,
    ? "values" ^ => [1*4 snp-tcb-value],           ; each at most once
  },
  ? "tdx" ^ => {
    ? "min_tee_tcb_svn" ^ => bytes-of<bytes .size 16>,
    ? "min_tcb_evaluation_data_number" ^ => uint .le 4294967295,
  },
}>

snp-tcb-value = "reported" / "current" / "committed" / "launch"

machine-entry = {
  "id" ^ => bytes-of<bytes .size (1..128)>,
  ? "tcb_floor" ^ => text,
}

gpu-policy = {
  ? "required" ^ => bool .default false,
  ? "expected_archs" ^ => [+ ("HOPPER" / "BLACKWELL" / "LS10")],
  ? "device_policy" ^ => {
    ? "allow_debug" ^ => bool .default false,
    ? "require_secboot" ^ => bool .default true,
    ? "require_nonce_match" ^ => bool .default true,
    ? "require_measres_success" ^ => bool .default true,
  },
}

; ===================================================================
; Shared
; ===================================================================

backing = "virtualized" / "kernel-service" / "privileged-service" / "hardware"

; Every byte string field is at most 1 MiB (section 4.7).
field-bytes = bytes .size (1..1048576)

bytes-of<B> = JC<text .b64u B, B>

; RFC 9999: non-zero, and only the five registered bits.
cmw-ind = 1..31

; Appendix A.
cvm-version-label = JC<"cvm_version", -70000>
cvm-platform-label = JC<"cvm_platform", -70001>
cvm-report-label = JC<"cvm_report", -70002>
cvm-binding-label = JC<"cvm_binding", -70003>
cvm-endorsements-label = JC<"cvm_endorsements", -70004>
cvm-registers-label = JC<"cvm_registers", -70005>
cvm-log-label = JC<"cvm_log", -70006>
cvm-chain-label = JC<"cvm_chain", -70007>
cvm-provenance-label = JC<"cvm_provenance", -70008>
cvm-tpm-quote-label = JC<"cvm_tpm_quote", -70010>
cvm-tpm-ak-label = JC<"cvm_tpm_ak", -70011>
cvm-launch-measurement-label = JC<"cvm_launch_measurement", -70020>
cvm-freshness-label = JC<"cvm_freshness", -70021>
cvm-host-data-label = JC<"cvm_host_data", -70022>
cvm-owner-label = JC<"cvm_owner", -70023>
cvm-policy-label = JC<"cvm_policy", -70024>
cvm-tcb-label = JC<"cvm_tcb", -70025>
cvm-identity-label = JC<"cvm_identity", -70026>
cvm-collateral-label = JC<"cvm_collateral", -70030>
cvm-reference-label = JC<"cvm_reference", -70031>
cvm-backing-min-label = JC<"cvm_backing_min", -70032>

; From RFC 9711 section 7.3 and appendix D.
eat.JC<J, C> = eat.JSON-ONLY<J> / eat.CBOR-ONLY<C>
eat.JSON-ONLY<J> = J .feature "json"
eat.CBOR-ONLY<C> = C .feature "cbor"
JC<J, C> = eat.JC<J, C>
eat.time-int = #6.1(int)
eat.nonce-label = eat.JC<"eat_nonce", 10>
eat.debug-status-label = eat.JC<"dbgstat", 263>
eat.profile-label = eat.JC<"eat_profile", 265>
eat.submods-label = eat.JC<"submods", 266>
eat.boot-seed-label = eat.JC<"bootseed", 268>
eat.iat-claim-label = eat.JC<"iat", 6>
eat.debug-status-type = eat.ds-enabled / eat.disabled / eat.disabled-since-boot
                      / eat.disabled-permanently / eat.disabled-fully-and-permanently
eat.ds-enabled = eat.JC<"enabled", 0>
eat.disabled = eat.JC<"disabled", 1>
eat.disabled-since-boot = eat.JC<"disabled-since-boot", 2>
eat.disabled-permanently = eat.JC<"disabled-permanently", 3>
eat.disabled-fully-and-permanently = eat.JC<"disabled-fully-and-permanently", 4>

; From draft-ietf-rats-ear-04 appendix A.
ear.verifier-id-label = eat.JC<"ear_verifier_id", 1004>
ear.raw-evidence-label = eat.JC<"ear_raw_evidence", 1002>
ear.status-label = eat.JC<"ear_status", 1000>
ear.trustworthiness-vector-label = eat.JC<"ear_trustworthiness_vector", 1001>
ear.appraisal-policy-ids-label = eat.JC<"ear_appraisal_policy_ids", 1003>
ear.attester-claims-label = eat.JC<"ear_attester_claims", 1005>
ear.verifier-claims-label = eat.JC<"ear_verifier_claims", 1006>
ear.claims-map-type = eat.JC<ear.claims-map-type-json, ear.claims-map-type-cbor>
ear.claims-map-type-json = {+ text => any}
ear.claims-map-type-cbor = {+ (text / int) => any}

; From draft-ietf-rats-ar4si-10 section 3.
ar4si.trustworthiness-vector = ar4si.non-empty<{
  ? ar4si.instance-identity-label => ar4si.trustworthiness-claim,
  ? ar4si.configuration-label => ar4si.trustworthiness-claim,
  ? ar4si.executables-label => ar4si.trustworthiness-claim,
  ? ar4si.file-system-label => ar4si.trustworthiness-claim,
  ? ar4si.hardware-label => ar4si.trustworthiness-claim,
  ? ar4si.runtime-opaque-label => ar4si.trustworthiness-claim,
  ? ar4si.storage-opaque-label => ar4si.trustworthiness-claim,
  ? ar4si.sourced-data-label => ar4si.trustworthiness-claim,
}>
ar4si.non-empty<M> = M .within ({+ any => any})
ar4si.trustworthiness-claim = -128..127
ar4si.instance-identity-label = eat.JC<"instance-identity", 0>
ar4si.configuration-label = eat.JC<"configuration", 1>
ar4si.executables-label = eat.JC<"executables", 2>
ar4si.file-system-label = eat.JC<"file-system", 3>
ar4si.hardware-label = eat.JC<"hardware", 4>
ar4si.runtime-opaque-label = eat.JC<"runtime-opaque", 5>
ar4si.storage-opaque-label = eat.JC<"storage-opaque", 6>
ar4si.sourced-data-label = eat.JC<"sourced-data", 7>
ar4si.trustworthiness-tier = eat.JC<"none", 0> / eat.JC<"affirming", 2>
                           / eat.JC<"warning", 32> / eat.JC<"contraindicated", 96>
ar4si.verifier-id = {
  ar4si.developer-label => text,
  ar4si.build-label => text,
}
ar4si.developer-label = eat.JC<"developer", 0>
ar4si.build-label = eat.JC<"build", 1>
```

## Appendix D. Examples

The examples abbreviate long byte strings with `...`. Each is complete in the conformance corpus under the path given, together with the policy and collateral that produce the appraisal.

### D.1. SEV-SNP evidence and its appraisal

Evidence from a Genoa guest bound in `report-data` mode, with its VCEK inline (`conformance/inputs/evidence/snp-hardware-affirmed.json`):

```json
{
  "cvm_version": 1,
  "eat_nonce": "aGVsbG8tYXR0ZXN0YXRpb24",
  "eat_profile": "tag:confidential.ai,2026:cvm#1",
  "submods": {
    "cpu": {
      "cvm_binding": {
        "mode": "report-data",
        "pattern": "challenge"
      },
      "cvm_endorsements": {
        "__cmwc_t": "tag:confidential.ai,2026:cvm-endorsements#1",
        "snp.vek": [
          "application/pkix-cert",
          "MIIFPzCCAvOgAwIBAgIBADBB...",
          2
        ]
      },
      "cvm_platform": {
        "hosting": "bare",
        "tee": "sev-snp",
        "vendor": "amd"
      },
      "cvm_report": [
        "application/vnd.confidential-ai.sev-snp-report",
        "BQAAAAAAAAAAAAMAAAAAAAAA...",
        4
      ]
    }
  }
}
```

The appraisal under a policy that requires revocation and holds the machine to a TCB floor (`conformance/inputs/expected/snp-hardware-affirmed.json`). `iat`, `ear_verifier_id` and `ear_raw_evidence` are the verifier's own and are omitted here, as the comparison rules of Section 14.3 omit them:

```json
{
  "ear_all_submods_bound": "true",
  "eat_nonce": "aGVsbG8tYXR0ZXN0YXRpb24",
  "eat_profile": "tag:ietf.org,2026:rats/ear#04",
  "submods": {
    "cpu": {
      "ear_appraisal_policy_ids": [
        "tag:confidential.ai,2026:cvm#1",
        "ni:///sha-384;JlevQJA5Dh..."
      ],
      "ear_attester_claims": {
        "cvm_freshness": {
          "mode": "report-data",
          "pattern": "challenge"
        },
        "cvm_host_data": {
          "semantics": "snp-host-data",
          "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        },
        "cvm_identity": {
          "chip_id": "tfmkyCgOY8l9KI22ZIV33CuE..."
        },
        "cvm_launch_measurement": {
          "alg": "sha384",
          "value": "2ZEro5bOQJwpR4Qdk6UHa2g5..."
        },
        "cvm_owner": {
          "author_key_digest": "AAAAAAAAAAAAAAAAAAAAAAAA...",
          "family_id": "AAAAAAAAAAAAAAAAAAAAAA",
          "id_key_digest": "AAAAAAAAAAAAAAAAAAAAAAAA...",
          "image_id": "AAAAAAAAAAAAAAAAAAAAAA"
        },
        "cvm_platform": {
          "generation": "Genoa",
          "hosting": "bare",
          "tee": "sev-snp",
          "vendor": "amd"
        },
        "cvm_policy": {
          "debug": false,
          "migratable": false,
          "single_socket": false,
          "smt": true,
          "vmpl": 0
        },
        "cvm_tcb": {
          "committed": {
            "bootloader": 10,
            "microcode": 27,
            "snp": 27,
            "tee": 0
          },
          "current": {
            "bootloader": 10,
            "microcode": 27,
            "snp": 27,
            "tee": 0
          },
          "launch": {
            "bootloader": 10,
            "microcode": 27,
            "snp": 27,
            "tee": 0
          },
          "reported": {
            "bootloader": 10,
            "microcode": 27,
            "snp": 27,
            "tee": 0
          }
        },
        "dbgstat": "disabled-since-boot",
        "snp": {
          "chip_id": "b5f9a4c8280e63c97d288db6...",
          "init_data": "000000000000000000000000...",
          "measurement": "d9912ba396ce409c2947841d...",
          "platform_smt_enabled": true,
          "platform_tsme_enabled": false,
          "policy_abi_major": 0,
          "policy_abi_minor": 0,
          "policy_debug_allowed": false,
          "policy_migrate_ma": false,
          "policy_single_socket": false,
          "policy_smt_allowed": true,
          "report_data": "68656c6c6f2d617474657374...",
          "reported_tcb_bootloader": 10,
          "reported_tcb_microcode": 27,
          "reported_tcb_snp": 27,
          "reported_tcb_tee": 0
        }
      },
      "ear_status": "affirming",
      "ear_trustworthiness_vector": {
        "configuration": 2,
        "hardware": 2,
        "runtime-opaque": 2
      },
      "ear_verifier_claims": {
        "cvm_collateral": {
          "snp_crl": {
            "signed": true,
            "status": "checked"
          }
        }
      }
    }
  }
}
```

### D.2. Complete examples per platform

| Platform | Corpus case |
| --- | --- |
| SEV-SNP, bare metal | `snp-hardware-affirmed`, `snp-genoa-report-data`, `snp-crl-checked` |
| TDX, bare metal, CCEL | `tdx-ccel-replays-every-rtmr` |
| TDX, CEL in CBOR and in JSON | `tdx-cel-cbor-replays`, `tdx-cel-json-replays` |
| TDX with Intel collateral and a floor | `tdx-v4-quote-with-fixture-collateral`, `tdx-floor-met` |
| dstack | `dstack-json-replays` |
| Azure SEV-SNP | `azure-snp-through-vtpm`, `azure-snp-pcr8-pinned` |
| Azure TDX | `azure-tdx-through-vtpm` |
| NVIDIA device submodules | `gpu-device-unknown-claim-ignored` (the envelope shape; an appraisal case needs a recorded NRAS exchange) |
| SEV-SNP `commitment` mode | the vectors of Appendix B.2 and B.3 (an appraisal case needs evidence from a register provider) |
| Arm CCA | `cca-nested-token-not-implemented` (the envelope shape) |

## Appendix E. Trust anchors

The roots a verifier pins, with the values the reference implementation pins at the time of writing. A verifier obtains roots from the vendors and SHOULD compare them with these values; a vendor rotation changes them and is announced by the vendor.

| Root | Pinned value |
| --- | --- |
| AMD ARK, Milan | certificate SHA-256 `69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd` |
| AMD ASK, Milan | certificate SHA-256 `67d303bd3905fd38db8b20e0793699870e7fa612eaad5dec358293fd8c0bac1b` |
| AMD ASVK, Milan | certificate SHA-256 `c5e081f59b7efab1fe2f8b505e159704e72f29cab7ef7cf628a05a42439082f5` |
| AMD ARK, Genoa | certificate SHA-256 `4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1` |
| AMD ASK, Genoa | certificate SHA-256 `5464738c1546aed5f2cecf1dc98c5c960a92e8913238a61711bc90ec6e828521` |
| AMD ASVK, Genoa | certificate SHA-256 `197e610743a917d6b9bb982a5a9226ccc0a15b611be0619e626aca9151457372` |
| AMD ARK, Turin | certificate SHA-256 `1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a` |
| AMD ASK, Turin | certificate SHA-256 `5b77ef5fe7a7a004fd9032668fba9d0fda22f88c4442069a479636a6ae3b3185` |
| AMD ASVK, Turin | certificate SHA-256 `104e10a8bd060a3c20a434261a57d0588fd65a88915b4f65b08bdecaf8df1a3c` |
| Intel SGX Root CA | P-256 public key, `x` `0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5`, `y` `67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394` |
| NVIDIA NRAS token signing chain | `SubjectPublicKeyInfo` SHA-256 `fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896`, the key of the "NVIDIA Attestation Service GPU Intermediate 004" certificate (valid until 2029-12-08), which the reference implementation pins as the top of the chain |
| Arm CCA platform vendors | none in common: each vendor's CoRIM signing key (Section 9.6.4) |

## Acknowledgments

The requirements in this document come from the Confidential AI design documents "Standardizing Attestation" and "SEV-SNP Measurement Registers" and from their reviews. The author thanks Amean Asad and Yolan Romailler for the design discussions and reviews this document builds on.
