# CVM Attestation v1: Evidence, Runtime Measurements and Appraisal Results for Confidential Virtual Machines

| | |
| --- | --- |
| Profile | `tag:confidential.ai,2026:cvm#1` |
| Version | 1, draft of 2026-10-01 |
| Conformance corpus | 1.9 |
| Author | Mahmoud Shehata, Confidential AI (mahmoud@confidential.ai) |
| Status | Draft for publication |

## Abstract

Confidential virtual machines (CVMs) on AMD SEV-SNP, Intel TDX and Arm CCA, with or without a cloud paravisor and with or without attached NVIDIA GPUs, each prove their state in a different format and each prove a different set of facts. This document defines one attestation contract that covers all of them. It specifies an evidence envelope that carries the unmodified hardware reports as an Entity Attestation Token (EAT) profile; a single freshness and key-binding rule with one declared binding mode per attester; a runtime measurement register model in which every register carries its hash algorithm, its source and the strength of the mechanism that protects it; one replayable event log encoding based on the TCG Canonical Event Log; a construction that gives SEV-SNP guests extend-only runtime registers bound into hardware-signed reports; a normative verification procedure; attestation results as EAT Attestation Results (EAR) with normalized claims; a verifier policy; and a conformance corpus that turns the verifier's decisions into executable cases, with the statements it does not yet cover listed.

## Status of this document

This is the normative specification of the EAT profile `tag:confidential.ai,2026:cvm#1`. It is a draft published for review and implementation. The machine-readable companions are normative and are published with it: the CDDL module of Appendix C (`schemas/cvm-profile-v1.cddl`), the test vectors of Appendix B (`docs/standard/vectors/cvm_profile_vectors.json`) and the conformance corpus of Section 14 (`conformance/`). Where this text and a companion disagree, the disagreement is a defect in this document or in the companion, and conformance is judged against the corpus until the defect is corrected; where the corpus is silent, this text governs. The JSON Schemas under `schemas/` are informative, and where one admits what the CDDL refuses, the CDDL governs.

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

A workload that relies on attestation, such as a key release service, a TLS client that verifies its peer, or an orchestrator that admits nodes, has to consume and verify evidence from every hardware vendor it runs on. AMD, Intel and Arm define different report formats, and out of the box they prove different things: Intel TDX reports hardware runtime measurement registers, AMD SEV-SNP has none, Arm CCA reports them with a width that follows the hash algorithm the host chose when it created the realm. Cloud providers add a further layer: Microsoft Azure wraps the hardware report behind a paravisor and a virtual TPM, so the freshness challenge lands in a TPM quote and the hardware report binds the TPM's key. Attached GPUs are attested by the GPU vendor's service with its own token format.

Without a common contract, every relying party re-implements vendor-specific checks, and guarantees written against one vendor's fields have to be rebuilt for the next. With this contract, a relying party writes one policy, receives one result format, and reads in that result exactly which facts were established and how strongly each is protected.

### 1.2. Scope

This document covers the following attesters, each specified in Section 9. Section 18 states which of them the reference implementation appraises today.

| Attester | TEE | Hosting | Hardware evidence | Binding mode |
| --- | --- | --- | --- | --- |
| AMD SEV-SNP guest | `sev-snp` | `bare`, `gcp`, `dstack` | SNP attestation report | `report-data` |
| AMD SEV-SNP guest with a register provider | `sev-snp` | `bare`, `gcp`, `dstack` | SNP attestation report whose report data is an `ats-mr-v1` commitment (Section 8.1) | `commitment` |
| Intel TDX guest | `tdx` | `bare`, `gcp`, `dstack` | TD quote, version 4 or 5 | `report-data` |
| Azure SEV-SNP confidential VM | `sev-snp` | `azure` | SNP report inside the HCL report (Section 9.4.1), and a vTPM quote | `vtpm-extradata` |
| Azure TDX confidential VM | `tdx` | `azure` | TD quote over the HCL report's TD report, and a vTPM quote | `vtpm-extradata` |
| Arm CCA realm | `cca` | `bare` | CCA attestation token (platform and realm tokens) | `cca-challenge` |
| NVIDIA Hopper and Blackwell GPUs | device | any | SPDM evidence appraised by NVIDIA NRAS | `nras-nonce` |
| NVIDIA NVSwitch (LS10) | device | any | SPDM evidence appraised by NVIDIA NRAS | `nras-nonce` |

Out of scope for version 1: device assignment through TEE-IO (TDISP, TDX Connect, SEV-TIO), SGX enclaves, live migration of CVMs, availability, microarchitectural side channels, physical attacks, and the build-time supply chain of the measured images (which reference values address, Section 13.4).

### 1.3. Design principles

1. Three messages with three authorities. Evidence is what the attester sends. Policy is what the relying party requires. The appraisal is what the verifier established. A launch measurement in a result is always the value the verifier extracted from a signed report.
2. Only signed or bound bytes decide. Every field of the evidence is classified as signed, bound, hint or reserved (Section 3.4). A hint selects a parser and the combinations Section 4.3 admits, and a hint that contradicts signed data is a refusal.
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
- Offsets in report layouts are byte offsets from the start of the structure. They are hexadecimal with a `0x` prefix in the SEV-SNP and HCL layouts, following AMD's and Microsoft's documents, and decimal in the TDX layouts, following Intel's; lengths are decimal byte counts.
- Hexadecimal byte strings are written in lowercase without separators unless spaces are shown for readability, in which case the spaces are not part of the value.
- CDDL is RFC 8610 with the control operators of RFC 9165 and RFC 9741.

## 2. Terminology

The roles Attester, Verifier, Relying Party, Endorser and Reference Value Provider, and the messages Evidence, Endorsements, Reference Values and Attestation Results, are used as defined in RFC 9334 section 4. In addition:

CVM: a virtual machine whose memory and register state the TEE protects from the host.

Hardware report: the structure the TEE signs: an SNP attestation report, a TD quote, a CCA token.

Launch measurement: the digest the TEE computes over the initial contents of the CVM before it runs: SNP `MEASUREMENT`, TDX `MRTD`, CCA Realm Initial Measurement (RIM).

Measurement register (register): an extend-only value that can only be changed by extending it, `R' = H(R || d)`, where `d` is the digest of what is being recorded.

Slot: the index of a register within its source.

Source: the mechanism that holds a register: `tdx-rtmr`, `snp-vmr`, `vtpm-pcr`, `cca-rem` (Section 6.2).

Backing: the strength of the mechanism that protects a register against modification by code inside the CVM (Section 6.4).

Event log: the ordered records of what was extended into registers. Replay recomputes the registers from the log.

Measured producer: software, itself covered by a measurement, that extends registers and appends log records.

Register provider: the component that holds software registers and computes the commitment on SEV-SNP (Section 8).

Anchor: the binding input that combines the nonce with an optional key. The attester and the verifier derive it with the same formula (Section 5.2).

Binding mode: where and how an attester's evidence binds the anchor (Section 5.4).

Paravisor: a privileged layer inside the CVM, below the guest operating system, that on Azure holds the vTPM and its attestation key.

HCL report: the structure the Azure paravisor (its host compatibility layer) produces, carrying the hardware report and the vTPM's attestation key (Section 9.4.1).

dstack: an open-source CVM framework whose guests extend RTMR 3 and keep a JSON event log of what they extended (Section 9.3).

Submodule: one attester's claims inside the evidence envelope, in the sense of RFC 9711 section 4.2.18.

Collateral: the endorsements a verifier needs besides the evidence: certificates, certificate revocation lists, TCB status documents, token signing keys.

Evaluation time: the instant against which the verifier judges every validity window. It is an input to the appraisal (Sections 11 and 15.9).

Refusal: the outcome of an appraisal that fails; it carries one refusal code (Section 14.4).

## 3. Architecture

### 3.1. Roles

| Role | In this profile |
| --- | --- |
| Attester | an agent inside the CVM that collects the hardware report and builds the envelope; the TEE firmware that signs the report; the paravisor's vTPM on Azure; the Realm Management Monitor (RMM) for Arm realms; each NVIDIA GPU and NVSwitch |
| Verifier | a library or service that implements Section 11; for NVIDIA devices, the NVIDIA Remote Attestation Service (NRAS) is a verifier whose results this verifier appraises (Section 9.7) |
| Relying party | the party that consumes the appraisal, and in the challenge pattern issues the nonce |
| Endorser | AMD Key Distribution Service (KDS), Intel Provisioning Certification Service (PCS), NVIDIA for the NRAS token signing keys, the Arm CCA platform vendor's verification service, the cloud provider for paravisor-held keys |
| Reference value provider | the publisher of the measured image, which publishes launch measurements and expected register values (Section 13.4) |

### 3.2. Message flow

```
 Relying party                 Attester (inside the CVM)             Verifier
      |                                  |                              |
      |------ nonce (16 to 64 bytes) --->|                              |
      |                                  | hardware reports bound to    |
      |                                  | the anchor (Section 5)       |
      |<-- Evidence (Section 4) ---------|                              |
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
| Which image launched | `cvm_launch_measurement` | signed by the TEE; matched against reference values |
| What ran after launch | `cvm_registers`, each with `backing` and `replayed` | only what measured producers recorded (Section 15.3) |
| Is the evidence fresh | `cvm_freshness` | the binding of Section 5 passed |
| Is the hardware genuine, and is its firmware acceptable | `hardware` in the trustworthiness vector, `cvm_tcb`, `cvm_collateral` | chain to the vendor root; TCB against named floors |
| Is guest debug off, and are the other security settings acceptable | `cvm_policy`, `dbgstat`, `configuration` in the vector | debug is refused by default |
| Which machine is this | `cvm_identity`, `instance-identity` in the vector | authenticated by the hardware chain; an SEV-SNP report under a VLEK or with a masked `CHIP_ID` identifies no machine (Section 13.3) |
| Which host-set labels were present | `cvm_host_data` | a label, Section 3.5 |
| Did every attester answer this challenge | `ear_all_submods_bound` | same nonce; it does not prove co-location (Section 15.6) |

A relying party that needs a single decision uses this rule: the appraisal is acceptable when `ear_all_submods_bound` is `"true"`, the `cpu` submodule and every device submodule have `ear_status` `affirming` (or `warning`, where the relying party accepts the vendor-reported vulnerabilities its policy admitted), the `vtpm` submodule, when present, has `affirming` or `none` (the latter when the policy pins no PCR), and the policy identifier in `ear_appraisal_policy_ids` is one the relying party recognizes. A `contraindicated` submodule, which debug and an SEV-SNP VMPL other than 0 produce (Section 12.4), is never acceptable under this rule. The profile defines no separate boolean because a boolean detached from the policy that produced it does not say which requirements were met: a genuine report can still describe an image or a firmware version the relying party does not accept.

### 3.4. Trust boundary inside the evidence

The envelope is unprotected (Section 4.1). Every field is one of:

- signed: bytes covered by a hardware or vendor signature: the SNP report, the TD quote, the HCL report's hardware report, the TPM quote, the CCA tokens, and the device evidence, whose SPDM signatures NRAS verifies and answers with signed tokens (Section 9.7);
- bound: fields the verifier checks against signed bytes before use: registers against the report, the quote or the commitment; the log against the registers; the nonce against its binding; endorsements against pinned roots;
- hint: every other field. A hint selects a parser, and `hosting` also selects which report types and binding modes are admitted (Section 4.3); a hint never raises what a verifier concludes, because every admitted combination is verified in full;
- reserved: `cvm_provenance`, which a version 1 verifier ignores whatever it holds (Section 4.3).

`cvm_platform` is a hint. The verifier MUST re-derive the vendor, the TEE and the generation from signed data (Section 9) and MUST refuse evidence whose hint contradicts them. `hosting` cannot be derived from signed data, so every path it admits is verified in full on its own terms: in particular `azure` admits `vtpm-extradata`, whose freshness rests on the paravisor, and a verifier therefore refuses that mode unless the policy pins the launch measurement that establishes the paravisor (Section 9.4.4). `commitment` rests on the register provider in the same way, and is refused under the same condition (Section 8.7). A verifier that reads `cvm_registers[].value` without binding it has a fail-open defect by definition.

### 3.5. Host-set fields

Each TEE lets the host place a value in the signed report at launch that the launch measurement does not cover: SNP `HOST_DATA` (32 bytes), TDX `MRCONFIGID` (48 bytes), CCA Realm Personalization Value (RPV, 64 bytes). The host can choose a different value on every launch, so on its own such a field is a label, and the profile reports it as `cvm_host_data` with explicit semantics. Other signed fields are host-set in the same way and are reported in `cvm_owner`: TDX `MROWNER` and `MROWNERCONFIG`, and the SEV-SNP ID block fields, which establish something only when the policy pins the ID key that signs them (Section 13.4).

A host-set field becomes a guarantee when the measured image contains code that enforces a relationship with it: for example, a guest that refuses to start unless `HOST_DATA` equals the digest of the configuration it loads. Only then does pinning it (`reference.host_data`, Section 13.4) establish something about the workload, and the guarantee rests on the launch measurement pin that establishes the enforcing code.

## 4. Evidence

### 4.1. Envelope

Evidence is an EAT claims set (RFC 9711) under the profile `tag:confidential.ai,2026:cvm#1`, carried unprotected: as a UJCS in JSON and as a UCCS (CBOR tag 601) in CBOR (RFC 9781). On the wire it is labeled with the media types of RFC 9782:

```
application/eat-ucs+json; eat_profile="tag:confidential.ai,2026:cvm#1"
application/eat-ucs+cbor; eat_profile="tag:confidential.ai,2026:cvm#1"
```

The envelope carries no signature of its own. Every byte a verifier relies on is signed by the TEE, a vendor service or the vTPM, or is bound by the verifier to such bytes (Section 3.4). A signature by a key inside the guest would add nothing a verifier could rely on beyond what those signatures already establish.

RFC 9781 section 4 premises the RATS use of unprotected claims sets on a secure channel in which the receiver authenticates the sender and the channel protects integrity. This profile departs from that premise: it relies on no property of the channel that carries the envelope, because every value an appraisal decides on is signed or bound (Section 3.4). RFC 9781 section 7 requires such a use to define the roles of its endpoints and its security argument; Section 3 and this section are that definition.

Top-level claims:

| Claim | CBOR key | Requirement | Value |
| --- | --- | --- | --- |
| `eat_profile` | 265 | MUST | `tag:confidential.ai,2026:cvm#1` |
| `eat_nonce` | 10 | MUST | the nonce, a byte string of 16 to 64 bytes: the relying party's in the challenge pattern, the attester's in the certificate pattern (Section 5.1) |
| `cvm_version` | -70000 | MUST | the integer 1 |
| `submods` | 266 | MUST | the submodules of Section 4.2 |

In JSON, `eat_nonce` is the base64url text (Section 4.7) of the 16 to 64 byte nonce, a narrowing of RFC 9711's text form; the anchor and every binding use the decoded bytes. The array form of RFC 9711 section 4.1 is refused.

A verifier MUST refuse an envelope with another `eat_profile` or another `cvm_version`, and MUST refuse an envelope whose `eat_nonce` differs from the nonce the relying party supplied to it. Other top-level claims are ignored, whatever they hold.

### 4.2. Submodules

`submods` maps names to attester claims sets. Names are drawn from these forms and no other:

| Name | Count | Contents |
| --- | --- | --- |
| `cpu` | exactly one | the CPU TEE's claims (Section 4.3), or for Arm CCA the nested token (Section 4.6) |
| `vtpm` | present exactly when the `cpu` submodule's binding mode is `vtpm-extradata` | the vTPM's claims (Section 4.4) |
| `gpu/<ueid>` | zero or more | one NVIDIA GPU (Section 4.5) |
| `nvswitch/<ueid>` | zero or more | one NVIDIA NVSwitch (Section 4.5) |

`<ueid>` is the device's identifier as the NVIDIA SDK reports it: 1 to 128 printable ASCII characters (0x21 to 0x7E) excluding `/`. A verifier refuses an envelope with more than 66 submodules with `envelope-invalid` while parsing it (Section 4.7), and a well-formed envelope with more than 32 device submodules with `device-not-allowed`. A verifier MUST refuse an envelope with an unknown name, without a `cpu` submodule, with a `vtpm` submodule whose `cpu` does not bind through it, or with a `cpu` bound through `vtpm-extradata` and no `vtpm`.

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

`cvm_tpm_quote.message` is the marshaled `TPMS_ATTEST` structure the TPM signed, `signature` the signature value over it (for the RSA attestation key of Section 9.4, the `sig` buffer of the `TPMS_SIGNATURE_RSA` without its size prefix, an RSASSA-PKCS1-v1_5 signature), `pcrs` the 24 PCR values of the quoted bank in PCR order, and `bank` the bank's TPM algorithm name (`sha256`, `sha384` or `sha512`, Section 6.1). Version 1 appraises only the `sha256` bank (Section 9.4.3). `cvm_tpm_ak.method` is `hcl-report` and `data` is the Azure HCL report that carries the attestation key and binds it to the hardware report (Section 9.4).

Each register's `alg` MUST be the quoted bank, its `index` a PCR inside the quote's signed selection, its `value` equal to the entry of `pcrs` at that index, its `source` `vtpm-pcr` and its `backing` `privileged-service`. Each index appears at most once.

### 4.7. Encoding rules

JSON (the primary encoding):

- Claim names are text; profile claims carry the `cvm_` prefix.
- Byte strings are base64url (RFC 4648 section 5) without padding and with zero trailing bits (RFC 4648 section 3.5), which is the strict `.b64u` of RFC 9741. A verifier MUST refuse the standard alphabet, padding and non-zero trailing bits.
- Integers are JSON numbers. No profile claim holds a floating-point value. Integers are written without a fraction or an exponent (`1`, never `1.0` or `1e0`), are at most 2^64 - 1, and are exact: an implementation parses the 64-bit members (`chain_len`, `seq`, `recnum`) without loss.
- Each value has exactly one encoding. An object with a duplicate member name is refused, in the envelope, in every `cvm_*` object and in every CMW collection. `null` is not a value: an optional member is absent or holds its type. An object is written as an object, never as the array of its members, and an enumerated value is its text, never an object naming it. An implementation whose JSON library admits any of these (keeping the last duplicate, reading `null` as absent, reading a struct from an array) MUST refuse them itself.
- Unknown claims at the top level and in a submodule claims set, device submodules included, are ignored whatever they hold, as EAT extensibility requires. An unknown member inside any `cvm_*` object is refused. `cvm_provenance` is reserved and exempt from both rules: its value is ignored whatever it holds.
- A CMW record's indicator, where this document does not fix it, is 1 to 31 (RFC 9999 section 3.1).

Bounds. A verifier refuses input that exceeds these bounds, and checks each bound before it parses the input the bound covers: the whole envelope is at most 10 MiB (10485760 bytes); JSON is nested at most 32 levels deep, where each array and each object counts one level and the envelope's top-level object is level 1; at most 66 submodules; a CMW collection has at most 32 entries and one level of nesting; every byte string field is at most 1 MiB (1048576 bytes) after decoding. The nesting bound applies to unknown claims too, so that an ignored claim cannot exhaust a recursive parser.

CBOR: claim keys are the integers of Appendix A; names inside profile objects stay text; byte strings are byte strings; every map and string has a definite length; every object the attester produces uses deterministic encoding (RFC 8949 section 4.2.1). A verifier MUST refuse a CBOR envelope that is not a claims set under UCCS tag 601, that uses an indefinite length, that has a duplicate map key, or that is not in deterministic encoding, and a `cvm_report` or `cvm_endorsements` record whose `type` is a CoAP content-format integer (the CCA token's own records, inside its bytes, keep theirs); the same one-encoding rule as JSON applies, so that two verifiers cannot read different claims from the same bytes.

### 4.8. EAT profile checklist

RFC 9711 section 6.3 lists the decisions a profile makes. For this profile:

| Item | Decision |
| --- | --- |
| 6.3.1 JSON, CBOR or both | both; JSON is primary; CBOR uses the keys of Appendix A |
| 6.3.2 map and array encoding | definite lengths only |
| 6.3.3 string encoding | definite lengths only |
| 6.3.4 preferred serialization | deterministic encoding (RFC 8949 section 4.2.1) for every CBOR object the attester produces |
| 6.3.5 CBOR tags | UCCS tag 601 when a CBOR envelope is written; no tags in JSON apart from those inside the bytes of a nested CCA token (Section 4.6) |
| 6.3.6 COSE/JOSE protection | none at the envelope; Section 4.1 states the argument |
| 6.3.7 COSE/JOSE algorithms | inherited from each hardware report; the profile adds SHA-384 for registers, the anchor and the commitment, and SHA-256 for the `spki-sha256` and `x509-tbs-sha256` key values, the vTPM key binding and the NRAS nonce |
| 6.3.8 detached EAT bundle support | not used in version 1 |
| 6.3.9 key identification | per submodule: VCEK or VLEK for SNP; the PCK chain for TDX; the HCL attestation key for the vTPM; the CCA platform and realm attestation keys; the NRAS key identifier (`kid`) |
| 6.3.10 endorsement identification | inline in `cvm_endorsements` or fetched by the verifier, anchored to pinned roots either way (Section 10) |
| 6.3.11 freshness | `eat_nonce` at the top, bound per submodule in a declared mode (Section 5) |
| 6.3.12 claims requirements | Sections 4.1 to 4.6 |

## 5. Freshness and binding

### 5.1. Patterns

`cvm_binding.pattern` names how the nonce was chosen:

- `challenge`: the relying party chose `eat_nonce` for this exchange. This is the pattern for every exchange with a live peer.
- `certificate`: the evidence is bound to an X.509 certificate (RFC 5280) that lives for the CVM's lifetime, as in attested TLS. The attester chose `eat_nonce` when it created the certificate, and binds the certificate through a key of kind `x509-tbs-sha256` (Section 5.3). The evidence is as fresh as the certificate: the relying party MUST check the certificate's validity window, and SHOULD refuse a certificate whose `notBefore` is older than the evidence age it accepts. A version 1 verifier receives the certificate's digest (Section 5.5), and MUST NOT emit `not_before` or `not_after`; the members are defined for verifiers that receive the certificate itself.

A device submodule always declares `challenge`, because the device protocol takes a nonce on every exchange; the nonce it answers is the envelope's, whichever party chose it (Section 4.5).

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
| `report-data` | SEV-SNP without a register provider, and TDX, on any hosting other than `azure` | the report's 64-byte report data equals `pad64(anchor)` |
| `commitment` | SEV-SNP with a register provider | the report data equals `header16 \|\| C` of Section 8.1, with `caller_data = pad64(anchor)` |
| `vtpm-extradata` | Azure SEV-SNP and TDX | the TPM quote's `extraData` equals `anchor`, and the hardware report binds the quote's key (Section 9.4) |
| `cca-challenge` | Arm CCA | the realm token's challenge equals `pad64(anchor)` |
| `nras-nonce` | NVIDIA GPUs and NVSwitch | the device's SPDM nonce equals `SHA-256(nonce \|\| "NVIDIA-GPU-EAT-v1")` for a GPU and `SHA-256(nonce \|\| "NVIDIA-SWITCH-EAT-v1")` for an NVSwitch |

`extraData` is a `TPM2B_DATA`, which holds at most `sizeof(TPMT_HA)` bytes: 50 on a vTPM whose largest digest is SHA-384. An unkeyed nonce bound in `vtpm-extradata` mode is therefore 16 to 50 bytes, and a keyed anchor (48 bytes) always fits. The `nras-nonce` rule binds the nonce itself and ignores the key, because NRAS derives the device challenge from a nonce it is given. Device evidence therefore carries no key binding; it answers the same nonce as the `cpu` submodule, which is all `ear_all_submods_bound` states (Section 15.6).

The mode is constrained by the platform (Section 4.3): a verifier MUST refuse a mode that the TEE and hosting do not admit.

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

Each `(source, index)` appears at most once. `alg` is pinned per source: `sha384` for `tdx-rtmr` and `snp-vmr`; the quoted bank for `vtpm-pcr`; the realm hash algorithm for `cca-rem` (`sha256` or `sha512` under RMM 1.0, and also `sha384` under RMM 2.0). The array is REQUIRED whenever `cvm_log` is present, so that a verifier without support for a log format can still pin register values.

### 6.2. Sources and index spaces

| Source | Index | Width (bytes) | Held by |
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

On `snp-vmr` the register provider starts with the guest kernel, so firmware cannot extend slots 0 to 2: they hold what the kernel records into them, and otherwise stay at genesis.

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

`event` is the deterministic CBOR encoding (RFC 8949 section 4.2.1) of the map `{0: domain (tstr), 1: operation (tstr), 2: content_digest (bstr), 3: content (bstr, OPTIONAL)}`, with `domain` and `operation` each 1 to 255 bytes of UTF-8. `content_digest` is 48 bytes. A verifier refuses with `replay-mismatch` an `event` that is not deterministically encoded, carries a duplicate or unknown key, has trailing bytes, or has a `domain` or `operation` outside 1 to 255 bytes, because such bytes do not authenticate one reading. The meaning of `content_digest` belongs to the producer, except in the records of Section 8.2 and 8.3, where it is fixed. The digest extended into the register is:

```
d = SHA-384("ats-mr-v1/record" || u64le(seq) || u16le(pcr) || event)
```

In CEL-CBOR a record is `{0: recnum, 1: slot, 3: [{0: 12, 1: d}], 9: 200, 10: {0: seq, 1: event}}`, with `event` stored as the exact bytes that were hashed; in CEL-JSON it is `{"recnum", "pcr", "digests", "content_type": "cvm", "content": {"seq", "event": hex}}`. The order across registers lives in the content because CEL keeps `recnum` per index (CEL section 4.2.2) and requires a record to carry what its digest covers (CEL section 4.2.1.2), and leaves how a digest derives from content to the content type (CEL section 4.2.5).

Domain `ats` is reserved for this profile's own records. In any log, a `cvm` record in domain `ats` is refused with `replay-mismatch` unless it is the boot record of Section 8.2 (record 0, in slot 3, without `content`) or, in a `commitment` log, a claim record of Section 8.3.

CEL v1.1 Table 2 assigns content types 4, 5 and 7 to 9, reserves 6 and 10, and defines no private range. The value 200 is taken through the `$TPMS_CEL_EVENT-extension` socket that the CEL CDDL provides; Section 17.4 records the registration request. Vectors are in Appendix B.3.

### 7.4. Replay

The verifier replays every register a log covers, from that register's starting value, and marks each register `replayed: true` or `replayed: false` in the result. Without a log, every register is reported with `replayed` false.

- A register the log extends is replayed when its records, extended in order from the starting value, reproduce the authoritative value of Section 6.5. For `tcg-cel-cbor`, `tcg-cel-json`, `dstack-json` and `tpm2-event-log`, every register the log extends MUST reproduce, and one that does not is refused with `replay-mismatch`. For `tdx-ccel`, RTMR 0 to 2 MUST reproduce, and RTMR 3 is reported with `replayed` false when it does not, because agents that extend RTMR 3 after boot do not all append to the CCEL.
- A register the log never extends is replayed exactly when it still holds its starting value, since the log then accounts for every extend into it.
- Starting values: zero for an RTMR and a REM; for a PCR the PC Client starting value (PCRs 17 to 22 all ones; PCR 0 at the locality of a `StartupLocality` event, otherwise zero; every other PCR zero); for an `snp-vmr` slot its genesis value (Section 8.1).
- `EV_NO_ACTION` records are skipped. A `tpm2-event-log` is replayed in the quoted bank, which version 1 requires to be SHA-256 (Section 9.4.3).
- A `cvm` record is replayed by requiring `seq` to count the log's `cvm` records from 0 without a gap and `recnum` to count its slot's records from 0 without a gap, recomputing `d` from `seq`, the record's index and the stored `event` bytes, requiring it to equal the recorded digest, and extending it. A record that breaks any of these is refused with `replay-mismatch`. The verifier never re-encodes content.
- dstack runtime events are replayed with the digest rules of Section 9.3, from zero, as `R = SHA-384(R || digest)`.

`replay_until_event`, under which the verified value would be the replay up to and including a named record, and a policy naming the slots that must replay, are not defined in version 1.

On an SNP `cpu` submodule in `commitment` mode the log is REQUIRED (refused with `log-required` when absent or in a format the mode does not admit), every record MUST have content type `cvm` (refused with `replay-mismatch` otherwise), `chain_len` MUST equal the number of records (refused with `log-required` otherwise), and Section 8 governs the replay from genesis.

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
| 0x048 | 4 | `KEY_INFO` | bit 0 `AUTHOR_KEY_EN`; bit 1 `MASK_CHIP_KEY`, MUST be 0; bits 4:2 `SIGNING_KEY`: 0 VCEK, 1 VLEK, every other value refused; bit 5 reserved, not checked; bits 31:6 MUST be zero |
| 0x050 | 64 | `REPORT_DATA` | the binding (Section 9.1.6) |
| 0x090 | 48 | `MEASUREMENT` | `cvm_launch_measurement`, `alg` `sha384` |
| 0x0C0 | 32 | `HOST_DATA` | `cvm_host_data`, semantics `snp-host-data` |
| 0x0E0 | 48 | `ID_KEY_DIGEST` | `cvm_owner.id_key_digest`; `owner.id_key_digests` |
| 0x110 | 48 | `AUTHOR_KEY_DIGEST` | `cvm_owner.author_key_digest` |
| 0x140 | 32 | `REPORT_ID` | chain memory (Section 8.8); not reported |
| 0x180 | 8 | `REPORTED_TCB` | `cvm_tcb.reported`; VEK selection and cross-check |
| 0x188 | 1 | `CPUID_FAM_ID` | generation, versions 3 and later |
| 0x189 | 1 | `CPUID_MOD_ID` | generation, versions 3 and later |
| 0x1A0 | 64 | `CHIP_ID` | `cvm_identity.chip_id`; VCEK cross-check |
| 0x1E0 | 8 | `COMMITTED_TCB` | `cvm_tcb.committed` |
| 0x1F0 | 8 | `LAUNCH_TCB` | `cvm_tcb.launch` |
| 0x2A0 | 512 | `SIGNATURE` | `R` at 0x2A0 and `S` at 0x2E8, each 72 bytes |

A violation of the `SIGNATURE_ALGO` or `KEY_INFO` rows is refused with `report-invalid`. A verifier also refuses with `report-invalid` a report with a non-zero byte in a reserved range: 0x04C to 0x04F; 0x18B to 0x19F (0x188 to 0x19F in version 2, which has no CPUID fields); 0x1EB; 0x1EF; and 0x1F8 to 0x29F in versions 2 to 4, or 0x208 to 0x29F in versions 5 and 6. In version 6 that last range spans the extended TCB fields at 0x220, 0x240 and 0x260, which ABI 1.59 defines for generations after Turin and which the generations of Section 9.1.3 leave zero. The ABI recommends checking every reserved field; the reserved bits inside `POLICY`, `PLATFORM_INFO` and the TCB values, `KEY_INFO` bit 5 and the signature field's bytes after `S` (0x330 to 0x49F, outside the signed range) are not checked by a verifier of this profile version, because the firmware refuses a guest policy with reserved bits set at launch and later ABI revisions assign bits in those fields.

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

A version 2 report carries no CPUID fields; the generation is the suffix (`-Milan`, `-Genoa`, `-Turin`) of the VEK issuer's common name, which Section 9.1.4 then authenticates through the generation's pinned root, so a version 2 report without an inline VEK is refused with `report-invalid`. Any other family or model is refused with `report-invalid`; this includes later generations, whose TCB layout this version does not define. The family and model ranges follow AMD's VCEK specification (publication 57230, section 1.5).

#### 9.1.4. Authentication

1. Roots. The verifier pins AMD's ARK, ASK and ASVK for each generation (Appendix E). An ARK is self-signed; the ARK signs the ASK and the ASVK; all three use RSA-4096 keys with RSASSA-PSS, SHA-384 and a 48-byte salt. ASK and ARK certificates supplied in the evidence are ignored.
2. Endorsement key. When `SIGNING_KEY` is 0 the report is signed by a VCEK, and the VEK MUST be signed by the ASK; when it is 1, by a VLEK, and the VEK MUST be signed by the ASVK. Every certificate in the chain (RFC 5280) MUST be inside its validity window at the evaluation time. KDS serves VLEKs only to the cloud provider, so a report signed by a VLEK and carrying no inline VLEK bound to it (Section 10.2) is refused with `collateral-unavailable`, as is a report whose `CHIP_ID` is all zero and that carries no inline VEK.
3. Report signature. The VEK's key is an ECDSA P-384 key. The signature covers bytes 0x000 to 0x29F of the report exactly as received. `R` and `S` are little-endian integers in the low 48 bytes of their 72-byte fields; the upper 24 bytes of each MUST be zero.
4. Endorsement cross-check. The VEK's extensions MUST equal the report: `1.3.6.1.4.1.3704.1.3.1` (bootloader SPL), `.3.2` (TEE SPL), `.3.3` (SNP SPL) and `.3.8` (microcode SPL) equal the components of `REPORTED_TCB`, and on Turin `.3.9` (FMC SPL) is present and equals its FMC component, whatever that component's value, since without it the FMC is unendorsed (AMD 57230, Table 11); this holds for a VCEK and a VLEK alike. AMD's VLEK certificate definition (publication 58369, revision 0.10) predates Turin and lists no FMC extension, so a Turin VLEK issued without one is refused. A VCEK's `1.3.6.1.4.1.3704.1.4` (hardware ID) equals `CHIP_ID`: all 64 bytes on Milan and Genoa; on Turin the hardware ID's 8 bytes equal the first 8 bytes of `CHIP_ID` and the remaining 56 bytes of `CHIP_ID` are zero. The hardware ID extension's value is either a DER OCTET STRING whose content is the hardware ID (AMD 57230) or the hardware ID's bytes themselves, as Azure's VCEKs carry it; the two forms differ in length, and the length decides. A VLEK carries no hardware ID, so under a VLEK no endorsement covers `CHIP_ID`. A cross-check failure is refused with `chain-invalid`. Section 10.2 binds an inline VEK with this cross-check before it is used, so the refusal applies to a VEK the verifier obtained itself.
5. Revocation. AMD's CRL for the generation is signed by the ARK and MUST be inside its window at the evaluation time; a CRL without `nextUpdate` has no defined window and is refused with `collateral-invalid`. The serial number of the ASK or ASVK in the chain MUST NOT appear in it. VCEK serial numbers are zero, so the CRL does not revoke an individual VCEK; a compromised chip is excluded through TCB floors and allowlists. The check is REQUIRED unless the policy sets `tcb.require_revocation` to false.
6. Allowlist. With a machine allowlist, the report's `CHIP_ID` MUST be on it. A report endorsed by a VLEK, or whose `CHIP_ID` is all zero (the host masked it), identifies no machine and is refused with `machine-not-allowed` when an allowlist is present (Section 13.3).

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
| `nras.jwks` | `application/jwk-set+json` | NRAS's token signing keys (RFC 7517) | any; used only when the envelope carries device submodules |

The `application/pkix-cert` and `application/pkix-crl` types are those of RFC 2585. In `application/vnd.confidential-ai.pcs-signed+json`, `body` is the exact bytes of Intel's PCS response body and `issuer_chain` the PEM issuer chain from the response header, both as base64url byte strings, so Intel's signature verifies over the bytes Intel produced. A label whose TEE is not the `cpu` submodule's TEE is refused.

### 10.2. Authority and precedence

Inline endorsements are inputs the verifier authenticates before use. A verifier:

1. anchors every certificate to the pinned vendor roots (Section 9) and every signed document to its signing chain, and refuses a body presented without its chain;
2. checks every validity window against the evaluation time before use: a certificate's `notBefore` and `notAfter`, a CRL's `thisUpdate` and `nextUpdate`, a TCB Info's or QE Identity's `nextUpdate`;
3. binds each artifact to the parameters that name it: a VCEK to the report's chip identifier and reported TCB, a VLEK to the reported TCB, a TCB Info to the PCK certificate's FMSPC, a CRL to its issuer;
4. prefers its own valid copy of a CRL or a TCB document, so an attester cannot substitute an older valid artifact for a newer one the verifier knows; a VEK is the same key from either source.

An inline artifact that fails its binding or its window is ignored as if absent: the verifier uses its own copy, and when it has none the check is unavailable (`collateral-unavailable`, or skipped under a waiver). An inline artifact whose signature, signing chain or encoding fails is refused with `collateral-invalid`, since no reading of it is authentic, and so is an artifact the verifier itself obtained that fails any check. A VEK is the exception, since Section 9.1.4 authenticates it as part of the report's chain: an inline VEK that cannot be parsed, names the other key type (VCEK or VLEK) than `SIGNING_KEY` does, or fails its binding or window is ignored as if absent, and a bound VEK whose chain fails is refused with `chain-invalid`, whichever source supplied it.

Freshness of collateral is each artifact's own validity window evaluated at the evaluation time. An artifact inside its window is usable however long ago it was fetched, and an artifact outside it is never used, however recently it arrived; the verifier's cache timers play no part.

### 10.3. Collateral keys

A verifier that holds collateral outside the evidence identifies each artifact by a key. The conformance corpus uses these text forms (Section 14.2):

| Key | Artifact |
| --- | --- |
| `snp_vcek/<generation>/<chip id hex>-<TCB hex>` | a VCEK: `<generation>` is `Milan`, `Genoa` or `Turin`; `<chip id hex>` is the report's 64-byte `CHIP_ID` in lowercase hexadecimal; `<TCB hex>` is the reported bootloader, TEE, SNP and microcode SPLs as two uppercase hexadecimal digits each, followed by the FMC SPL on Turin |
| `snp_cert_chain/<generation>` | AMD's ASK and ARK for the generation |
| `snp_crl/<generation>` | AMD's CRL for the generation |
| `tdx_tcb_info/<fmspc>` | the TDX TCB Info for an FMSPC in lowercase hexadecimal, with its signing chain |
| `tdx_qe_identity/td` | the TD QE Identity, with its signing chain |
| `tdx_pck_crl/<ca>` | the PCK CRL, `<ca>` `platform` or `processor` |
| `tdx_root_crl` | the SGX Root CA CRL |
| `nras_jwks/<url>` | the NRAS JWKS served at `<url>`, written as the URL itself; the corpus carries JWKS in `nras[].jwks` (Section 14.2) and uses no key of this form |
| `cca_corim/<implementation id hex>` | the platform vendor's signed CoRIM for an Arm CCA implementation: the CPAK of each instance and the reference values of the platform software (Section 9.6.4) |

## 11. Verification procedure

A verifier appraises evidence under a policy, with the relying party's nonce, the digest of the presented certificate in the certificate pattern (which a version 1 verifier receives as `freshness.key`, Section 5.5), collateral, and an evaluation time. Every step fails closed: a failure is a refusal with the code of Section 14.4, and no appraisal is produced.

For the `cpu` submodule:

1. Parse. Parse the envelope within the bounds of Section 4.7, and validate the policy (Section 13.1; `policy-invalid`). Refuse an unknown profile or `cvm_version` and any submodule name or combination Section 4.2 does not admit (`envelope-invalid`), and an `eat_nonce` that differs from the nonce the relying party supplied (`binding-mismatch`).
2. Identify. Select the parser from `cvm_report`'s media type, parse the hardware report, and re-derive the vendor, the TEE and the generation from it (Section 9). Refuse a report the parser does not accept (`report-invalid`), a TEE or media type the verifier does not implement (`platform-unsupported`), and a `cvm_platform` or `dbgstat` hint that contradicts the report (`envelope-invalid`).
3. Authenticate. Verify the hardware chain to the pinned root and the report's signature, including every validity window at the evaluation time and the cross-checks Section 9 lists for the platform (`signature-invalid`, `chain-invalid`, and `collateral-unavailable` for a VEK that can be neither found inline nor fetched). When the policy carries a machine allowlist, the identity this step authenticated MUST be on it (`machine-not-allowed`).
4. Guest policy. Enforce the normalized security settings (Section 13.1): debug disabled unless allowed; on SEV-SNP, a guest-requested report (VMPL at most 3), VMPL 0 and migration disallowed unless allowed; on TDX, `SEPT_VE_DISABLE` set, reserved attributes zero, and no migration-service TD unless allowed; on Arm CCA, the platform lifecycle in a secured state unless debug is allowed (`guest-policy`).
5. Freshness. Verify the binding of `cvm_binding.mode` (Section 5.4). For `commitment` the check is the recompute of Section 8.1 over the registers step 8 establishes (`binding-mismatch`).
6. Collateral. Check revocation, the TCB status, the TCB floor that applies to this machine (Section 13.2) and, on TDX, the QE Identity, each with its signing chain anchored and its window checked; record each outcome (`revoked`, `collateral-unavailable`, `collateral-invalid`, `tcb-not-allowed`). Advisories are reported and not checked.
7. Registers. Establish the authoritative register values (Section 6.5) and refuse envelope values that differ (`register-mismatch`).
8. Replay. Replay the log when present (Section 7.4), mark each register `replayed`, and apply the slot rules of Section 8 in `commitment` mode (`log-required`, `log-invalid`, `replay-mismatch`, `unsupported`).
9. Reference values. Apply the reference values and the backing minimum (Sections 13.1 and 13.4; `reference-mismatch`, `backing-below-minimum`), then produce the claims and the trustworthiness vector (Section 12).

Steps 4 to 9 read only values that step 3 has authenticated or that the envelope binds to them. A verifier MAY evaluate the steps in any order and MUST produce no appraisal unless every step passes; when evidence fails more than one check it MAY refuse with the code of any failing step. Each conformance case exercises one failing statement (Section 14.2).

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

The appraisal carries no signature. A verifier that hands an appraisal across a trust boundary signs it as an EAR token, a JWT (RFC 7519) or CWT (RFC 8392) as draft-ietf-rats-ear-04 section 3 defines, or delivers it over an authenticated channel; the field names alone make nothing verifiable. A failed appraisal produces no appraisal: the verifier returns the refusal code. A relying party that records failures MAY express them with the AR4SI contraindicated values; this profile does not.

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
| `cvm_tcb` | -70025 | vendor-specific TCB values and, on TDX, the vendor's status and advisories (Section 9) |
| `cvm_identity` | -70026 | the hardware identifier: SEV-SNP `chip_id`, TDX `ppid`, Arm CCA `instance_id`, authenticated by the hardware chain; an SEV-SNP `chip_id` under a VLEK or a masked `CHIP_ID` is reported as the report carries it and identifies no machine (Section 13.3) |
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
| `cvm_reference` | -70031 | which reference values were applied: `launch_measurement` true when a launch measurement pin matched and false when none was configured, and `registers` listing each pinned slot, which matched; absent when the policy pins nothing that applies to the submodule |
| `cvm_backing_min` | -70032 | `{required, weakest_seen}`; absent when the submodule has no registers |
| `ear_nvidia_evidence` | text | device submodules: `{signature_verified, parsed, nonce_match}` from NRAS's signed claims (Section 9.7), each present when the device token carries the claim it comes from |

In a `cvm_collateral` entry, `reason` is present on a `skipped` entry; `signed` is true on every `checked` entry and absent otherwise; `next_update` is the `nextUpdate` of a TCB Info or QE Identity and appears only on `tdx_tcb_info` and `tdx_qe_identity`; `this_update` is not emitted in version 1.

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

The second entry of `ear_appraisal_policy_ids` names the effective policy: `ni:///sha-384;<base64url>` (RFC 6920), the SHA-384 of the JCS serialization (RFC 8785) of the policy in which every member that has a default is present with its value or its default, and no member is null. The members without a default (`freshness.key`, `reference.host_data`, `tcb.default_floor`, a machine's `tcb_floor`, the members of a floor, `identity`, `owner`, `gpu.expected_archs`) appear only when set; every other object appears, empty or not, as in Appendix B.4, which shows the effective default policy in full. Two appraisals carry the same identifier exactly when their effective policies serialize to the same bytes; reordering an array changes the identifier without changing the requirements. The identifier of the default policy is in Appendix B.4.

### 12.6. Composition with the TDX confidential-GPU EAR profile

draft-kykdxy-rats-tdx-cgpu-ear-profile-02 defines EAR claims for TDX guests with confidential GPUs. This profile composes with it:

- a TDX `cpu` submodule carries, beside the `cvm_*` claims, the Intel Trust Authority names that draft reuses, as lowercase hexadecimal text: `tdx_mrtd`, `tdx_rtmr0` to `tdx_rtmr3`, `tdx_mrconfigid`, `tdx_mrowner`, `tdx_mrownerconfig`, `tdx_td_attributes`, `tdx_tee_tcb_svn`, `tdx_xfam`, `tdx_mrseam`, `tdx_mrsignerseam`;
- device submodules carry NRAS's claim names unchanged, and `ear_nvidia_evidence` in `ear_verifier_claims`;
- `ear_all_submods_bound` is the draft's text claim. The verifier emits `"true"` or `"false"` and never `"unknown"`, since it checks every binding. A binding that fails is a refusal, so the claim is `"false"` only when a device's signed nonce match is false and the policy (`gpu.device_policy.require_nonce_match`) tolerates it.

The claim names and value encodings match that draft; its container and its submodule labels differ. The draft places the `tdx_*` claims in `ear_evidence_claims` of a submodule labeled `tdx` and names GPU submodules `gpu_0`, `gpu_1` and so on, where this profile uses `ear_attester_claims` of `cpu` and `gpu/<ueid>`. A relying party written against the draft maps `tdx` to `cpu`, `ear_evidence_claims` to `ear_attester_claims`, and `gpu_<i>` to the `i`-th `gpu/<ueid>` submodule in ascending byte order of the names. The draft makes every member of `ear_nvidia_evidence` required, and this profile omits a member whose source claim NRAS did not sign.

EAR-04 section 3 requires an EAR extension to be a map, and `ear_all_submods_bound` is a text value because draft-kykdxy defines it so; a relying party that applies EAR-04's extension rule alone refuses it. The conflict lies between the two drafts, and this profile follows draft-kykdxy until they reconcile.

### 12.7. Composition with Confidential Containers Trustee

For an SEV-SNP `cpu` submodule the verifier emits an `snp` object in `ear_attester_claims`, beside the `cvm_*` claims, carrying the names the Confidential Containers Trustee verifier emits, with Trustee's types: `policy_abi_major`, `policy_abi_minor` (integers), `policy_smt_allowed`, `policy_migrate_ma`, `policy_debug_allowed`, `policy_single_socket` (booleans), `reported_tcb_bootloader`, `reported_tcb_tee`, `reported_tcb_snp`, `reported_tcb_microcode` (integers), `platform_tsme_enabled`, `platform_smt_enabled` (booleans), and `measurement`, `report_data`, `init_data` (Trustee's name for `HOST_DATA`) and `chip_id` (lowercase hexadecimal text). A policy written against Trustee's annotated evidence reads this object unchanged. The object is compatibility output: the `cvm_*` claims are normative, the `snp` object carries Trustee's view of the same report (part of it repeats `cvm_*` content, and members such as `report_data` and the policy ABI version appear only there), and its keys stay text in both encodings.

## 13. Verifier policy

### 13.1. Shape and defaults

The policy is a verifier input, chosen by the relying party. It is a JSON object under the encoding rules of Section 4.7 (a `null` member, an object written as an array, or an unknown member fails its validation with `policy-invalid`). Every member is optional and every default fails closed:

| Member | Default | Meaning |
| --- | --- | --- |
| `reference` | every array and map empty, `host_data` absent | reference values, Section 13.4 |
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

A floor is named, so a fleet carries one floor per generation and moves a machine between floors without editing every policy. A floor constrains at least one platform, and a `tdx` member without members constrains nothing and fails validation:

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

## 14. Conformance

This section defines verifier conformance. A verifier conforms to this profile when it reproduces the decision of every case of the conformance corpus at the corpus version it declares, and meets the requirements of Sections 4 to 13 and 15.9 that the corpus does not yet cover (`UNCOVERED.md`). The CDDL module constrains shapes, the vectors of Appendix B constrain formulas, and the corpus constrains decisions. An attester conforms when it produces evidence under Sections 4, 5 and 9 that a conforming verifier appraises; a register provider conforms to Sections 7.3 and 8.1 to 8.6. Version 1 publishes no corpus for attesters or register providers.

### 14.1. Layout

```
conformance/
  VERSION            the corpus version
  README.md          how to run the corpus
  UNCOVERED.md       the normative statements that have no case yet
  cases/<id>.json    one case per file
  inputs/            the evidence, policies, collateral, expected appraisals (inputs/expected/)
                     and recorded NRAS exchanges the cases reference
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
refusal-code = text                   ; Section 14.4
nras-exchange = { "arch": "HOPPER" / "BLACKWELL" / "LS10", "nonce": text, "response": path, "jwks": path }
                                      ; nonce: the request's nonce, lowercase hexadecimal (Section 9.7.1)
```

`signing_chain` is the PEM issuer chain that Section 10.1 calls `issuer_chain`.

`rule.section` names the section of this document the case exercises and `rule.statement` states the rule, so a case traces to the text. An input whose path ends in `.gz` is stored gzip-compressed (RFC 1952) and is its decompressed content; only inputs over 1 MiB are compressed.

A case fixes everything a decision depends on:

- `now` is the evaluation time. Every validity window in the appraisal is judged against it. A conforming verifier takes the evaluation time as an input.
- `collateral` is the whole collateral available to the appraisal, each file the artifact's bytes as the source serves them, with signed Intel artifacts carrying their signing chain beside the body. A request for a key the case does not carry fails as unavailable collateral. The envelope's inline endorsements are inputs like any other, and Section 10.2 applies.
- `nras` holds the recorded exchange for each architecture batch: the nonce the verifier will send, NRAS's detached EAT, and the JWKS that verifies it. Nothing in the corpus reaches a network.
- the policy is complete; a case without one runs under the defaults, and its identifier (Section 12.5) is the one the expected appraisal carries.
- the relying party's nonce is the envelope's `eat_nonce`, and the digest of the presented certificate, in the certificate pattern, is the policy's `freshness.key`. The rule that refuses an `eat_nonce` other than the relying party's therefore has no case (`UNCOVERED.md`).

A case exercises one statement. Where an input cannot avoid breaking several, `rule.statement` names the refusal expected.

### 14.3. Comparison

For `expect.appraisal`, the runner encodes the implementation's appraisal as the JSON of Section 12 and compares it with the expected file as parsed JSON values after removing, from both, the members that vary between implementations: `iat`; `ear_verifier_id`; `ear_raw_evidence`; `reason` inside every `cvm_collateral` entry. Everything else must be equal. An implementation that emits an extra claim fails the case.

For `expect.refusal`, the runner maps the implementation's error to one code of Section 14.4 and compares codes. An error that maps to no code is no decision and fails the case, as does a refusal with another code, or an appraisal where a refusal was expected, or the reverse.

### 14.4. Refusal codes

A refusal names the rule family that failed:

| Code | Sections | Meaning |
| --- | --- | --- |
| `envelope-invalid` | 3.4, 4, 5.3, 5.4, 6.1, 6.2, 6.4, 6.5, 8.1, 9.4.1, 10.1, 11 steps 1 and 2 | the envelope, a submodule or a `cvm_*` object breaks a shape, encoding, size, nesting, version or consistency rule, including a hint that contradicts the signed report, a backing the register's source does not admit, `snp-vmr` registers outside `commitment` mode, envelope values that disagree with each other (a vTPM register and its entry of `cvm_tpm_quote.pcrs`, an Azure SEV-SNP report and the HCL report's hardware area), an HCL report outside Section 9.4.1, and a reserved key kind |
| `policy-invalid` | 11 step 1, 13 | the policy fails its own validation |
| `platform-unsupported` | 9, 11 step 2 | the TEE, hosting or report media type is one this verifier does not implement |
| `report-invalid` | 9.1.2, 9.1.3, 9.2.2, 9.4.3, 11 step 2 | the hardware report cannot be parsed, breaks a layout rule of Section 9 (a reserved byte, the signature algorithm, the key selection, a body type or size), or its version is outside the supported range; a TPM quote that is not a quote |
| `signature-invalid` | 9.1.4, 9.2.3, 9.4.3, 11 step 3 | a hardware or vendor signature does not verify: the report, the quote, the TPM quote |
| `chain-invalid` | 9.1.4, 9.2.3, 11 steps 3 and 6 | a certificate chain does not reach the pinned root, contradicts the report, or is outside its validity at the evaluation time; a quoting enclave that is not the one Intel's QE Identity names |
| `machine-not-allowed` | 9.1.4, 9.7.3, 11 step 3, 13.3 | the authenticated machine identity is not on the allowlist, or the evidence identifies no machine while an allowlist is present |
| `guest-policy` | 11 step 4 | a guest policy bit, TD attribute, VMPL, host-requested report, debug state or lifecycle violates policy |
| `binding-mismatch` | 4.1, 4.6, 5, 8.7, 9.4, 9.7.2, 11 steps 1 and 5 | the binding of the submodule's mode does not hold (including the HCL report's key binding), the envelope's `eat_nonce` differs from the relying party's nonce, NRAS's overall or device nonce differs, a key binding the policy requires is absent or different (a CCA submodule under a policy key included), the certificate pattern without `freshness.key`, or `vtpm-extradata` or `commitment` without a pinned launch measurement |
| `collateral-unavailable` | 9.1.4, 9.6.4, 9.7.2, 10, 11 steps 3 and 6 | an artifact the policy requires could not be obtained, including a VEK that a VLEK-signed or masked report does not carry, an NRAS or JWKS endpoint that cannot be reached and a missing CCA CoRIM |
| `collateral-invalid` | 9.1.4, 9.2.3, 10, 11 step 6 | an artifact fails its signature, its signing chain, its binding or its window at the evaluation time, or cannot be parsed; an inline artifact that fails only its binding or window is ignored (Section 10.2) |
| `revoked` | 11 step 6 | a certificate is revoked |
| `tcb-not-allowed` | 9.2.3, 11 step 6, 13.2 | a TCB status outside the allowed set, a TCB value below its floor, a TDX module identity or TCB level that matches no entry, or a QE TCB level the QE Identity revokes or does not list |
| `register-mismatch` | 6.5, 9.4.3, 11 step 7 | an envelope register differs from the authoritative value |
| `log-required` | 4.3, 7.1, 7.4, 8, 11 step 8 | a log the mode requires is absent or in a format the mode does not admit, or `chain_len` and the log disagree |
| `log-invalid` | 7.1, 9.3, 11 step 8 | the log cannot be parsed whole under its format's rules, or breaks a shape rule of its format |
| `replay-mismatch` | 7.3, 7.4, 8, 9.2.6, 9.3, 11 step 8 | a replay does not reproduce a register that must reproduce, a record digest does not reproduce, a `cvm` event or claim is not deterministically encoded, a commitment log carries a record of another content type, a slot or `ats` record rule is broken, a CCEL record names an index above 4, or chain memory detects a restart or a fork |
| `reference-mismatch` | 11 step 9, 13.1, 13.4 | a pinned launch measurement, register, PCR, host data, owner key or slot owner differs, or a pin nothing in the evidence can satisfy |
| `backing-below-minimum` | 11 step 9, 13.1 | a register's backing is below the policy minimum |
| `device-required` | 13.5 | the policy requires a device and the envelope carries none |
| `device-not-allowed` | 4.2, 13.5 | a device's architecture is outside the allowed set, or the envelope carries more than 32 device submodules |
| `device-token-invalid` | 9.7.2 | NRAS answered with a token the verifier refuses: signature, issuer, claims version, `submods` digest or entries, key identifier, or a token that maps to no device |
| `device-policy` | 9.7.2, 9.7.3, 13.5 | NRAS's overall result is false, the device count differs, a device token is of another architecture, or a device gate failed |
| `unsupported` | 7.1, 7.4, 9.4.3, 9.4.4, 9.6.1, 9.6.2, 9.7.1, 11 step 8 | a format or feature this version does not implement: the `aael` log, a log format the submodule does not admit, a TPM bank other than SHA-256 or a quote selection other than one SHA-256 selection, a CCA collection entry, profile or binding variant outside Sections 9.6.1 and 9.6.2, an NRAS request that relaxes NRAS's certificate checks |

### 14.5. Versioning and change control

The corpus version is `<profile version>.<revision>`, `1.0` at first publication. A change to any case, including a new case, raises the revision. A change that alters a decision in Sections 4 to 13 lands together with the case that shows it. An implementation states the version it passes (for example, "conforms to `tag:confidential.ai,2026:cvm#1`, corpus 1.9") and pins that version in its continuous integration.

The reference implementation generates the expected results (Section 18). A case the reference implementation fails is a defect in one or the other, fixed before the corpus version is published. Where a requirement the corpus does not cover differs from what the reference implementation does, Section 18 lists the difference and the text governs.

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

### B.4. Policy identifier (Section 12.5)

The identifier of the default policy. The canonical form is the JCS serialization of the effective default policy; an implementation that fills the defaults of Section 13.1 and serializes with RFC 8785 reproduces it:

```
JCS          {"commitment":{"header16":"QVRTLU1SLTEBARAAAAAAAA","seed":"YM3K6sPxWpbLKhuF1CxaTRKfztZUNQRMklD9_--YmEzDvUIJcsOvWCleD2G6IeSn"},"freshness":{},"gpu":{"device_policy":{"allow_debug":false,"require_measres_success":true,"require_nonce_match":true,"require_secboot":true},"required":false},"min_backing":"hardware","policy_bits":{"allow_debug":false,"allow_migration":false,"allow_service_td":false,"require_sept_ve_disable":true,"require_vmpl0":true,"require_zero_reserved_attributes":true},"reference":{"launch_measurement":[],"pcrs":{},"registers":{},"slot_owners":{}},"tcb":{"floors":{},"require_revocation":true,"require_signed_collateral":true,"tdx_allowed_status":["UpToDate"]}}
SHA-384      a678b73c551d1a00857d906715789f89c0f89683086fe8a28a1dfb537a9271520c121a3da5ca0838fb9e0cc8b3d0dc10
id           ni:///sha-384;pni3PFUdGgCFfZBnFXificD4loMIb-iiih37U3qScVIMEho9pcoIOPueDMiz0NwQ
```
