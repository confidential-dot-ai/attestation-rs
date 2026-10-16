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
