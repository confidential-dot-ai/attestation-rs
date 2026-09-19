# CVM attestation profile v1

Status: draft for review. Owner: attestation DRI. Companion documents: "Standardizing Attestation" and "SEV-SNP Measurement Registers" (Notion, Confidential AI / Docs). This document is the library-side design those two ask for, and it changes both of them; section 11 lists exactly what.

## 1. Summary

We standardize by profiling existing standards, and we invent only the one thing nobody has: a hardware-bound runtime measurement register bank on SEV-SNP.

- Evidence is an EAT claims set (RFC 9711) under the profile `tag:confidential.ai,2026:cvm#1`, carried unprotected (RFC 9781 UJCS/UCCS) because every trusted byte inside it is signed by hardware or derived from a hardware signature by the verifier. One submodule per attester: the CPU TEE, an optional vTPM, and one per NVIDIA device. Arm CCA tokens nest as they are.
- Runtime measurements are a register array with an explicit algorithm, index, source and `backing` label per register, plus a TCG Canonical Event Log (CEL, v1.1) that replays to them. TDX RTMRs, Azure vTPM PCRs, Arm CCA REMs and the new SNP registers all populate the same array.
- Freshness is one nonce bound per platform in a declared mode. On SNP with the register driver, `report_data` becomes the `ats-mr-v1` commitment and the nonce lives in the committed caller data.
- Attestation results are EAR (draft-ietf-rats-ear-04) with our normalized claims in `ear_attester_claims`, collateral outcomes in `ear_verifier_claims`, and the trustworthiness vector filled per AR4SI-10. c8s already mints EAR; it moves from profile 03 to 04 and drops its private claims for the profiled ones.
- The Rust library exposes exactly these types, verifies fail-closed, and publishes JSON Schemas that attestation-go and c8s-verify-js pin in CI, so the three implementations cannot drift again.

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
| draft-ietf-rats-ear-04 | results: `ear_verifier_id`, `submods`, `ear_status`, `ear_trustworthiness_vector`, `ear_attester_claims`, `ear_verifier_claims`, `ear_raw_evidence` |
| draft-ietf-rats-ar4si-10 | trustworthiness tiers and per-category values |
| TCG Canonical Event Log Format v1.1 r11 | record layout (`recnum`, register index, `digests`, typed `content`), CBOR and JSON encodings, replay |
| Arm CCA token (RMM spec; profiles `tag:arm.com,2023:cca_platform#1.0.0`, `tag:arm.com,2023:realm#1.0.0`) | nested as a token submodule, verified by the CCA rules |
| AMD SEV-SNP ABI, Intel TDX DCAP, NVIDIA NRAS EAT | the hardware reports and vendor tokens the envelope carries |

## 4. Evidence profile

Profile identifier: `tag:confidential.ai,2026:cvm#1`, carried in `eat_profile` (claim key 265).

### 4.1 RFC 9711 section 6.3 checklist

| Item | Decision |
| --- | --- |
| 6.3.1 JSON, CBOR or both | JSON is the primary wire encoding (this is what every consumer speaks today). CBOR is defined by the same claims with the CWT keys and is used where a token is natively CBOR (Arm CCA) and for the event log. |
| 6.3.2 map and array encoding | definite lengths only |
| 6.3.3 string encoding | definite lengths only |
| 6.3.4 preferred serialization | deterministic encoding, RFC 8949 section 4.2.1, for every CBOR object we produce |
| 6.3.5 tags | UCCS tag 601 when a CBOR evidence set is written; no tag inside JSON |
| 6.3.6 protection | none at the envelope (UJCS/UCCS). Trust comes from the hardware signatures inside; section 4.2 lists which fields are trusted and which are hints. |
| 6.3.7 algorithms | inherited from each hardware report; the profile adds SHA-384 for registers and the commitment, SHA-256 for the vTPM AK binding and the GPU nonce derivation |
| 6.3.8 detached bundles | not used in v1 |
| 6.3.9 key identification | per submodule: VCEK or VLEK for SNP, PCK chain for TDX, HCL AK for the vTPM, CCA platform key, NRAS JWKS `kid` |
| 6.3.10 endorsement identification | inline `cvm_endorsements` (section 4.6) or fetched by the verifier; either way anchored to embedded roots |
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
| `cvm_version` | private | must | integer, 1 |

Submodule names are chosen by the attester within these reserved forms: `cpu` (exactly one, required), `vtpm` (at most one), `gpu/<ueid>` and `nvswitch/<ueid>` (one per device). Other names are rejected.

### 4.4 Submodule claims

`cpu` submodule (a claims set):

| Claim | Req | Class | Meaning |
| --- | --- | --- | --- |
| `cvm_platform` | must | hint | `{vendor, tee, generation?, hosting}`; vendor in `amd`, `intel`, `arm`; tee in `sev-snp`, `tdx`, `cca`; hosting in `bare`, `azure`, `gcp`, `dstack` |
| `cvm_report` | must | signed | `{format, data}`; format in `sev-snp-report`, `tdx-quote`, `hcl-report`; `data` is the raw bytes, base64url in JSON |
| `cvm_binding` | must | bound | freshness binding mode (section 4.5) and its parameters |
| `cvm_endorsements` | may | bound | inline collateral (section 4.6) |
| `cvm_registers` | may | bound | runtime register array (section 4.7) |
| `cvm_log` | may | bound | event log (section 4.8) |
| `cvm_chain` | must when binding is `commitment` | bound | `{chain_len, caller_data, bootseed}` (section 4.9) |
| `dbgstat` | may | hint | EAT debug status; the verifier derives the real value from the report |

For Arm CCA the `cpu` submodule is instead a nested token (RFC 9711 section 4.2.18.3): the CCA collection token bytes (CMW tag 907 or legacy 399, platform token at 44234, realm token at 44241). The realm token's challenge is the nonce; the platform challenge is the hash of the realm key. No `cvm_report` wrapper is needed because the token is already an EAT.

`vtpm` submodule:

| Claim | Req | Class | Meaning |
| --- | --- | --- | --- |
| `cvm_tpm_quote` | must | signed | `{message, signature, pcrs, bank}`; TPMS_ATTEST and its signature, the PCR values of the quoted bank |
| `cvm_tpm_ak` | must | bound | how the AK is bound to the CPU report; on Azure, `report_data[0..32] == SHA-256(var_data)` from the HCL report |
| `cvm_registers` | must | bound | the PCRs projected as registers, source `vtpm-pcr`, backing `privileged-service` |
| `cvm_log` | may | bound | TPM2 event log or CEL |

`gpu/<ueid>` and `nvswitch/<ueid>` submodules: the existing NVIDIA device evidence (`arch`, `evidence_b64`, `cert_chain_b64`) plus `cvm_binding` with mode `nras-nonce`. The verifier's NRAS interaction and the resulting per-device EAT are unchanged from today.

### 4.5 Freshness and binding modes

`cvm_binding.mode` declares where the nonce is bound. The verifier computes the expected value and compares in constant time; a mismatch is an error.

| Mode | Platforms | Expected value |
| --- | --- | --- |
| `report-data` | SNP without the register driver, TDX, dstack | `report_data == pad64(anchor)` |
| `commitment` | SNP with the register driver | `report_data == header16 \|\| SHA-384("ats-mr-v1/commit" \|\| R[0..n] \|\| chain_len \|\| caller_data)` with `caller_data` starting with `anchor` |
| `vtpm-extradata` | Azure SNP, Azure TDX, future SVSM vTPM | TPM quote `extraData == anchor`, and the CPU report binds the AK |
| `cca-challenge` | Arm CCA | realm token `challenge == pad64(anchor)` |
| `nras-nonce` | NVIDIA devices | SPDM nonce `== SHA-256(nonce \|\| "NVIDIA-GPU-EAT-v1")` (switches use the switch tag) |

`anchor` is the relying party's binding input. When `cvm_binding.key` is absent, `anchor = nonce`. When present, `anchor = SHA-384(nonce || key.kind || key.value)` where `key` is `{kind, value}` and `kind` is `spki-sha256` (hash of a serving certificate's SubjectPublicKeyInfo) or `raw` (an opaque value the relying party chose). This replaces the per-platform padding rules c8s carries today with one derivation the verifier owns.

### 4.6 Endorsements

`cvm_endorsements` carries the same collateral set the verifier would otherwise fetch, so verification can be offline and so a KDS or PCS outage does not stop a verifier that already holds fresh collateral:

| Field | Content |
| --- | --- |
| `snp.vek` | VCEK or VLEK, DER |
| `snp.crl` | AMD CRL for the generation, DER |
| `tdx.tcb_info` | `{body, issuer_chain}` exactly as Intel PCS returned them |
| `tdx.qe_identity` | `{body, issuer_chain}` |
| `tdx.pck_crl`, `tdx.root_crl` | DER |
| `nras.jwks` | JWKS document |

Inline endorsements are inputs, never authority: the verifier anchors every certificate to the embedded AMD, Intel or NVIDIA roots and checks every validity window and `nextUpdate` before use. The verifier's own cache (the collateral unification in the sweep) uses the same struct, so inline, cached and fetched collateral are one type with three transports.

### 4.7 Registers

`cvm_registers` is an array; each entry:

| Field | Meaning |
| --- | --- |
| `index` | integer slot |
| `alg` | `sha-256`, `sha-384` or `sha-512` |
| `value` | the register value |
| `source` | `tdx-rtmr`, `snp-vmr`, `vtpm-pcr`, `cca-rem` |
| `backing` | `hardware`, `privileged-service`, `kernel-service`, `virtualized` |

The verifier never trusts `value` from the envelope. For `tdx-rtmr` and `cca-rem` the authoritative values are in the signed report and the envelope values must equal them. For `vtpm-pcr` the quoted PCR digest must reproduce from them. For `snp-vmr` the commitment must reproduce from them (section 4.9). When a log is present it must replay to them.

Slot semantics are fixed across platforms so policy is portable: slots 0 to 3 carry the TDX RTMR meaning from the TDX virtual firmware design and the TCG firmware profile (0 firmware configuration, the PCR 1 and 7 analog; 1 what the firmware loads, boot loader and partition table, PCR 2 to 5; 2 kernel, command line, initrd and OS-loaded components, PCR 8 to 15; 3 runtime), slots 4 to 15 are workload slots available where the platform has them. `vtpm-pcr` entries keep their PCR index and are distinguished by `source`. The verifier reports the backing of every register it verified, and policy sets a minimum backing so a downgrade from `hardware` to `kernel-service` can never pass silently.

### 4.8 Event log

`cvm_log` is `{format, data}` with `format` in:

| Format | Notes |
| --- | --- |
| `tcg-cel-cbor` | the target. CEL v1.1 records: `recnum`, register index (the CEL `pcr` field, integer), `digests`, typed `content`. Deterministic CBOR. |
| `tcg-cel-json` | same records, JSON encoding, for human inspection only |
| `tdx-ccel` | the ACPI CCEL as the guest exposes it (TCG2 binary), accepted during transition |
| `tpm2-event-log` | TCG2 binary log from a vTPM, accepted during transition |

c8s runtime events (`domain`, `operation`, `content_digest`) are carried as CEL records with a profile-private content type; the record's digest is the value that was extended. Replay hashes the stored record bytes exactly as extended and never re-encodes them. The verifier replays every register the log covers and marks each register `replayed: true` or `false` in the result; policy decides which slots must replay (today: RTMR 0 to 2 must, RTMR 3 reports).

### 4.9 SNP registers and the commitment (`ats-mr-v1`)

This is the format from the register document, unchanged where it is specified and fixed where it is not.

```
genesis(slot i): R[i] = SHA-384(0^48 || "ats-mr-v1/genesis" || seed || i)
extend:          R[i] = SHA-384(R[i] || SHA-384(record_bytes))
commit:          C    = SHA-384("ats-mr-v1/commit" || R[0] || ... || R[n-1] || chain_len || caller_data)
report_data:     header16 || C
```

- `seed` is an open decision (section 12). This document recommends a constant domain tag; the register document seeds from the launch digest, which forces the provider to obtain a report before its first extend and adds no security the pinned launch digest does not already provide.
- `header16` is `magic[8] = "ATS-MR-1"`, `version u8 = 1`, `alg u8 = 1 (SHA-384)`, `reg_count u8`, `flags u8`, `reserved[4] = 0`. The verifier pins magic, version, alg and reg_count from policy; any other value fails.
- `chain_len` is a 64-bit little-endian count of every extension since genesis. `caller_data` is 64 bytes: `anchor` (48) followed by 16 caller bytes. `bootseed` (EAT claim 268) is a per-boot random value the driver extends into slot 3 as the first record, so a rebooted chain is distinguishable from a rewound one.
- `cvm_chain` in the envelope carries `chain_len`, `caller_data` and `bootseed`; the log supplies the records.

Verification order: launch measurement pinned first, then debug policy and VMPL, then replay, then commitment, then policy on the log. The first two are the load-bearing steps; the register document says so and the verifier enforces the order.

## 5. Result profile

Results are EAR per draft-ietf-rats-ear-04 with `eat_profile = tag:ietf.org,2026:rats/ear#04`. The library does not sign tokens; it produces the appraisal content and the relying party (c8s CDS today) signs. One EAR `submods` entry per evidence submodule, same names.

Per appraisal:

| Claim | Content |
| --- | --- |
| `ear_status` | AR4SI tier |
| `ear_trustworthiness_vector` | section 5.2 |
| `ear_appraisal_policy_ids` | the policy identifier the verifier applied |
| `ear_attester_claims` | our normalized claims, section 5.1 |
| `ear_verifier_claims` | collateral and reference-value outcomes, section 5.1 |
| `eat_nonce` | the nonce that was bound |

### 5.1 Normalized claims

`ear_attester_claims` for the `cpu` submodule:

| Claim | Meaning |
| --- | --- |
| `cvm_platform` | verified vendor and TEE; hosting as reported |
| `cvm_launch_measurement` | `{alg, value}` |
| `cvm_registers` | verified array from section 4.7 plus `replayed` per entry |
| `cvm_freshness` | `{mode, key?}` as bound; presence means the check passed, because a failure is an error |
| `cvm_host_data` | `{semantics, value}`; semantics in `snp-host-data` (32 bytes), `tdx-mrconfigid` (48), `cca-rpv` (64); a label, see section 10 |
| `cvm_owner` | SNP `family_id`, `image_id`, `id_key_digest`, `author_key_digest`; TDX `mr_owner`, `mr_owner_config` |
| `cvm_policy` | `{debug, migratable, smt, single_socket?, vmpl?, sept_ve_disable?, ...}` normalized booleans and small integers |
| `dbgstat` | EAT value derived from `cvm_policy.debug` |
| `cvm_tcb` | vendor-tagged: SNP `{reported, committed, current, launch}` each with the SPL components; TDX `{tee_tcb_svn, pck_tcb, pcesvn, status, advisories}`; CCA `{lifecycle, sw_components}`; GPU `{driver, vbios}` |
| `cvm_identity` | SNP `chip_id`; TDX `fmspc`; CCA `instance_id`; GPU `ueid` |

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
| instance-identity | 2 when the identity is recognized by policy (chip id, FMSPC, instance id allowlist); 0 when no policy |
| executables | 2 when the launch measurement and every required register match reference values; 3 when only the launch measurement matched; 33 when a required register carries unrecognized extends; 96 when a contraindicated value is present |
| configuration | 2 when policy bits are acceptable; 96 when debug is enabled or VMPL is not 0 |
| runtime-opaque | 2 for every CVM whose report verified: the runtime is inside the TEE, encrypted and opaque to the hypervisor and host; this is the claim a TEE uniquely earns. Nothing is claimed about isolation between processes inside the guest |
| file-system | 0 unless an IMA-backed slot is verified, then 2 or 32 |
| storage-opaque | 0 in v1 |
| sourced-data | 2 for a GPU submodule NRAS affirmed with an acceptable device policy |

An `isSafe` boolean is not part of the profile. A relying party that wants one derives it from `ear_status` under its own policy.

## 6. Verification procedure

Normative order for the `cpu` submodule; every step fails closed.

1. Parse the envelope. Reject unknown profile versions and unknown submodule names.
2. Select the parser from `cvm_report.format`. Re-derive vendor and TEE from the report and reject a contradicting `cvm_platform`.
3. Verify the hardware chain to the embedded root and the report signature. SNP: ARK to ASK or ASVK to VEK, VEK validity, chip id and TCB cross-check against the report, VLEK detected from the certificate. TDX: PCK chain to the embedded Intel root, QE report signature and binding. CCA: platform token signature by the platform key, realm token by the RAK, RAK hash equals the platform challenge.
4. Enforce guest policy: debug disabled unless policy allows, VMPL 0 on SNP, TD attributes reserved bits, CCA lifecycle.
5. Bind freshness per `cvm_binding.mode`.
6. Verify collateral per policy: revocation, TCB status and advisories, QE identity, each with its signing chain anchored; record each outcome.
7. Establish registers: authoritative values from the report, the quote's PCR digest, or the commitment; reject envelope values that differ.
8. Replay the log when present; mark each register `replayed`.
9. Apply reference values and the backing minimum; produce claims, verifier claims and the vector.

For `vtpm`, steps 3 and 5 are the TPM signature by the AK and the AK binding to the CPU report, and step 7 projects PCRs. For GPU submodules the existing NRAS flow applies with the per-device policy gates the library already has.

## 7. Policy and reference values

Policy is a verifier input, never evidence:

```
VerifyPolicy {
  reference: { launch_measurement: [digest], registers: { slot -> [digest] } }
  min_backing: Backing
  freshness: { key: Option<KeyBinding> }
  tcb: { snp_floor?, tdx_allowed_status: [status], require_revocation: bool, require_signed_collateral: bool }
  policy_bits: { allow_debug: bool, allow_migration: bool, require_vmpl0: bool }
  identity: { allowed: [id] }?
  gpu: NvidiaGpuParams (existing)
}
```

Reference values come from confos manifests in v1. CoRIM is the intended carrier once the manifests are published as CoMID; the policy struct is shaped so that swap is additive.

## 8. Rust surface

Types are the profile, one to one. Names are indicative; the PR that lands them is the source of truth.

```rust
pub struct Evidence { pub nonce: Vec<u8>, pub submods: BTreeMap<String, Submod> }
pub enum Submod { Cpu(CpuEvidence), Vtpm(VtpmEvidence), Gpu(GpuDeviceEvidence), Cca(CcaToken) }

pub struct CpuEvidence {
    pub platform: PlatformHint,
    pub report: Report,                 // SevSnp(bytes) | TdxQuote(bytes) | Hcl(bytes)
    pub binding: Binding,               // ReportData | Commitment { header } | VtpmExtraData
    pub endorsements: Option<Collateral>,
    pub registers: Option<Vec<Register>>,
    pub log: Option<EventLog>,
    pub chain: Option<ChainInfo>,
}

pub struct Register { pub index: u16, pub alg: HashAlg, pub value: Vec<u8>, pub source: RegisterSource, pub backing: Backing }
pub enum Backing { Hardware, PrivilegedService, KernelService, Virtualized }   // ordered
pub struct EventLog { pub format: LogFormat, pub data: Vec<u8> }

pub struct Appraisal {
    pub status: Tier,
    pub vector: TrustVector,
    pub attester: AttesterClaims,       // section 5.1
    pub verifier: VerifierClaims,       // section 5.1
}

impl Verifier {
    pub async fn appraise(&self, evidence: &Evidence, policy: &VerifyPolicy) -> Result<Appraisal>;
    pub async fn appraise_json(&self, json: &[u8], policy: &VerifyPolicy) -> Result<Appraisal>;
}
```

Collateral is one type with three transports (inline, cached, fetched), keyed by `CollateralKey`, with `valid_until` taken from each artifact, exactly as the sweep plan describes. The service becomes a router over the library cache.

Schemas: `schemas/cvm-evidence-v1.json` and `schemas/cvm-claims-v1.json` are generated from the Rust types and committed; attestation-go and c8s-verify-js load them in CI and fail on drift. The WASM export becomes `appraise(envelope_json, policy_json)`; the four per-platform exports are deleted.

## 9. Compatibility and migration

The current envelope `{platform, evidence, nvidia_gpu?}` maps mechanically: `platform` splits into `cvm_platform.tee` and `hosting`; `evidence` becomes `cvm_report` with the format chosen by platform; `nvidia_gpu.devices` become `gpu/<uuid>` submodules. The library accepts both forms for two minor releases; `attest()` emits the profile by default with an opt-out; `POST /verify` accepts both; `POST /attest` returns the profile. `VerificationResult` v1 is kept for one release as a projection of `Appraisal` and then removed.

The SNP register driver cannot ship before the verifiers understand the `commitment` mode; until then a report from that image fails every existing verifier's freshness check. Rollout order is therefore: library and WASM, attestation-go, c8s and c8s-verify-js, then the confos image.

c8s moves its EAR from profile 03 to 04 and its private `launch_digest`, `tee_public_key` and `operator_keys_hash` claims into `ear_attester_claims` under the names here (`tee_public_key` stays a c8s extension inside `ear_attester_claims`).

## 10. Security considerations

- Everything outside a hardware signature is a hint or is bound before use (section 4.2). An implementation that reads `cvm_registers.value` without binding it has a fail-open bug by definition.
- Backing is a floor, never a downgrade path: policy states the minimum, the verifier reports the weakest seen, and a `kernel-service` register never satisfies a `hardware` requirement.
- Registers record what measured producers extend. A process that runs code through a path that does not extend a register leaves no trace; on SNP with the register driver this includes root inside the guest. The guarantee boundary is therefore "what the sanctioned producers recorded", and a deployment that needs "everything that ran" must either measure every execution into a slot (an IMA-style exec hook feeding a register) or remove the paths (no root, no exec outside the runtime). The profile carries `backing` and per-slot `replayed` so a relying party can tell which it got.
- The register document's kernel-service argument depends on a concrete restriction set (no module loading, no kexec, no `/dev/mem`, lockdown, eBPF and user namespaces, and every other kernel interface root can reach) that must be enumerated, measured into the launch digest, and checked by the verifier through the pinned image. Until that table exists and is pinned, `backing` for those registers is `virtualized`.
- Debug policy and VMPL are checked before any register claim is evaluated. With debug enabled the host reads guest memory and every register is meaningless.
- Nonces are at least 16 bytes. `report_data` comparisons are constant time over the full field.
- Collateral freshness is the artifact's own window (`nextUpdate`, certificate validity), never a wall clock; a CRL past `nextUpdate` is rejected, and a body without its signing chain is rejected.
- The commitment header is pinned; an attacker cannot use it as 16 bytes of free choice next to the commitment.

## 11. Changes to the two Notion documents

Standardizing Attestation:

- Replace the single JSON object with the two claim sets here: evidence (section 4) and result (section 5). `cert_chain` and `report` move to evidence; `launch_measurement`, `mr`, `tcb`, `host_data` move to results.
- `mr` becomes the register array with `index`, `alg`, `value`, `source`, `backing`, and the slot semantics of section 4.7.
- `host_data` is `32 or 48 or 64` by vendor and is a label; the Kata initdata case is the documented exception.
- `tcb` becomes the vendor-tagged union with all four SNP TCB values, and the floor moves to policy.
- `report_data` is replaced by `cvm_binding` and the mode table.
- Add the policy claims (debug bits per Yolan's comment) as `cvm_policy` and `dbgstat`.
- Remove `isSafe`; adopt `ear_status` and the vector.
- Cloud variants are the `vtpm` submodule with `privileged-service` backing, and Azure launch measurements are pinnable.
- `aael-cbor` becomes CEL.

SEV-SNP Measurement Registers:

- Add the restriction table Yolan asked for, with build, boot and runtime entries and how each is measured and verified.
- Resolve the module-loader contradiction (the NVIDIA open kernel modules are loadable modules).
- State the root-executes-unmeasured-code limit as the guarantee boundary, or add the exec hook.
- Name SVSM at VMPL0 as the target backing and keep the format independent of it.
- Specify the header, `bootseed`, deterministic CBOR for records, the genesis seed decision, the atomicity of extend and commit, kernel-held log storage, slot ownership, and behavior past sixteen workloads.
- Add debug policy and VMPL to "what the verifier checks".

## 12. Decisions needed

1. Genesis seed: constant domain tag (recommended) or launch digest.
2. Slot ownership on SNP: who allocates slots 4 to 15 and how the allocation is recorded (proposed: a `CEL_MGMT`-style management record at first use).
3. CEL private content type for c8s events: profile-private identifier, or a TCG registration request.
4. Whether `cvm_registers` values are required in evidence when a log is present (proposed: required, so a verifier without log support can still pin values).
5. c8s EAR profile move from 03 to 04 in the same release as the library, or one release later.
6. Naming: `cvm_` claim prefix and the `tag:confidential.ai,2026:cvm#1` profile URI.

## 13. Implementation plan

Each step is one reviewable PR in `attestation-rs` unless noted, in this order, after the open hotfixes (#89 to #93) merge.

1. `types`: `Evidence`, `Submod`, `Register`, `Backing`, `EventLog`, `Binding`, `Appraisal`, `VerifyPolicy`; schemas generated and committed; fail-closed expectations; `collateral_verified` and `*_match` removed from the new types.
2. `collateral`: `CollateralKey`, `Collateral` with `valid_until`, one fetcher, one cache with single flight, negative cache and validity-driven refresh; the service thinned to a router; typed collateral errors.
3. `verify`: `appraise` over the new types for SNP, TDX, Azure, GCP, dstack, GPU; envelope v1 accepted through the mapping in section 9; WASM `appraise` export; legacy exports deleted.
4. `platforms` to `pub(crate)` with a curated public surface.
5. `registers`: CEL parsing and replay, register establishment per source, `ats-mr-v1` commitment verification behind a feature until the driver ships.
6. attestation-go and c8s-verify-js: schema pins, `appraise` parity, EAR 04 in c8s.
7. Arm CCA: nested token submodule and the CCA verification rules, when Vera Rubin hardware is available.

Each PR carries the premises it rests on and how they were verified, per the review standard the hotfixes set.
