# Layer 8: appraisal results

Section 12 and Appendix B.4: what a verifier asserts and in what form. Three entries are open, and all three change values a relying party keys its rules on.

### RES-1. The appraisal is an EAR claims set, unsigned by default

The result is an EAR draft-04 claims set with one entry per evidence submodule, under the same names. It carries no signature: a verifier that hands it across a trust boundary signs it as an EAR token (JWT or CWT) or delivers it over an authenticated channel. A failed appraisal produces no appraisal.

- Why: EAR is the result format the RATS working group is standardizing, and a library verifier inside the relying party has nobody to sign for.
- Rejected: a profile-specific result object, and a mandatory signature.
- Where: Section 12.1, 15.13.

### RES-2. Normalized `cvm_*` claims are the normative output

Every `cpu` submodule reports its facts under the same claim names whatever the platform. `cvm_platform`, `cvm_launch_measurement`, `cvm_freshness`, `cvm_host_data`, `cvm_policy`, `cvm_tcb`, `cvm_identity` and `dbgstat` are always present. `cvm_registers` is present when the submodule has registers, `cvm_owner` is absent on Arm CCA, and `cvm_chain` and `bootseed` appear in `commitment` mode. `dbgstat` covers the TEE's guest-debug facility only.

- Why: a relying party writes one rule against one name. The platform-specific content sits inside `cvm_tcb`, `cvm_owner`, `cvm_identity` and the per-TEE members of `cvm_policy`, where it carries meaning.
- Where: Section 12.2. Cases: `snp-hardware-affirmed` (layer 10), `tdx-v4-quote-with-fixture-collateral` (layer 3).

### RES-3. Compatibility objects ride beside the normalized claims

A TDX submodule also carries the Intel Trust Authority names (`tdx_mrtd`, `tdx_rtmr0` to `tdx_rtmr3` and the rest) that the TDX confidential-GPU EAR draft reuses. An SEV-SNP submodule also carries the `snp` object with the names and types the Confidential Containers Trustee verifier emits. Device submodules carry NRAS's claims verbatim. The `cvm_*` claims are normative. The `tdx_*` names and the NRAS claims are carried as those vocabularies define them, and some (`tdx_xfam`, `tdx_mrseam`, `tdx_mrsignerseam`) appear nowhere else in the appraisal.

- Why: policies written against Intel Trust Authority, Trustee and NRAS read these appraisals without a rewrite. The draft's container and submodule labels differ, and Section 12.6 gives the mapping.
- Where: Sections 12.6, 12.7.

### RES-4. Verifier claims record what was checked

`ear_verifier_claims` carries `cvm_collateral` (per check: `checked`, `skipped` with a reason, or `not-applicable`), `cvm_reference` (which pins applied and matched) and `cvm_backing_min` (the floor and the weakest backing seen).

- Why: the same appraisal can come from full collateral or from a waiver, and the relying party has to be able to tell.
- Rejected: one `collateral_verified` boolean, which hid which check ran.
- Where: Section 12.3. Cases: `snp-crl-checked` (layer 3), `azure-snp-pcr8-pinned`.

### RES-5. The trustworthiness vector follows AR4SI, and a category without an assertion is absent

`instance-identity` is 2 only under a machine allowlist. `configuration` is 2 when the guest settings hold. `executables` is 2 when the launch measurement and every pinned register match, 3 when only the launch measurement is pinned, and absent without a launch pin. `hardware` is 2 when the chain, the signatures, revocation and the TCB assessment all hold, 32 for an accepted vendor status with known vulnerabilities, and absent when the TCB was not assessed or revocation was waived. `runtime-opaque` is 2 with debug off and 96 with it on. `ear_status` is the worst tier the vector reaches.

- Why: an absent category says "not assessed", which a 2 would overstate and a 0 would blur. `executables` needs the launch pin because nothing else vouches for the code that measured the registers.
- Where: Section 12.4. Cases: `snp-launch-measurement-pinned`, `tdx-registers-pinned`, `tdx-registers-pinned-without-launch-measurement`, `azure-snp-pcr8-pinned`.

### RES-6. The policy identifier names the effective policy

`ear_appraisal_policy_ids` holds the profile URI and `ni:///sha-384;<base64url>`, the SHA-384 of the JCS serialization of the policy with every default filled in. Two appraisals carry the same identifier exactly when their effective policies serialize to the same bytes.

- Why: a relying party that receives an appraisal from a verifier it does not operate needs to know which requirements produced it. Filling the defaults makes an empty policy and a spelled-out default policy the same identifier.
- Where: Section 12.5, Appendix B.4. Case: `snp-crl-checked-with-defaults-spelled-out`. BND-8 (layer 5) is open against this entry.

### RES-7. `configuration` is 96 for a policy-admitted VMPL above 0 (open)

Today an SEV-SNP report from VMPL 1 to 3, which a policy admits by clearing `require_vmpl0`, gets `configuration` 96, so the submodule is `contraindicated`. A guest that requests its own report from under an SVSM lands there, as the case `snp-vlek-chain-appraises` shows with a VMPL 1 recording. An Azure guest is unaffected: its report is the one the paravisor requested, and it carries VMPL 0. AR4SI defines 96 as a configuration that is "unsupportable as it exposes unacceptable security vulnerabilities".

- Options: (a) keep 96; (b) 32, "includes or exposes known vulnerabilities"; (c) 2 when the launch measurement is pinned and matched, and 36 ("elements of the configuration relevant to security are unavailable to the Verifier") when it is not.
- Recommendation: (c). The code at VMPL 0 is covered by the launch measurement, so a pin vouches for it, and without a pin the verifier knows nothing about it.
- If accepted: Sections 3.3 and 12.4 change. The case `snp-vlek-chain-appraises` pins no launch measurement, so under (c) its expected appraisal moves to `configuration` 36 and status `warning`, its statement changes, and the corpus revision rises.

### RES-8. Device submodules report `sourced-data` (open)

Today a device submodule's vector carries `sourced-data` 2 when NRAS affirmed the device and every device gate held. AR4SI defines `sourced-data` as the integrity of "data objects from external systems used by the Attester", and `hardware` 2 as "passed its hardware and/or firmware verifications needed to demonstrate that these are genuine/supported".

- Options: (a) keep `sourced-data`; (b) report `hardware` 2 when NRAS affirms the device.
- Recommendation: (b). NRAS checks the device's certificate chain and firmware measurements, which is what `hardware` describes.
- If accepted: Sections 9.7.3 and 12.4 change. No expected appraisal in the corpus carries a device submodule yet.

### RES-9. `ear_all_submods_bound` is a top-level text claim (open)

The appraisal carries `ear_all_submods_bound` as `"true"` or `"false"`, the form the TDX confidential-GPU EAR draft defines. EAR draft-04 section 3 requires an EAR extension to be a map, so a relying party that applies that rule alone refuses the claim. Section 12.6 records the conflict.

- Options: (a) follow the confidential-GPU draft, as today; (b) emit a map of the profile's own; (c) emit both.
- Recommendation: (a), and raise the conflict with the authors of both drafts. The claim exists to compose with that draft, and a private form would compose with nothing.
- If accepted: no change. If the drafts settle on a map, the result format changes and the profile identifier with it.

### RES-10. Two claims are defined and not emitted by default

`ear_raw_evidence` (the envelope as appraised and the endorsements used) is optional, and a verifier should omit it when forwarding to a party that does not hold the evidence. `cvm_workload_id` is reserved and never emitted in version 1.

- Why: raw evidence lets a decision be re-verified after a vendor withdraws collateral, and it carries the stable hardware identifiers of Section 16.
- Where: Sections 12.1, 12.2, 15.9, 16. The reference implementation does not emit `ear_raw_evidence`.
