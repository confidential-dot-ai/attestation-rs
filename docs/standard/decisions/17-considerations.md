# Layer 17: considerations

Sections 15 to 17: security, privacy and IANA considerations. Most of this text states consequences of earlier layers. The entries below, with PRC-4 for Section 15.9, are the places where it adds a requirement or takes a position. Two entries are open.

### CON-1. The limits of the guarantee are stated as limits

Registers record what measured producers extended, and code that runs through a path that extends nothing leaves no trace (15.3). A kernel compromise defeats SEV-SNP software registers (15.4). `ear_all_submods_bound` shows that every attester answered the same nonce and proves nothing about co-location (15.6). Device appraisal and the Azure paravisor are delegated trust (15.11).

- Why: a relying party that misreads what an appraisal establishes makes a wrong decision with a correct result.
- Where: Sections 15.3, 15.4, 15.6, 15.11.

### CON-2. Three requirements outside the verifier (open)

Today Section 15 adds three requirements that fall outside the verifier. Two are on the relying party: check a signed appraisal's `eat_nonce` or `iat` (15.13), and release a secret only to, or over a channel authenticated by, a key the evidence binds (15.15). The third is on the attester's side: the private half of a bound key is generated inside the CVM and never leaves it (15.16). All three were added in the 2026-09-23 review. Sections 5.1 and 5.2 already place two requirements on the relying party (check the certificate's validity window, and compare the reported key with the key of its own channel).

- Question: does a profile for evidence and results place requirements on how its outputs and bound keys are used?
- Options: (a) keep the three as requirements; (b) state them as security considerations without requirement language, and leave Sections 5.1 and 5.2 as they are.
- Recommendation: (a). An unkeyed appraisal can be relayed, so "appraise, then release a key" is unsafe without the binding, and that is the main use of this profile.
- If accepted: no change.

### CON-3. Some signed settings are carried and left alone

SEV-SNP policy bits 21 to 25, `PLATFORM_INFO` bits 2 to 7, the mitigation vectors and TDX `TEE_TCB_SVN2` are neither normalized nor enforced in version 1. A relying party that depends on one reads it from the hardware report in the evidence.

- Why: each needs a policy member and a normalized claim, and none was required by a deployment the profile serves today. Naming them keeps the omission visible.
- Where: Section 15.14.

### CON-4. Stable hardware identifiers are named, and forwarding them is discouraged

`cvm_identity`, the `snp` object's `chip_id`, and the device `ueid` and submodule names identify one machine or device for its lifetime, and the vTPM key (`cvm_tpm_ak`) is stable for a VM instance. A verifier should omit `ear_raw_evidence` when forwarding to a party that does not hold the evidence, and a deployment should remove identity before forwarding to a party that does not need it.

- Where: Section 16.

### CON-5. Three media types in the vendor tree

The profile registers `application/vnd.confidential-ai.sev-snp-report`, `application/vnd.confidential-ai.tdx-quote` and `application/vnd.confidential-ai.pcs-signed+json`, and uses the RFC 9782 EAT types and the Veraison tsm-report type as they are.

- Why: a CMW record needs a media type for the raw report, and the vendor tree lets the profile's owner define one without a standards action.
- Where: Sections 4.3, 10.1, 17.1.

### CON-6. Claim keys are private-use and claim names unregistered (open)

Today (Section 17.2) the profile's CBOR keys sit below -65536, the Private Use range of the CWT Claims registry, the `cvm_` JSON names are unregistered, and version 1 requests no registration. Private use gives no protection against collision: EAR draft-04 assigns -70002, which this profile uses for `cvm_report`, to `ear_veraison_key_attestation`.

- Options: (a) stay private-use for version 1; (b) request registration now, CWT keys in the Specification Required range and the JWT claim names.
- Recommendation: (b), before version 1 is final. This document qualifies as the required specification, and changing keys later is a wire change.
- If accepted: Section 17.2 states the request, and Appendix A, the CDDL labels and the CBOR key columns of Sections 4.1, 4.3, 4.4, 12.2 and 12.3 take the assigned keys. No implementation reads CBOR yet, so nothing deployed changes.

### CON-7. Unregistered code points: a CEL content type with a registration request, the Arm CCA tags by allowlist

The CEL content type `cvm` uses the value 200 through the CEL extension socket, and a request to the Trusted Computing Group accompanies publication. The Arm CCA tags 399 and 907 are accepted by allowlist. The profile identifier is a tag URI and needs no registration.

- Where: Sections 17.3, 17.4, 17.5.

### CON-8. A verifier bounds the work evidence can make it do

Bounds are applied before any request, collateral is cached by its key, and collateral is requested only from origins the verifier's configuration names. The envelope chooses its own profile version, so a relying party that needs a later version's guarantee checks the profile URI in the appraisal.

- Why: evidence drives fetches before anything is authenticated, and an unauthenticated claim must never choose where a verifier connects.
- Where: Sections 15.10, 15.17, 15.18.

### CON-9. A verifier that keeps state does not go back to an older CRL

A CRL still inside its window can predate a revocation. A verifier that keeps state should refuse a CRL whose CRL number is lower than one it has accepted for the same issuer, and should refresh collateral at the vendor's publication cadence.

- Why: validity windows are weeks long, so an attester or a stale cache could otherwise present a CRL from before a revocation. The same gap for Intel's TCB Info is closed by `tcbEvaluationDataNumber` floors (POL-4).
- Where: Section 15.8. The reference implementation does not track CRL numbers.
