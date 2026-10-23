# Layer 10: SEV-SNP

Section 9.1: SEV-SNP guests on bare metal, Google Cloud and dstack, and the hardware report Azure wraps. Most of this section transcribes AMD's ABI (publication 56860) and VCEK specification (57230); those facts are checked against the sources, the hardware run and the tests. The entries below are the choices this profile makes on top of them.

### SNP-1. Report versions 3 to 6, and the generation comes from signed data

Versions 3 to 6 are accepted, and version 2 only with hosting `azure`. The generation (Milan, Genoa, Turin) is derived from the report's CPUID family and model. A version 2 report has no CPUID fields, so its generation is the suffix of the VEK issuer's name, which the chain then authenticates. Any other family or model is refused with `report-invalid`.

- Why: the generation selects the pinned roots and the TCB layout, so it cannot come from a hint. Later generations are refused because their TCB layout is undefined here.
- Where: Sections 9.1.2, 9.1.3. Cases: `snp-generation-hint-agrees`, `snp-generation-hint-contradicts-report` (layers 4 and 2). The corpus holds no version 2, version 6 or Turin report (`UNCOVERED.md`).

### SNP-2. AMD's roots are pinned per generation, and the signature is checked strictly

The verifier pins the ARK, ASK and ASVK of each generation (Appendix E). A VCEK must be signed by the ASK and a VLEK by the ASVK, every certificate must be inside its window at the evaluation time, and ASK and ARK certificates supplied in the evidence are ignored. The report's signature covers bytes 0x000 to 0x29F exactly as received, and the upper 24 bytes of `R` and of `S` must be zero.

- Why: a chain the attester supplies proves nothing about who issued it. The padding rule leaves one encoding of a signature, so no byte outside the signed range is free for an attester to choose.
- Where: Section 9.1.4 (steps 1 to 3). Cases: `snp-hardware-affirmed`, `snp-tcb-reserved-byte-altered`, `snp-signature-upper-bytes-nonzero`.

### SNP-3. The endorsement is cross-checked against the report

The VEK's SPL extensions must equal the components of `REPORTED_TCB`, a Turin VEK must carry the FMC SPL, and a VCEK's hardware ID must equal `CHIP_ID`. A failure is `chain-invalid`. An inline VEK is bound with this check before it is used, so one for another chip or TCB is ignored and the verifier's own source serves.

- Why: the certificate has to endorse this report. AMD's VLEK definition (58369, revision 0.10) predates Turin and lists no FMC extension, so the Turin rule for a VLEK rests on the VCEK specification alone and no Turin VLEK was available to check.
- Where: Sections 9.1.4 (step 4), 10.2. Cases: `snp-inline-vek-for-another-tcb`, `snp-inline-vek-for-another-tcb-provider-serves` (layer 6). No genuine input isolates the cross-check itself (`UNCOVERED.md`).

### SNP-4. A VLEK is accepted and identifies no machine

A report signed by a cloud provider's VLEK is authenticated through the ASVK. The VLEK carries no hardware ID, so no endorsement covers the report's `CHIP_ID`, and under a machine allowlist the report is refused with `machine-not-allowed`. The VLEK must be inline, since AMD serves VLEKs only to the provider.

- Why: VLEK-signed reports are what some providers issue, and refusing them would exclude those platforms. Their weaker identity is stated where a relying party asks for identity.
- Where: Sections 9.1.4 (steps 2, 4 and 6), 13.3. Cases: `snp-vlek-chain-appraises`, `snp-vlek-without-inline-vek`, `snp-vlek-masked-chip-identifies-no-machine` (layer 7).

### SNP-5. Revocation is checked by default

AMD's CRL for the generation, signed by the ARK and inside its window, must not list the ASK or ASVK in the chain. The check is required unless the policy sets `tcb.require_revocation` to false. VCEK serial numbers are zero, so a compromised chip is excluded through TCB floors and allowlists.

- Where: Section 9.1.4 (step 5). Cases: `snp-crl-checked`, `snp-crl-forged`, `snp-revocation-required-without-crl` (layer 3), `snp-crl-past-its-window` (layer 6).

### SNP-6. A host-requested report is always refused, and VMPL 0 is the default

A report whose `VMPL` is above 3 was requested by the host (`SNP_HV_REPORT_REQ`), binds no anchor, and is refused whatever the policy says. A VMPL other than 0 is refused under `require_vmpl0`, which defaults to true.

- Why: the firmware zero-fills a host-requested report's `REPORT_DATA`, so it can never answer a challenge. RES-7 (layer 8) is open on how an admitted VMPL 1 to 3 is reported.
- Where: Sections 8.5, 9.1.2, 9.1.5, 13.1. Case: `snp-vmpl-nonzero-refused`. A host-requested report has no recording (`UNCOVERED.md`).

### SNP-7. Reserved byte ranges are checked, reserved bits inside fields are left alone

A non-zero byte in a reserved range of the report (listed per report version in Section 9.1.2) is refused with `report-invalid`, as are a signature algorithm other than ECDSA P-384 and a `KEY_INFO` that masks the chip key or names another signing key. Reserved bits inside `POLICY`, `PLATFORM_INFO` and the TCB values are left unchecked.

- Why: the firmware refuses a guest policy with reserved bits set at launch, and later ABI revisions assign bits in those fields, so a verifier that refused them would break on a firmware update.
- Where: Section 9.1.2. No case: AMD firmware signs no report with these values, and changing a signed report exercises the signature, as `snp-tcb-reserved-byte-altered` shows (`UNCOVERED.md`).

### SNP-8. `hardware` is 2 only when a TCB floor applied and revocation was checked

AMD runs no TCB status service, so the policy's floor is the only TCB assessment. Without a floor, or with revocation waived, the `hardware` category makes no claim.

- Why: a genuine chip on firmware nobody assessed is a weaker statement than "the hardware is acceptable", and the vector should say which one was made.
- Where: Sections 9.1.5, 12.4. Case: `snp-hardware-affirmed`.
