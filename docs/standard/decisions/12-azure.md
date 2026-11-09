# Layer 12: Azure

Section 9.4: Azure SEV-SNP and TDX confidential VMs, where a paravisor holds a vTPM between the guest and the hardware.

### AZR-1. The hardware report and the vTPM evidence are separate submodules

The `cpu` submodule carries the hardware report: the SNP report from the HCL report's hardware area, or a TD quote obtained over the HCL report's TD report. The `vtpm` submodule carries the TPM quote, the PCRs and the HCL report, which is the attestation key's proof. An SEV-SNP `cpu` report must be byte for byte the HCL report's hardware area.

- Why: the hardware report is appraised by the same code as on bare metal, and the vTPM's claims carry their own, weaker backing.
- Rejected: the HCL report as a report type of the `cpu` submodule, which would have made Azure a separate TEE to every consumer.
- Where: Sections 9.4, 9.4.1, 9.4.2. Cases: `azure-snp-through-vtpm`, `azure-tdx-through-vtpm`, `azure-snp-cpu-report-not-the-hcl-area`.

### AZR-2. The anchor is bound in the quote, and the hardware binds the quote's key

The TPM quote's `extraData` equals the anchor, and the hardware report's report data carries the SHA-256 of the HCL variable data that holds the attestation key.

- Why: the guest cannot place a value in the hardware report on Azure, so freshness goes through the vTPM, and the key that signs the quote has to be tied to genuine hardware.
- Where: Sections 5.4, 9.4.2, 9.4.3. Cases: `azure-snp-nonce-not-bound`, `azure-snp-nonce-length-differs` (layer 5).

### AZR-3. The launch measurement must be pinned

`vtpm-extradata` is refused with `binding-mismatch` unless the policy pins the launch measurement, which covers the paravisor and firmware. This is BND-6 applied to Azure.

- Why: the paravisor creates the attestation key and is the only thing that makes the quote mean anything. Without the pin, a guest on other hardware can present a fabricated HCL report with its own key.
- Where: Section 9.4.4. Case: `azure-snp-pcr8-pinned-without-launch-measurement`.

### AZR-4. Only PCRs inside the signed selection become registers

A register of the `vtpm` submodule must be a PCR the quote selected, must equal the quoted value, and must name the quoted bank as its `alg`. The registers have backing `privileged-service`. Version 1 appraises the SHA-256 bank only, and the quote must hold exactly one selection, for that bank; anything else is refused with `unsupported`.

- Why: the quote's digest covers the selected PCRs and nothing else. A multi-bank selection has a digest over values the envelope does not carry.
- Where: Sections 4.4, 9.4.3, 9.4.4. Cases: `azure-snp-quoted-pcrs-altered`, `azure-snp-register-outside-bank` (layer 9), `azure-snp-register-differs-from-quoted-pcr` (layer 4). A quote whose selection is not one SHA-256 selection has no case (`UNCOVERED.md`).

### AZR-5. The HCL report's layout is fixed

The request data version must be 1, the report type must name the `cpu` submodule's TEE, the hash type must be SHA-256, and the variable data must hold exactly one `HCLAkPub` key, RSA of 2048 bits. A violation is `envelope-invalid`, since the HCL report outside the hardware area is unsigned.

- Why: OpenHCL's request version 2 inserts a field before the variable data, and a verifier that read it under the version 1 layout would hash the wrong bytes.
- Where: Section 9.4.1. Cases: `azure-snp-hcl-version-not-1`, `azure-snp-hcl-report-type-for-tdx`, `azure-snp-hcl-hash-type-not-sha256`, `azure-snp-hcl-variable-data-size-includes-padding`.

### AZR-6. The vTPM's vector carries `executables` alone

The `vtpm` submodule reports `executables` 2 when the policy pins at least one PCR and every pinned PCR matched, and 0 when it pins none. Hardware, configuration and runtime claims belong to the `cpu` submodule that binds the key. Guest configuration delivered as Confidential Containers initdata is pinned through PCR 8.

- Why: a vTPM adds measurements and nothing about the hardware, so its vector says only what its PCR pins establish. AR4SI requires a vector to carry at least one category, hence the 0.
- Where: Sections 9.4.4, 12.4. Cases: `azure-snp-pcr8-pinned`, `azure-snp-pcr8-not-in-reference` (layer 7).
