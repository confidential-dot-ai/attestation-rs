# Statements without a case

Normative statements of the design doc (sections 4 to 7) that no case in
`cases/` exercises yet, with what closes each. The list shrinks; an entry is
removed in the commit that adds its case.

| Section | Statement | What closes it |
| --- | --- | --- |
| 4.4, 4.5, 4.9 | an appraisal in `commitment` mode, and every rule of section 4.9 past the envelope's shape (genesis, `chain_len` against the log, the boot record, claim records, slot owners, `reference.slot_owners`) | evidence from the SNP register driver, which does not exist yet; the envelope's shape rules for the mode have cases, and the vectors of Appendix B cover the formulas |
| 4.5 | an appraisal bound through a key (`spki-sha256`, `x509-tbs-sha256`, `raw`), and the certificate pattern's `not_before` and `not_after` | a recording made with a key binding; every refusal these rules make has a case |
| 4.4, 4.5, 5.3, 7 | the NRAS exchange: token signatures, issuer, claims version, `submods` digests, the device nonce, device claims, `ear_nvidia_evidence`, the device gates, and `ear_all_submods_bound` `"false"` | a recording of GPU and NVSwitch evidence with its NRAS exchange; the device submodule's shape, the architecture allowlist, the device bound and `gpu.required` have cases |
| 4.4 | `cvm_tpm_ak`: the HCL report's type names the TEE of `cvm_platform` | a case that changes the recorded HCL report's type |
| 4.5, 4.7 | `cca-challenge`, `cca-rem` and the Arm CCA rules | Arm CCA hardware; a nested token has a case that shows the platform is not implemented |
| 4.7 | `snp-vmr` registers in an appraisal | the SNP register driver |
| 4.8 | `tpm2-event-log` on the vtpm submodule | an Azure recording that includes the vTPM event log |
| 4.10, 4.1 | the CBOR encoding | the CBOR entry point |
| 6 | step 3: VLEK detection; step 6: `revoked` | a VLEK recording; a CRL that revokes a certificate we hold, which no vendor has issued |
