# Statements without a case

Normative statements of the standard (`docs/standard/cvm-attestation-v1.md`,
sections 4 to 13) that no case in `cases/` exercises yet, with what closes
each. The list shrinks; an entry is removed in the commit that adds its case.
Most rows need evidence the hardware signs, since changing a signed report
exercises its signature and not the rule.

| Section | Statement | What closes it |
| --- | --- | --- |
| 5.4, 6.5, 8 | an appraisal in `commitment` mode, `snp-vmr` registers in an appraisal, and every rule of section 8 past the envelope's shape (genesis, `chain_len` against the log, the boot record, claim records, no other `ats` records, slot owners, `reference.slot_owners`, chain memory) | evidence from a register provider, which does not exist yet; the envelope's shape rules for the mode have cases, and the vectors of Appendix B cover the formulas |
| 5.1, 5.2, 5.3 | an appraisal bound through a key (`spki-sha256`, `x509-tbs-sha256`, `raw`), and the certificate pattern's `not_before` and `not_after` | a recording made with a key binding; every refusal these rules make has a case |
| 5.5 | evidence carried in `id-pe-cmw`, and the dstack certificate extensions | parsing in the reference implementation, and a recorded certificate |
| 9.7, 12.6, 13.5 | the NRAS exchange: token signatures, issuer, claims version, `submods` digests, the device nonce, each device token's `hwmodel` against its batch, device claims, `ear_nvidia_evidence`, the device gates, a request that relaxes NRAS's certificate checks, and `ear_all_submods_bound` `"false"` | a recording of GPU and NVSwitch evidence with its NRAS exchange; the device submodule's shape, the architecture allowlist, the device bound and `gpu.required` have cases, and the reference implementation's unit tests cover the `hwmodel` comparison and the certificate-hold refusal |
| 9.4.4 | a `tpm2-event-log` on the `vtpm` submodule replays | an Azure recording that includes the vTPM event log |
| 9.1.2, 9.1.3 | report version 6; Turin models 0x12 to 0x1F | recordings from firmware that emits version 6 and from those Turin parts; the reference implementation's unit tests parse both |
| 9.1.2, 9.1.4 | `SIGNATURE_ALGO` other than 1; `KEY_INFO` reserved bits, `MASK_CHIP_KEY` and `SIGNING_KEY` values other than 0 and 1 | a genuine report with those values, which AMD firmware does not sign; changing a signed report exercises the signature, and the reference implementation's unit tests cover each |
| 9.1.4 | the ASK or ASVK serial against the CRL; the ARK and ASK or ASVK windows | a CRL that revokes a current intermediate, and an evaluation time inside the VEK's window but outside its chain's, neither of which exists; the unit tests use AMD's Genoa CRL, which revokes the original Genoa ASK (serial 020001), and the pinned roots' windows |
| 9.2.2 | the attestation key type and the QE vendor ID | a quote with another key type or QE vendor, which Intel's QE does not produce; the reference implementation's unit tests cover both |
| 9.2.3 | the TDX module identity (`MRSIGNERSEAM`, `SEAMATTRIBUTES`, a `tdxModuleIdentities` entry and its levels); Intel's TCB level ordering and matching; the TCB Info's PCE identifier; a TCB Info or QE Identity without `nextUpdate`, or of another version or `id`; the QE and module statuses converged with the platform's; the TCB signing certificate's role and the Root CA CRL over it | collateral Intel signed in each shape, and a recording whose `TEE_TCB_SVN[1]` is not zero with the TCB Info for its FMSPC; every Intel TCB Info carries PCE identifier `0000`; the reference implementation's unit tests cover each against altered collateral |
| 9.2.5 | the TD attribute groups (profiling counted as debug, `RESERVED_P` ignored, `ICSSD`, `SERVTD_EXT`, `LASS` and `TPA` permitted) | recordings of TDs launched with those attributes |
| 9.6, 5.4, 6.2 | `cca-challenge`, `cca-rem` and the Arm CCA rules | Arm CCA hardware and an implementation; a nested token has a case that shows the platform is not implemented |
| 11 | step 6: `revoked` | a CRL that revokes a certificate we hold, which no vendor has issued |
| 4.7, 4.8 | the CBOR encoding | the CBOR entry point |
| 4.1, 11 | step 1: an `eat_nonce` that differs from the relying party's nonce is refused with `binding-mismatch` | a relying-party nonce in the case format; the reference implementation enforces the rule in its service, CLI and WebAssembly entry points |
| 8.5, 9.1.5 | a report whose `VMPL` is above 3 (host-requested) is refused whatever the policy says | a recording of a host-requested report |
