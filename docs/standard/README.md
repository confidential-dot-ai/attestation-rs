# CVM attestation standard, version 1: map

This directory holds the working draft of the EAT profile `tag:confidential.ai,2026:cvm#1`: one contract for evidence, runtime measurements and appraisal results across AMD SEV-SNP, Intel TDX, Arm CCA, Azure and Google Cloud confidential VMs, and NVIDIA GPUs. The normative text is [`cvm-attestation-v1.md`](cvm-attestation-v1.md). This page is the way in: the model, one exchange end to end, the modules with their status, and how the draft is reviewed.

## The model

1. Three messages, three authors. The attester sends evidence, the relying party supplies a policy, and the verifier returns an appraisal or a refusal. The launch measurement in an appraisal is always the value the verifier extracted from the signed report, and the other attester claims are signed or bound.
2. Evidence is an unsigned envelope around unmodified hardware reports, one submodule per attester: `cpu`, `vtpm`, `gpu/<ueid>`, `nvswitch/<ueid>`.
3. Every evidence field is signed (by the hardware or a vendor), bound (checked against signed bytes before use), a hint (it selects a parser and never raises a conclusion) or reserved.
4. One nonce covers the envelope. The anchor is the nonce, or a hash of the nonce and a key, and each CPU attester binds it in one declared mode: report data, a register commitment, a vTPM quote or the Arm CCA challenge. A device binds the nonce itself, through NRAS.
5. Runtime state is a set of measurement registers. Each carries its source and its backing, the strength of what protects it, and an event log replays to the register values.
6. Collateral (certificates, CRLs, TCB documents, token keys) arrives inline or from the verifier's own source, is anchored to pinned vendor roots either way, and is fresh by its own validity window at an evaluation time that is an input.
7. Verification is nine steps that fail closed. Every submodule is appraised, and one failure refuses the whole envelope with one of 24 codes.
8. The appraisal is an EAR claims set: per submodule, normalized `cvm_*` claims, what the verifier checked, and an AR4SI trustworthiness vector.
9. The policy is one JSON object in which every member is optional and every default fails closed. The appraisal names the policy that produced it.
10. Conformance is a corpus. Each case fixes evidence, policy, collateral and time, and states the appraisal or the refusal code. The reference implementation generates the expected results.

## One exchange, end to end

SEV-SNP on bare metal, challenge pattern, `report-data` binding. The corpus case is `snp-hardware-affirmed`, and Appendix D.1 prints its evidence and appraisal.

1. The relying party sends a nonce of 16 to 64 bytes.
2. The attester asks the firmware for a report with `REPORT_DATA = pad64(nonce)` and wraps it: `eat_profile`, `eat_nonce`, `cvm_version`, and a `cpu` submodule holding `cvm_platform` (a hint), `cvm_report` (the 1184-byte report, unmodified), `cvm_binding` (`challenge`, `report-data`) and, inline, the VCEK.
3. The verifier parses the envelope within its bounds, derives the generation from the report's CPUID fields, verifies the VCEK to the pinned AMD root and the report's signature, and cross-checks the VCEK's extensions against the report.
4. It enforces the guest policy (debug off, VMPL 0, no migration agent), checks `REPORT_DATA == pad64(nonce)`, checks AMD's CRL and the TCB floor, and applies the reference values the policy pins.
5. It returns the appraisal: status `affirming`, the launch measurement, the TCB, the guest settings, the chip identifier, the trustworthiness vector and the identifier of the policy. A failed check returns one refusal code and no appraisal.

Every other platform is this exchange with a difference:

| Platform | What differs |
| --- | --- |
| Intel TDX | a TD quote; the chain is Intel's PCK certificates, with the QE Identity and TCB Info as collateral; four hardware RTMRs are registers, and a CCEL or CEL log replays to them |
| Azure | the anchor is bound in a vTPM quote and the hardware report binds the vTPM's key; PCRs are registers in a `vtpm` submodule; the policy must pin the launch measurement |
| Google Cloud | as bare metal, with hosting `gcp` |
| dstack | as bare metal for TDX or SEV-SNP, with hosting `dstack` and the raw report only; TDX guests add dstack's JSON event log |
| NVIDIA GPUs and NVSwitch | one submodule per device; NRAS appraises the device evidence, and the verifier checks NRAS's signed answer, the nonce and the device policy |
| SEV-SNP with a register provider | report data is a commitment over 16 software registers, and a log replays to them; the policy must pin the launch measurement |
| Arm CCA | the CCA token nests as it is; the realm challenge carries the anchor; a vendor CoRIM authenticates the platform |

## Modules and status

The draft is a core contract plus modules. Each module has its own status, and a module moves up only through its gate:

| Status | Meaning | Gate to reach it |
| --- | --- | --- |
| experimental | specified; no implementation, or no genuine evidence behind it | the text exists |
| draft | implemented in the reference implementation; decisions still open or unreviewed | the reference implementation passes the module's cases |
| candidate | decisions closed | every entry in the module's decision file is accepted, every rule has a case or a stated reason in `conformance/UNCOVERED.md`, and the hardware run is green |
| stable | the wire format is frozen | a second implementation passes the module's cases without reading the first |

The layers of the review stack, in order:

| Layer | Module | Adds | Status | Behind it |
| --- | --- | --- | --- | --- |
| 1 | Map | this page, the decision register's format | | |
| 2 | Model | front matter, Sections 1 to 3 | draft | the principles every later layer applies |
| 3 | Procedure and conformance | Sections 11 and 14, the corpus layout | draft | implemented; corpus 1.9, 163 cases |
| 4 | Evidence | Sections 4.1 to 4.4, 4.7, 4.8 | draft | implemented for JSON; the CBOR rules these sections carry are decided in layer 16 |
| 5 | Freshness and binding | Sections 5.1 to 5.4, Appendix B.1 | draft | implemented; one open decision |
| 6 | Endorsements | Section 10 | draft | implemented |
| 7 | Policy | Sections 13.1 to 13.4 | draft | implemented |
| 8 | Appraisal results | Section 12, Appendix B.4 | draft | implemented; three open decisions |
| 9 | Registers and logs | Sections 6 and 7 | draft | implemented for TDX RTMRs and vTPM PCRs |
| 10 | SEV-SNP | Section 9.1 | draft | implemented; hardware run |
| 11 | TDX, Google Cloud, dstack | Sections 9.2, 9.3, 9.5, Appendix B.5 | draft | implemented; TDX hardware run |
| 12 | Azure | Section 9.4 | draft | implemented; hardware run |
| 13 | NVIDIA devices | Sections 4.5, 9.7, 13.5 | draft | implemented; no recorded NRAS exchange in the corpus |
| 14 | SEV-SNP software registers | Section 8, Appendices B.2 and B.3 | experimental | verifier side only; no register provider exists |
| 15 | Arm CCA | Sections 4.6 and 9.6 | experimental | no implementation |
| 16 | Certificate pattern and CBOR | Section 5.5, Appendix A, and the CBOR rules of layer 4 | experimental | no certificate parser, no CBOR entry point |
| 17 | Considerations | Sections 15 to 17 | draft | two open decisions |
| 18 | Companions | Sections 18 and 19, Appendices C to E, Acknowledgments, schemas, vector file | draft | checked by the reference implementation's tests |

The experimental modules are named by the core (their binding modes, claims and sources are enumerated in Sections 4 to 6), so promoting one later changes nothing on the wire for an implementation of the core.

## How the draft is reviewed

The draft arrives as a stack of pull requests, one layer each, in the order of the table. Layer 1 adds this page and the format of the decision register. Every later layer adds three things:

- its sections of `cvm-attestation-v1.md`, at their final positions. Section numbers are final from the first layer, so the file has gaps until the stack is complete, and a forward reference resolves in a later layer;
- its file under [`decisions/`](decisions/README.md): one entry per choice the layer makes, with what was chosen, why, what was rejected, and where the text and the corpus carry it;
- the conformance cases that cite its sections, with their inputs. Inputs are marked as generated, so a diff collapses them; the case files are the part to read.

A reviewer decides the entries. Merging a layer accepts them. An entry marked open records a question with a recommendation; the text states the current choice until the question closes, and the module stays at draft. After a layer merges, a change to a decision is its own pull request and changes the entry, the text and the cases together (Section 14.5), paired with the reference implementation's change.

The reference implementation lives on the branch `design/cvm-attestation-profile-v1`. It carries the top of the stack byte for byte in `docs/standard/`, `schemas/` and `conformance/`, and passes every case natively and through WebAssembly.
