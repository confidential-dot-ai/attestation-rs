# Why this CVM attestation format exists

Status: design rationale and conformance questions, 2026-09-21. Read beside the [profile](cvm-attestation-profile-v1.md). This explains the branch's choices; it does not certify the implementation or establish that other implementations interoperate with it. No kernel driver is implemented by this document.

## 1. Start with the problem, before choosing a standard

A consumer needs to answer several different questions:

1. Is this evidence authentic, and which authority authenticated it?
2. Which base image launched, and does it match an approved reference?
3. Which later measurements were recorded, by which producer, under which protection?
4. Does the evidence bind the challenge and key for this exchange?
5. Are firmware versions and security settings acceptable under this deployment's policy?
6. If several components supplied evidence, what relationship between them was actually established?

One generic `verified: true` cannot explain which questions were answered. A signature can be genuine while the workload is unapproved. A log can replay correctly while its producer is untrusted. A CPU and GPU can answer the same challenge without proving their physical proximity or a protected data path between them.

The original flat JSON also places raw evidence next to derived claims. Those fields need different treatment: receiving `launch_measurement` from a caller is different from extracting it from a verified hardware report. Separating Evidence, Policy, and Appraisal makes those authorities explicit. The IETF's [RATS architecture, RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html#section-4), provides established names for these roles and messages; our security argument still needs to stand on its own.

## 2. What EAT and EAR mean, and where they came from

| Name | Source and status | Role in this proposal |
| --- | --- | --- |
| EAT: Entity Attestation Token | [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html), published Standards Track RFC, April 2025 | Common claim vocabulary and a mechanism for defining use-case-specific profiles. EAT is not itself a complete CVM format and can represent evidence or results. |
| EAR: EAT Attestation Results | [draft-ietf-rats-ear-04](https://datatracker.ietf.org/doc/html/draft-ietf-rats-ear-04), active Internet-Draft when checked | A particular EAT-based result format, carrying a verifier's appraisal and its context. It is not a finalized RFC. |
| AR4SI: Attestation Results for Secure Interactions | [draft-ietf-rats-ar4si-10](https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-10), Internet-Draft | Vocabulary for reporting different dimensions of an appraisal. Values are category-specific assertions, not confidence percentages. |
| CMW: Conceptual Message Wrapper | [RFC 9999](https://www.rfc-editor.org/rfc/rfc9999.html#section-3.1) | A typed container for a report, endorsement, or other attestation message. Packaging alone supplies no authenticity. |
| UJCS/UCCS | [RFC 9781](https://www.rfc-editor.org/rfc/rfc9781.html#section-7) | Unprotected JSON/CBOR claims-set formats. Their use requires an explicit protection argument; an unsigned JSON object does not become trustworthy by using standard names. |

These are IETF specifications, not formats invented in the two Notion drafts. The branch's profile selected them as building blocks. There is also a concrete existing consumer: c8s's `internal/earclaims/claims.go` names `tag:ietf.org,2026:rats/ear#03`, and `internal/ear/issuer.go` signs JWT results. Moving c8s to `#04` is a proposed coordinated migration, not a change already made by this branch. Some c8s comments expand EAR as “Entity Attestation Result”; the referenced IETF document's title is “EAT Attestation Results.”

The adoption argument is compatibility with existing attestation tooling and c8s's result path. The costs are extra structure, exact encoding requirements, and tracking draft revisions. A small private JSON format would be easier initially, but would leave every external integration to define its own translation. EAT/EAR adoption is justified only if we implement and test the promised mapping.

## 3. What this project needs to contribute

The project-specific design is the CVM contract and its proof obligations:

- A common way to describe launch and runtime measurements without treating their protection levels as equal.
- A backing model with enforceable minimums, supported by actual hardware or approved measured software.
- Exact mappings from each hardware report into normalized claims, preserving platform differences.
- A nonce/key binding contract and a precise statement of what multi-component binding proves.
- The SNP register commitment, producer requirements, log ordering, and kernel trust argument.
- Collateral handling that keeps issuer chains attached to signed bodies and respects artifact validity.
- Independent vectors and cross-implementation tests for producers, verifiers, and clients.

These are contributions we must explain and validate. We have not established that every idea is novel. Adding a `cvm_` prefix is namespacing, not a security result. Reproducing hash vectors proves agreement on those formulas, not complete protocol conformance or a secure kernel implementation.

## 4. Evidence: field-by-field reasoning

The following describes the current profile proposal and its Rust types, not a claim that EAT requires these CVM choices.

| Field or value | Origin | Why it is here and what it does not establish |
| --- | --- | --- |
| `eat_profile` | EAT name; our evidence identifier | Selects our exact interpretation rules. `tag:confidential.ai,2026:cvm#1` is an identifier, not a downloadable policy or proof of IETF approval. |
| `cvm_version: 1` | Our profile | Additional parser version check. Its overlap with the versioned profile identifier needs justification before freezing the format. |
| `eat_nonce` | EAT name; our binding constraints | This profile requires a 16–64 byte challenge. The relying party must compare its independently held challenge and verify the platform binding. Echoing supplied JSON is insufficient. |
| `submods` | EAT name | The profile chooses `cpu`, `vtpm`, `gpu/<id>`, and `nvswitch/<id>` labels. Those names organize separately appraised components; organization is not proof of a relationship. |
| `cvm_platform.vendor`, `.tee` | Our profile | Parser hints that must agree with authenticated report contents. They are not independent endorsements. |
| `cvm_platform.hosting` | Our profile | Attester-supplied deployment hint. A valid AMD/Intel report alone does not authenticate a cloud-provider label. |
| `cvm_report` | Our field using a CMW record | Keeps the original signed report bytes rather than replacing them with a caller's normalized summary. |
| `cvm_report[0]` | CMW media-type position; our vendor media-type string | Identifies the report encoding. A media-type label is not itself trusted evidence. |
| `cvm_report[1]` | CMW byte payload | Original binary report encoded for JSON. Preserve exact signed bytes. |
| `cvm_report[2] = 4` | CMW indicator bitmask | `1 << 2` denotes evidence. It is not quote version 4, four certificates, or a trust score. |
| `cvm_binding.pattern` | Our profile | Distinguishes a live challenge from the proposed certificate-lifetime use case. The latter needs separate age and certificate-binding rules. |
| `cvm_binding.mode` | Our profile | Names the actual proof path: report data, SNP commitment, vTPM extraData, CCA challenge, or NVIDIA nonce. Each requires a backend-specific check. |
| `cvm_binding.key` | Our profile | Binds agreed key material together with the challenge. The consumer still needs possession/channel checks appropriate to its protocol. |
| `cvm_endorsements` | Our field using CMW collections | Supplies verification material. Inline certificates and CRLs do not choose their own trusted root or waive freshness checks. |
| `cvm_registers` | Our profile | Accompanies logs or software-register commitments. Input values and backing labels must be authenticated or derived before appearing in results. TDX values can be extracted directly from its quote. |
| `cvm_log` | Our profile | Identifies the log format and its bytes. A matching replay establishes consistency with measured register values; producer trust and measurement coverage are separate. |
| `cvm_chain.chain_len` | Our profile | Counts extensions for SNP commitment mode. It is not by itself a commitment to ordering. |
| `bootseed` | EAT name; our SNP construction | A 32-byte boot identifier bound through the first record. It is not a hardware monotonic counter or complete rollback defense. |

JSON byte strings use base64url without padding in this branch. `<48 bytes>` means 48 decoded bytes, not 48 text characters. Hash identifiers are explicit because a digest is uninterpretable without its algorithm and because platforms have different register widths. The parser enforces lengths and canonical encoding; JSON Schema is a structural aid, not cryptographic verification.

## 5. Policy: the verifier's requirements

`VerifyPolicy` is our library API, not a universal EAT or EAR policy language. Accepting evidence never grants the attester authority to relax the relying party's requirements. If an HTTP client can submit a policy, the surrounding application must decide whether that client is authorized to choose it.

| Field | Reason and intended behavior |
| --- | --- |
| `reference.launch_measurement` | Approved base-image digests. Empty currently means no launch pin; defaults alone do not approve a workload. |
| `reference.registers` | Approved final values per register. Array values are alternatives. CLI expectations now intersect that choice instead of broadening it. |
| `reference.pcrs` | Explicit vTPM PCR expectations, preserving the distinction from RTMR/VMR indices. Azure init-data maps to PCR 8 using the documented extend. |
| `reference.slot_owners` | Required workload-slot owner labels. Their security value depends on the producer-authorization mechanism, which the kernel design must establish. |
| `reference.host_data` | Required host-set label. Application guarantees require approved measured guest code that enforces the label's meaning. |
| `min_backing` | Lowest accepted register protection. The comparison does not promote a weak register into a stronger one. |
| `freshness.key` | The key the relying party expects this evidence to bind. The expected nonce is a separate input in the service/CLI/WASM entry points. |
| `commitment.header16`, `.seed` | Pinned parameters of the unreleased SNP commitment protocol. They cannot be attacker-selected alternate algorithms. |
| `tcb.floors`, `.default_floor` | Named firmware-version constraints, selected globally or per allowed machine. Backend applicability must be specified. |
| `tcb.tdx_allowed_status` | Accepted Intel status values. `UpToDate` is a firmware assessment, not workload approval. |
| `tcb.require_revocation`, `.require_signed_collateral` | Requirements on collateral checks. Results must make any permitted skipped check visible. |
| `policy_bits` | Allowed or required security settings, including debug and migration. They have platform-specific applicability behind a common API. |
| `identity.machines`, `owner.id_key_digests` | Separate machine and workload-owner restrictions. A machine identity does not identify the approved application. |
| `gpu` | Device presence, architecture, and NRAS claim requirements. A CPU-only result cannot satisfy a required-device policy. |

## 6. Appraisal: what the verifier is willing to assert

The branch returns a Rust object/JSON claims set. It does not mint a signed profile-result token. Across a trust boundary, a consumer must authenticate the verifier and protect the result, for example through an authenticated service channel or a properly issued signed token. A serialized appraisal is not independently verifiable merely because its fields use EAR names. This follows the verifier-authority distinction in [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html#section-4).

The EAR container uses `eat_profile`, `iat`, `ear_verifier_id`, and `submods`. Within each submodule, `ear_status` summarizes the appraisal; `ear_trustworthiness_vector` breaks it down; `ear_attester_claims` contains evidence-derived claims; `ear_verifier_claims` contains policy-derived conclusions; and `ear_appraisal_policy_ids` identifies applied policies. `ear_raw_evidence` optionally preserves evidence for later inspection. These names come from [EAR section 3](https://datatracker.ietf.org/doc/html/draft-ietf-rats-ear-04#section-3).

The profile-specific payload answers the questions the application actually asked:

| Field | Why it is present and its limit |
| --- | --- |
| `cvm_launch_measurement.{alg,value}` | The authenticated launch digest, with its algorithm. Presence alone does not mean it was approved; inspect the reference check. |
| `cvm_registers[].index` | Register number within its declared source. RTMR 3, PCR 3, and VMR 3 are not interchangeable. |
| `.alg`, `.value` | Hash algorithm and authenticated register bytes. A final value is not a readable workload history. |
| `.source` | The mechanism: `tdx-rtmr`, `snp-vmr`, `vtpm-pcr`, or future `cca-rem`. |
| `.backing` | The established protection level. The current SNP appraiser caps this at `virtualized`; a working driver and reviewed image policy are prerequisites for promotion. |
| `.replayed` | Whether the supplied log was checked against that register. `false` can coexist with an authenticated, policy-pinned value extracted from a quote. |
| `.owner`, `.purpose` | Bound claim-record metadata for workload slots; not proof of producer authorization on their own. |
| `cvm_freshness` | The binding that passed. It describes the check, not an independent time-to-live guarantee. |
| `cvm_host_data.{semantics,value}` | Host-set bytes with explicit interpretation: SNP HOST_DATA, TDX MRCONFIGID, or future CCA RPV. Being signed does not make the host's choice an application guarantee. |
| `cvm_policy` | Normalized security settings derived from the report. `debug: false` must have a precisely scoped meaning. |
| `dbgstat` | Reused EAT debug vocabulary, the RFC 9711 text value in JSON, scoped to the TEE's guest-debug facility. |
| `cvm_tcb` | Actual backend-specific firmware information. Rust serializes this as an untagged union interpreted with `cvm_platform.tee`; there is currently no inner `type` tag. |
| TDX `.tee_tcb_svn`, `.pck_tcb`, `.pcesvn` | Separate version information from the quote and endorsement certificate, checked by the TDX backend. |
| TDX `.fmspc`, `.status`, `.advisories` | Collateral lookup family identifier and evaluated Intel status information. FMSPC is not a unique machine ID. |
| SNP `.reported`, `.committed`, `.current`, `.launch` | Distinct TCB sets, kept distinct rather than collapsed into one ambiguous version tuple. |
| `cvm_identity` | Authenticated hardware/device identifier: chip ID, PPID, or device UEID. It is not automatically a boot or workload identity and can expose a stable correlatable identifier. |
| `cvm_collateral` | Which collateral checks occurred, were skipped, or did not apply, with available validity/signature information. |
| `cvm_reference` | Which configured measurement references matched. Missing pins must not be described as successful checks. |
| `cvm_backing_min` | Required and weakest observed register backing, making the comparison inspectable. |
| `ear_all_submods_bound` | Adapted from a separate [TDX/confidential-GPU profile draft](https://datatracker.ietf.org/doc/html/draft-kykdxy-rats-tdx-cgpu-ear-profile-02), not core EAR. The branch's type and meaning need reconciliation with that draft. |

The trustworthiness vector's integers are not a universal scale where larger means better. AR4SI assigns meanings within each category; for example, hardware value 2 concerns authentic/supported hardware, while executables value 2 concerns approved code during and after boot. Our mapping must establish the conditions for each assertion. See [AR4SI section 2.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-10#section-2.3.4).

## 7. Trace an assertion all the way to its authority

For the sample's `cvm_registers[3]`, the argument is: the TDX backend verifies the quote and its chain; extracts signed RTMR 3; compares it with configured reference values; and reports whether a log also reproduced it. `backing: hardware` refers to the register mechanism. None of that proves all executed code extended this register.

For SNP VMRs, consistency of log, registers, and commitment is only one part of the argument. Approval also needs the measured kernel to enforce register state and every report path, along with its configuration and producer restrictions. The design's root-resistance claim cannot be earned by a hash formula alone.

For a CPU/GPU bundle, freshness checks tie the component responses to a challenge. A separate argument is required for physical attachment, trusted topology, or a confidential data channel. Do not let the word “bound” silently claim those properties.

## 8. Concrete corrections and open choices before claiming conformance

1. **EAT JSON debug status.** [RFC 9711 section 4.2.9](https://www.rfc-editor.org/rfc/rfc9711.html#section-4.2.9) uses `"disabled-since-boot"` in JSON and integer `2` in CBOR. The branch's `u8` JSON field and the earlier example do not match that encoding. Also define the debug facilities covered by our CPU submodule before claiming the full EAT meaning. *Resolved:* `dbgstat` is now the RFC 9711 text value in JSON, a contradicting attester hint is refused, and the profile scopes it to the TEE's guest-debug facility (section 5.1).
2. **Binding extension compatibility.** The [TDX/GPU draft](https://datatracker.ietf.org/doc/html/draft-kykdxy-rats-tdx-cgpu-ear-profile-02#section-3) defines `ear_all_submods_bound` as strings `"true"`, `"false"`, or `"unknown"`; this branch emits a boolean. Agree on the type and proof semantics, or give the narrower CVM claim a distinct name. Do not claim consumers need no translation yet.
3. **AR4SI assertion coverage.** [Executables value 2](https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-10#section-2.3.4) is stronger than “a launch digest and a selected register matched.” Document the producer coverage and measured-image enforcement that justify it, or emit a narrower supported assessment. Audit all other category mappings by the same rule.
4. **Real policy identity.** The code currently emits the profile URI as `ear_appraisal_policy_ids`. It does not distinguish two callers using different measurement allowlists or debug allowances. Specify policy identity/versioning if results are meant to be auditable or reusable. *Resolved:* each submodule now carries the profile URI and the policy's own RFC 6920 name over the JCS serialization of the effective policy, with a vector in Appendix B.
5. **Contract versus implementation status.** Arm CCA appraisal, SNP driver collection, stronger SNP backing, consumer migration, and some certificate-carriage details are unfinished. Separate implemented behavior from proposed wire contracts. Do not equate a schema or vectors with an independently conforming implementation.
6. **Complexity budget.** Explain why both a profile identifier and `cvm_version` are needed, which compatibility aliases remain public, and whether CMW's array representation belongs directly in the ergonomic API or only on the wire. These are reviewable choices, not obligations imposed by hardware.
7. **CEL record conformance.** [CEL v1.1](https://trustedcomputinggroup.org/wp-content/uploads/TCG_Canonical-Event-Log-Format_v1.1_pub.pdf) section 4.2.2 keeps `recnum` per PCR or NV index, and the section 5.2 CDDL places content under `content_type` (9) and `content` (10) and defines the log as one array. The branch numbered records across all slots, bound that number into the record digest, keyed content by its type value, and carried the log as a CBOR sequence. *Resolved:* records follow the CDDL and `recnum` counts per slot. The cross-register order moved into the `cvm` content as `seq`, so the record digest formula and its vectors are unchanged. The log is the CDDL's array. Parsing, encoding and replay live in the standalone `tcg-cel` crate, whose tests reproduce the CEL specification's own PC Client example against an independent CBOR encoder.

The next documentation pass should state, for every security-relevant field: its owner, units/encoding, signed source or derivation, validation rule, absent-value behavior, policy meaning, and a negative test. Standard-derived claims additionally need exact-version conformance tests. Project-specific claims need a written argument and independent implementation vectors. That is the evidence needed for others to implement and evaluate this design.
