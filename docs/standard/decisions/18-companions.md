# Layer 18: companions

Sections 18 and 19, Appendices C to E, the schemas under `schemas/` and the vector file. This layer is checked by the reference implementation's tests more than by reading: a test holds Appendix C equal to `schemas/cvm-profile-v1.cddl`, holds the CDDL, the JSON Schemas and the parsers to one another on every corpus input, and checks every vector.

### CMP-1. The CDDL module is normative, the JSON Schemas are informative

Appendix C and `schemas/cvm-profile-v1.cddl` are the same bytes and constrain the three shapes on the wire: the evidence envelope, the appraisal and the policy (Sections 4, 12 and 13). Log records and the rules CDDL cannot state stay in the text. The three JSON Schemas are generated from the reference implementation's types, and where one admits what the CDDL refuses, the CDDL governs.

- Why: CDDL covers both encodings and is the notation of the documents this profile composes. JSON Schema is what most JSON tooling consumes, so it is published as a convenience.
- Where: Status of this document, Appendix C.

### CMP-2. Vendor documents are cited at a pinned revision

The AMD, Intel, Arm, TCG and UEFI documents carry the revision the text was checked against: AMD's ABI 1.59 and VCEK specification 1.05, Intel's TDX Module ABI 348551-008 and quote verification library at a named commit, the RMM specification 1.0-rel0 and 2.0-bet3. The dstack and Confidential Containers references name a repository without a commit.

- Why: report layouts and verification algorithms change between revisions, and "as the vendor specifies" is checkable only against one.
- Where: Section 19.1.

### CMP-3. A verifier pins the vendor roots, and Appendix E gives values to compare

A verifier obtains its roots from the vendors. Appendix E lists what the reference implementation pins: the AMD ARK, ASK and ASVK per generation, Intel's SGX root key, and for NRAS the key of an NVIDIA intermediate certificate.

- Why: a published fingerprint lets an implementer check that a download is the certificate this text was verified against. The NVIDIA value is an intermediate's key, which the reference implementation trusts as the top of the NRAS token chain.
- Where: Appendix E, Sections 9.1.4, 9.2.3, 9.7.2.

### CMP-4. Implementation status is recorded in the text

Section 18 names the reference implementation, the corpus version it passes, what it does not implement (Arm CCA, the register provider, CBOR, chain memory, the certificate extension parser, `ear_raw_evidence`), and any known departure from the text.

- Why: a reader has to be able to tell a requirement that runs from one that is only written down.
- Where: Section 18.
