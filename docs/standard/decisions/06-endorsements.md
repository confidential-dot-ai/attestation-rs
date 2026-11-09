# Layer 6: endorsements

Section 10: collateral carried inside the evidence, and how a verifier treats it beside its own.

### END-1. Collateral can travel inside the evidence, under a closed set of labels

`cvm_endorsements` is a CMW collection typed `tag:confidential.ai,2026:cvm-endorsements#1` with labels from one table: `snp.vek`, `snp.crl`, `tdx.tcb_info`, `tdx.qe_identity`, `tdx.pck_crl`, `tdx.root_crl`, `nras.jwks`. An unknown label, a label for another TEE and a nested collection are refused.

- Why: a verifier can appraise offline, and a vendor service outage does not stop a verifier that receives fresh collateral with the evidence.
- Rejected: a label for AMD's ASK and ARK. The roots are pinned, and an ASK or ARK supplied in evidence is ignored. Intel's chains do travel (the PCK chain inside the quote, `issuer_chain` beside each signed document) and are anchored to the pinned root.
- Where: Section 10.1. Cases: `snp-endorsement-label-unknown`, `snp-endorsement-type-wrong`, `snp-endorsement-indicator-evidence`, `snp-endorsement-for-other-tee`, `snp-endorsements-type-tag-wrong`, `snp-endorsements-without-type-tag`, `envelope-cmw-collection-nested`.

### END-2. Inline endorsements are inputs the verifier authenticates

Every inline artifact is anchored to a pinned vendor root, checked against its validity window at the evaluation time, and bound to the parameters that name it: a VCEK to the report's chip identifier and reported TCB, a VLEK to the reported TCB, a TCB Info to the PCK certificate's FMSPC, a CRL to its issuer.

- Why: the attester chooses what it sends. An inline artifact can stand in for a fetch and can never add authority.
- Where: Section 10.2. Cases: `tdx-inline-root-crl-forged`, `snp-inline-vek-of-another-chip`, `snp-inline-vek-for-another-tcb`.

### END-3. The verifier's own copy wins, and a failing inline copy is ignored

A verifier prefers its own valid CRL or TCB document to an inline one. An inline artifact that fails its binding or its window is ignored as if absent, and the verifier's own source serves. An inline artifact whose signature or encoding fails is refused with `collateral-invalid`. A VEK is the exception, since Section 9.1.4 authenticates it as part of the report's chain: an inline VEK that cannot be parsed or names the other key type is also ignored as if absent, and a bound VEK whose chain fails is `chain-invalid` from either source.

- Why: an attester must not be able to substitute an older artifact, still inside its window, for a newer one the verifier knows.
- Where: Section 10.2. Cases: `snp-inline-vek-for-another-tcb-provider-serves`, `snp-vek-from-the-provider`, `tdx-inline-root-crl-forged`. The preference for the verifier's copy over a valid inline one has no case (`UNCOVERED.md`).

### END-4. Collateral is fresh by its own validity window

An artifact inside its window at the evaluation time is usable however long ago it was fetched, and an artifact outside it is never used, however recently it arrived. The verifier's cache timers play no part.

- Why: the window is what the vendor signed. A cache age is a property of one verifier and cannot be reproduced by another.
- Where: Sections 10.2, 15.8. Cases: `snp-crl-past-its-window`, `tdx-collateral-past-its-window`.

### END-5. Intel's signed documents travel as the bytes Intel signed

A TCB Info or QE Identity is carried as `{body, issuer_chain}` under `application/vnd.confidential-ai.pcs-signed+json`, where `body` is the exact response bytes and `issuer_chain` the PEM chain from the response header.

- Why: Intel's signature covers the exact bytes of the response member, so re-serialized JSON would not verify.
- Where: Sections 10.1, 17.1.

### END-6. Collateral outside the evidence is identified by a text key

Each artifact a verifier holds has a key, such as `snp_vcek/<generation>/<chip id hex>-<TCB hex>` or `tdx_tcb_info/<fmspc>`. The corpus uses these forms to give a case its collateral.

- Why: a case has to name the whole collateral an appraisal may use, and a second implementation has to map the names to its own store.
- Where: Sections 10.3, 14.2.
