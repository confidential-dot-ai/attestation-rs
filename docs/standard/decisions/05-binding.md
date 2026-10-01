# Layer 5: freshness and binding

Sections 5.1 to 5.4 and Appendix B.1: how evidence is tied to a challenge and to a key. Section 5.5 (certificate carriage) arrives in layer 16. One entry is open.

### BND-1. One mandatory nonce

`eat_nonce` is required in every envelope and is 16 to 64 bytes. The verifier refuses an envelope whose `eat_nonce` differs from the nonce the relying party supplied, and derives the anchor from the relying party's nonce.

- Why: an appraisal bound only to the envelope's own nonce accepts a replay. Sixteen bytes is the floor for an unguessable challenge, and 64 is what fits the report data fields.
- Rejected: optional nonces with timestamp freshness, and one nonce per submodule.
- Where: Sections 4.1, 5.1, 15.7. The comparison with the relying party's nonce has no case (`UNCOVERED.md`), because a case takes the envelope's nonce as the relying party's.

### BND-2. Two patterns: challenge and certificate

In `challenge` the relying party chose the nonce for this exchange. In `certificate` the evidence is bound to an X.509 certificate that lives for the CVM's lifetime, the attester chose the nonce when it created the certificate, and the evidence is as fresh as the certificate. A device submodule always declares `challenge`.

- Why: attested TLS needs evidence a server can present to every client without a round trip, and that evidence must say so, since its freshness is weaker.
- Where: Sections 5.1, 5.3. Cases: `snp-certificate-pattern-needs-tbs-key`, `snp-tbs-key-needs-certificate-pattern`.

### BND-3. The anchor is the nonce, or a tagged hash of the nonce and a key

Without a key the anchor is the nonce. With a key it is `SHA-384("ats-anchor-v1" || u8(len(nonce)) || nonce || u8(len(kind)) || kind || u16be(len(value)) || value)`. The attester and the verifier compute it with the same formula.

- Why: the tag and the length prefixes make the hash input unambiguous, and the unkeyed form lets an attester that already places a nonce in report data conform unchanged.
- Rejected: hashing in every case, which would break those attesters for no gain.
- Where: Section 5.2, Appendix B.1. Cases: `snp-keyed-anchor-not-bound`, `snp-policy-key-not-bound`.

### BND-4. Three key kinds, one reserved

`spki-sha256` and `raw` belong to the challenge pattern, `x509-tbs-sha256` to the certificate pattern. `tls-exporter` is reserved for version 2, and a version 1 verifier refuses it.

- Why: a public key digest covers key release, a certificate digest covers attested TLS, and `raw` leaves room for an application value without a new kind.
- Where: Section 5.3. Cases: `snp-key-kind-reserved`, `snp-key-value-wrong-size`, `snp-raw-key-too-long`.

### BND-5. One declared binding mode per attester, constrained by the platform

`cvm_binding.mode` names where the anchor is bound: `report-data`, `commitment`, `vtpm-extradata`, `cca-challenge` or `nras-nonce`. The verifier computes the expected value and compares it with the signed field in constant time over the whole field. A mode the TEE and hosting do not admit is refused.

- Why: the verifier checks one place and never searches the report for the nonce, so an attester cannot satisfy the check with a field of its choosing.
- Where: Section 5.4. Cases: `snp-genoa-report-data`, `snp-nonce-not-bound`, `snp-binding-mode-for-other-platform`, `tdx-binding-commitment`, `azure-snp-nonce-not-bound`, `azure-snp-nonce-length-differs`.

### BND-6. A mode that rests on guest software requires a pinned launch measurement

`vtpm-extradata` rests on the paravisor that holds the vTPM key, and `commitment` on the register provider. Both are refused with `binding-mismatch` unless the policy pins the launch measurement.

- Why: without the pin, a guest on other hardware can present a fabricated HCL report with its own key, bind it once into a genuine report and sign quotes for any nonce, and any SEV-SNP guest can commit to registers, a log and owners it invents.
- Where: Sections 3.4, 8.7, 9.4.4. Cases: `azure-snp-pcr8-pinned-without-launch-measurement` (layer 12), `snp-commitment-without-launch-measurement` (layer 14).

### BND-7. The policy can require a key, and the appraisal reports the one that was bound

When the policy names a key, the evidence's key must equal it. In the challenge pattern a policy may name none: the verifier then uses the evidence's key, if any, and reports it in `cvm_freshness.key`, and a relying party that relies on the binding compares the reported key with the key of its own channel. In the certificate pattern the policy must name the key (CRT-3, layer 16).

- Why: the verifier cannot know which channel the relying party is on, so either the relying party says which key it expects or it checks the one reported.
- Where: Sections 5.2, 15.15. Case: `snp-policy-key-not-bound`.

### BND-8. The required key is a policy member (open)

Today the key a relying party requires is `freshness.key` in the policy, and the policy identifier covers the whole effective policy (Section 12.5). A policy that names a key therefore has its own identifier: every certificate, since the certificate pattern requires the policy to name the key, and every keyed challenge whose key the relying party requires through the policy. That defeats the rule of Section 3.3 that a relying party recognizes the identifier of a policy it accepts.

- Options: (a) make the key a verifier input beside the nonce and remove `freshness` from the policy; (b) keep it in the policy and leave it out of the identifier.
- Recommendation: (a). The key is per exchange, like the nonce, and a policy is per deployment. Option (b) leaves an identifier that no longer names everything the policy required.
- If accepted: under (a), Sections 3.2, 4.6, 5.2, 5.5, 11, 12.5, 13.1, 14.2, 14.4 and 15.15 and Appendices B.4 and C change. The policy schema loses `freshness`, so every policy identifier changes (Appendix B.4 and all 32 expected appraisals) and every policy input drops the member. The case format gains a key input, the cases `snp-policy-key-not-bound`, `snp-keyed-anchor-not-bound` and `snp-certificate-pattern-without-presented-certificate` change shape, and the reference implementation's entry points take the key as an argument. Under (b), only Section 12.5 changes and no expected appraisal moves, since no appraisal case sets `freshness.key`.
