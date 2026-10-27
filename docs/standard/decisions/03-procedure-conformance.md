# Layer 3: procedure and conformance

Sections 11 and 14: how a verifier proceeds, how a refusal is named, and how conformance is judged. Every later layer brings cases in the format this layer defines.

### PRC-1. Nine steps, in any order, and no appraisal unless all pass

The procedure is parse, identify, authenticate, guest policy, freshness, collateral, registers, replay, reference values. A verifier may evaluate the steps in any order and produces no appraisal unless every step passes. Evidence that fails several checks may be refused with the code of any failing step.

- Why: steps 4 to 9 read only values that step 3 authenticated or that the envelope binds to them, and real implementations interleave them (a revocation check inside chain validation, for instance).
- Rejected: a fixed order with a required first-failure code. It would force one control flow on every implementation and adds nothing for a relying party.
- Where: Section 11. Cases: `snp-crl-checked`, `tdx-v4-quote-with-fixture-collateral`, `tdx-debug-attribute-refused`.

### PRC-2. Every submodule is appraised, and one failure refuses the envelope

A verifier appraises every submodule the envelope carries and refuses the whole envelope when any submodule fails.

- Why: an attester decides what it sends, and a relying party should not have to work out which partial results are acceptable.
- Rejected: partial appraisals (a passing CPU beside a failed device).
- Where: Section 11. The one tolerated shortfall is a device nonce match the policy waives, which the appraisal reports (NVD-6, layer 13).

### PRC-3. A refusal is one of 24 codes

A failed appraisal produces a refusal code naming the rule family that failed, and no appraisal. The codes are identifiers compared across implementations, and the text defines nothing else in a refusal.

- Why: a relying party and a conformance runner act on the code. Free-text errors cannot be compared.
- Rejected: expressing failures as AR4SI contraindicated values inside an appraisal. A failed appraisal has no authenticated claims to carry them.
- Where: Sections 12.1, 14.4.

### PRC-4. The evaluation time is an input

Every validity window is judged against one instant the verifier is given. A verifier deployed as a service takes it from its own clock.

- Why: decisions become reproducible and the corpus can pin them. A caller-supplied time in a service would let the caller revive expired collateral, so Section 15.9 forbids it.
- Where: Sections 11, 14.2, 15.9. Cases: `snp-crl-past-its-window`, `tdx-collateral-past-its-window` (layer 6).

### PRC-5. A corpus of cases decides conformance

A verifier conforms when it reproduces every case's decision at the corpus version it declares and meets the requirements `UNCOVERED.md` lists as lacking a case. A case fixes the evidence, the policy, the collateral and the time, and expects an appraisal or a refusal code. Nothing in a case reaches a network.

- Why: prose alone does not make two implementations agree. A case is the smallest unit a second implementer can run.
- Where: Sections 14, 14.1, 14.2. Version 1 publishes no corpus for attesters or register providers.

### PRC-6. Appraisals compare as JSON values, refusals as codes

For an expected appraisal the runner removes `iat`, `ear_verifier_id`, `ear_raw_evidence` and each collateral entry's `reason` from both sides and requires the rest to be equal; an extra claim fails the case. For an expected refusal it compares codes, and an error that maps to no code fails the case.

- Why: the removed members vary between implementations by design. Everything else is the decision.
- Where: Section 14.3.

### PRC-7. A decision change raises the corpus revision, a wire change a new profile identifier

The corpus version is `<profile version>.<revision>`. A change to any case raises the revision, and a change that alters a decision lands together with the case that shows it. A change to the wire format defines a new profile identifier.

- Why: an implementation pins one corpus version and states it, so a relying party knows which decisions a verifier makes.
- Where: Status of this document, Section 14.5.

### PRC-8. Order of authority among the text and its companions

Where the text and a companion disagree, conformance is judged against the corpus until the defect is corrected; where the corpus is silent, the text governs. The CDDL governs over the JSON Schemas, which are informative. The reference implementation generates the expected results, and a case it fails is a defect in one or the other.

- Why: each artifact has one job (the CDDL constrains shapes, the vectors constrain formulas, the corpus constrains decisions), and a reader needs to know which wins.
- Where: Status of this document, Sections 14, 14.5.

### PRC-9. Conformance is declared per module (proposed)

Today Section 14 defines conformance over the whole corpus. The proposal: each case names the module it belongs to (the layers of this stack), and an implementation declares the modules it implements, for example "core, SEV-SNP and TDX at corpus 1.9". Section 9 already requires `platform-unsupported` for a TEE, hosting or report media type a verifier does not implement. The proposal extends that rule to the other modules (devices, `commitment` mode, the certificate pattern, CBOR), which have none today.

- Why: a verifier for one platform is a legitimate product, and the status ladder in the map needs a second implementation per module to call it stable.
- If accepted: Sections 9, 14, 14.2 and 14.4 change, the case format gains a `module` member, and the corpus revision rises. The case `cca-nested-token-not-implemented`, which today obliges every conforming verifier to refuse Arm CCA, moves under the rule.

### PRC-10. Every rule carries an identifier (proposed)

Today a case cites a section, and the statements without a case are kept by hand in `UNCOVERED.md`. Six of the 24 refusal codes have no case: `report-invalid`, `chain-invalid`, `revoked`, `log-required`, `device-token-invalid`, `device-policy`. The proposal: each normative rule gets a stable identifier in the text, a case cites the identifiers it exercises, and coverage is computed.

- Why: the gate from draft to candidate asks that every rule has a case or a stated reason, and a hand-kept list cannot show that it is complete.
- If accepted: identifiers are added to the text without renumbering sections, `rule.section` becomes `rule.ids`, and `UNCOVERED.md` is generated.
