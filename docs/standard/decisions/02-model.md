# Layer 2: model

Sections 1 to 3 and the front matter. These are the principles every later layer applies; a disagreement here changes most of what follows, so it is settled first.

### MOD-1. Three messages, three authors

Evidence is what the attester sends, the policy is what the relying party requires, and the appraisal is what the verifier established. A launch measurement in an appraisal is always the value the verifier extracted from the signed report, and the other attester claims are signed or bound. `hosting` alone is repeated as the attester reported it, as a label.

- Why: a relying party has to tell a verified value from a claimed one by where it sits, without knowing the platform.
- Rejected: one object that carries expectations and outcomes together, as the pre-profile result did with its `*_match` fields. Each consumer re-derived which fields were verified.
- Where: Sections 1.3 (item 1), 3.1, 3.2.

### MOD-2. Only signed or bound bytes decide

Every evidence field is signed, bound, a hint, or reserved. A hint selects a parser and the combinations Section 4.3 admits. A hint that contradicts signed data is a refusal.

- Why: the envelope is unprotected, so a verifier needs a rule for every field. A verifier that reads a bound field before binding it fails open.
- Rejected: ignoring a hint that contradicts the report. A contradiction means the attester and the verifier disagree about what is being verified, and a refusal surfaces it.
- Where: Sections 1.3 (item 2), 3.4, 15.1. Case: `snp-generation-hint-contradicts-report`.

### MOD-3. Fail closed, with visible waivers

A check that cannot be performed is a failure unless the policy waives it, and a waived check appears in the result as `skipped` with its reason.

- Why: a silent skip turns an outage or a missing artifact into an acceptance.
- Where: Sections 1.3 (item 3), 11, 12.3, 13.1.

### MOD-4. Compose existing standards and define only what they leave open

The profile is built from RATS roles (RFC 9334), EAT (RFC 9711), unprotected claims sets (RFC 9781), CMW (RFC 9999), EAR, AR4SI, the TCG Canonical Event Log and CoRIM. It adds the claims, the binding rule, the register model and the procedure those documents leave to a profile.

- Why: relying parties and other verifiers already parse these formats, and adjacent drafts (the TDX confidential-GPU EAR profile, the Arm CCA token) compose with a profile that uses the same parts.
- Rejected: a bespoke JSON format, which every consumer would have to learn and which no other profile could reuse.
- Where: Section 1.3 (item 7), 4.8.

### MOD-5. Preserve platform differences that carry meaning, normalize the rest

TCB values, host-set fields and register widths stay platform-specific. Debug and migration are reported under one name on every TEE (`cvm_policy.debug`, `cvm_policy.migratable`), and the settings only one TEE has (SMT, VMPL, the TD attribute settings) sit beside them.

- Why: a relying party writes one rule for "debug is off" and still pins an exact firmware version where the platform defines one.
- Where: Sections 1.3 (item 6), 12.2.

### MOD-6. Scope of version 1

Eight attesters: SEV-SNP guests with and without a register provider, TDX guests, Azure SEV-SNP and TDX, Arm CCA realms, NVIDIA GPUs and NVSwitch. Out of scope: device assignment through TEE-IO, SGX enclaves, live migration, availability, microarchitectural side channels, physical attacks, and the build-time supply chain of the measured images.

- Why: these are the attesters with a hardware-signed report today, and each out-of-scope item needs either hardware that is not deployed or a different kind of evidence.
- Where: Section 1.2.

### MOD-7. An appraisal carries no single pass or fail value

The relying party decides from the submodule statuses, `ear_all_submods_bound` and the policy identifier. Section 3.3 gives the rule.

- Why: a boolean detached from the policy that produced it does not say which requirements were met. A genuine report can describe an image or a firmware version the relying party does not accept.
- Rejected: an `isSafe` style member.
- Where: Section 3.3.

### MOD-8. Host-set fields are labels

SNP `HOST_DATA`, TDX `MRCONFIGID` and the CCA Realm Personalization Value are reported as `cvm_host_data` with explicit semantics. They establish something about the workload only when measured code enforces a relationship with them, and the guarantee then rests on the launch measurement pin.

- Why: the host can choose a different value on every launch, and the launch measurement does not cover it.
- Where: Sections 3.5, 13.4. Cases: `snp-host-data-pinned`, `snp-host-data-differs` (layer 7).
