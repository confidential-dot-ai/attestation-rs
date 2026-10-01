# Layer 15: Arm CCA (experimental)

Sections 4.6 and 9.6: Arm CCA realms. The text follows the Arm CCA token drafts and the RMM specification. No implementation exists, the reference implementation refuses the evidence with `platform-unsupported`, and the entries below are provisional until one does.

### CCA-1. The CCA token nests as the RMM returned it

The `cpu` submodule of a realm is the CCA attestation token itself, as an EAT nested token. There is no `cvm_report` wrapper and no `cvm_binding`: the submodule is in the challenge pattern, in `cca-challenge` mode, and binds no key in version 1.

- Why: the token is already an EAT with two signatures, and re-wrapping it would add a layer a verifier has to strip.
- Where: Sections 4.6, 5.4. Case: `cca-nested-token-not-implemented`.

### CCA-2. Two token forms, by allowlist

A verifier accepts the collection under tag 907 (RMM 2.0 and the current token draft) and the collection under tag 399 (RMM 1.0), each holding exactly the platform token and the realm token. Any other entry is refused with `unsupported`.

- Why: both forms are deployed, and neither tag is registered with IANA, so an allowlist is the only safe reading.
- Where: Sections 9.6.1, 17.3.

### CCA-3. Three profile pairs are accepted

The platform token's profile selects where the realm key's hash is bound: the challenge claim for the 2023 and 2024 profiles, the workload binding claim for the 2026 profile. A realm token without a profile claim takes the one its platform profile's row names. Any other pair or profile is refused with `unsupported`.

- Why: the binding between the two tokens is what makes the realm token trustworthy, and it moved between profile revisions.
- Where: Section 9.6.2.

### CCA-4. The vendor's signed CoRIM is the endorsement, and it is required

There is no single root for CCA platforms. The CoRIM for the implementation ID binds each instance ID to its platform attestation key and carries the reference values of the platform software. Without it the platform token cannot be authenticated, and the verifier refuses with `collateral-unavailable` whatever the policy says. Only the platform software check is waivable.

- Why: a waiver that skipped the key binding would accept any self-signed platform token.
- Where: Sections 9.6.4, 9.6.6. A verifier fetches the CoRIM only from origins its configuration names.

### CCA-5. REMs are pinned by value and never replayed in version 1

The four Realm Extensible Measurements are `cca-rem` registers with backing `hardware` and `replayed` false.

- Why: the RMM specification and its reference implementation define the extend input differently for short extensions and for hash algorithms other than SHA-512, so a replay rule cannot be fixed yet.
- Where: Section 9.6.5.

### CCA-6. Only the secured lifecycle state passes by default

A platform lifecycle of secured is accepted. The two debug states are refused unless `allow_debug`, and are then reported with `configuration` 96. Every other state is refused.

- Where: Section 9.6.5.
