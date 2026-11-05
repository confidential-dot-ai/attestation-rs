# Layer 7: policy

Sections 13.1 to 13.4: what a relying party can require. Section 13.5 (device policy) arrives with the NVIDIA module in layer 13.

### POL-1. One JSON object, every member optional, every default fails closed

The policy is a verifier input the relying party chooses. It follows the encoding rules of Section 4.7, and a `null` member, an object written as an array or an unknown member fails validation with `policy-invalid`. An empty policy waives nothing: every check is required and every relaxation is off. It also pins nothing (no image, machine or TCB floor), so it establishes the least: `executables` is absent, and on SEV-SNP so is `hardware`.

- Why: a relying party that writes nothing gets no relaxation, and a misspelled member cannot silently add one.
- Where: Section 13.1. Cases: `policy-unknown-member`, `policy-null-member`, `policy-member-not-an-object`, `snp-crl-checked-under-the-default-policy`.

### POL-2. Guest settings default to their strict value, and each relaxation is a named member

By default debug is refused, migration is refused, an SEV-SNP report must come from VMPL 0, a TD must set `SEPT_VE_DISABLE` and leave reserved attributes zero, and a service TD is refused. `policy_bits` holds one member per relaxation.

- Why: a relaxation is a decision the policy identifier should record, so each one has a name.
- Where: Section 13.1. Case: `tdx-debug-attribute-refused` (layer 3).

### POL-3. Collateral checks are waived only by name

`tcb.require_revocation` and `tcb.require_signed_collateral` default to true. A waived check is reported as `skipped` with a reason, and `hardware` then makes no claim.

- Why: an operator who cannot reach a vendor service needs a way to proceed, and the relying party needs to see that it happened.
- Where: Sections 12.3, 12.4, 13.1. Cases: `snp-revocation-required-without-crl`, `tdx-collateral-required-but-unavailable` (layer 3).

### POL-4. TCB floors are named and applied per machine

A floor has a name, a machine on the allowlist can point to one, and `tcb.default_floor` covers the rest. An SEV-SNP floor bounds all four TCB values (`reported`, `current`, `committed`, `launch`) unless `values` narrows it. On TDX the Intel status and the floor are independent requirements, and the floor adds `tee_tcb_svn` and the TCB Info's `tcbEvaluationDataNumber`. `Revoked` can never be an allowed status, and a floor that constrains nothing fails validation.

- Why: a fleet carries one floor per generation and moves a machine between floors without editing every policy. A floor on `reported` alone leaves a host free to roll firmware back to its committed version between attestations.
- Where: Sections 13.1, 13.2. Cases: `snp-tcb-below-floor`, `snp-floor-names-fmc-before-turin`, `tdx-floor-met`, `tdx-floor-tee-tcb-svn`, `tdx-floor-evaluation-data-number`, `tdx-tcb-status-not-allowed`, `policy-floor-constrains-nothing`, `policy-floor-tdx-constrains-nothing`, `policy-default-floor-not-defined`, `policy-revoked-status-allowed`.

### POL-5. A machine allowlist compares the identity the hardware chain authenticated

`identity.machines` lists `{id, tcb_floor?}`. The identity is the submodule's `cvm_identity` value, compared after the chain authenticated it. An SEV-SNP report endorsed by a VLEK, or whose `CHIP_ID` is all zero, identifies no machine and never matches.

- Why: an identity the attester states proves nothing. Under a VLEK no endorsement covers the chip identifier.
- Where: Section 13.3. Cases: `snp-machine-on-allowlist`, `snp-machine-not-on-allowlist` (layer 3), `snp-machine-floor-applies`, `snp-machine-floor-overrides-default`, `snp-default-floor-for-machine-without-floor`, `snp-vlek-masked-chip-identifies-no-machine`, `policy-empty-machine-allowlist`, `policy-machine-floor-not-defined`.

### POL-6. Reference values are flat pins, and an unsatisfiable pin is a refusal

The policy pins the launch measurement, registers, PCRs, slot owners, host data and SEV-SNP ID key digests. A pin that nothing in the evidence can satisfy (a PCR pin without a `vtpm` submodule, an ID key pin on a TD quote) is refused with `reference-mismatch`.

- Why: a pin the verifier skips because the evidence lacks the field would pass evidence the relying party meant to exclude.
- Where: Sections 13.1, 13.4. Cases: `snp-launch-measurement-not-in-reference`, `tdx-register-not-in-reference`, `azure-snp-pcr8-not-in-reference`, `snp-host-data-pinned`, `snp-host-data-zero-padded`, `snp-host-data-differs`, `snp-host-data-longer-than-the-field`, `snp-owner-key-not-accepted`, `azure-snp-owner-key-accepted`, `snp-pcr-pin-without-vtpm`, `tdx-owner-pin-unsatisfiable`.

### POL-7. Reference values come from the image publisher, as flat JSON and as a signed CoRIM

A publisher should publish each image's values in both forms, and a verifier that ingests both treats them as one source.

- Why: flat JSON is what a policy holds today, and a signed CoRIM is what the RATS ecosystem exchanges. The reference implementation ingests the flat form only.
- Where: Sections 13.4, 15.12.

### POL-8. The minimum backing defaults to `hardware`

`min_backing` sets the weakest protection level the policy accepts for any verified register, and a relying party that accepts software registers lowers it explicitly.

- Why: a guarantee must not be downgraded from hardware to software without the policy saying so. Layer 9 defines the levels.
- Where: Sections 13.1, 15.2. Case: `azure-snp-backing-below-minimum`.
