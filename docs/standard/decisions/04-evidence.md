# Layer 4: evidence

Sections 4.1 to 4.4, 4.7 and 4.8: the envelope, its submodules and its encoding. Sections 4.5 (device submodules) and 4.6 (the nested Arm CCA token) arrive with their modules in layers 13 and 15.

### ENV-1. The envelope carries no signature

Evidence is an EAT claims set under the profile `tag:confidential.ai,2026:cvm#1`, carried unprotected: a UJCS in JSON and a UCCS (tag 601) in CBOR, labeled with the RFC 9782 media types. The profile relies on no property of the channel that carries it, which departs from the secure-channel premise of RFC 9781 section 4, and Sections 3 and 4.1 state the roles and the argument RFC 9781 section 7 asks for.

- Why: every byte a verifier relies on is signed by the TEE, a vendor service or the vTPM, or is bound to such bytes. A signature by a key inside the guest adds nothing a verifier can rely on.
- Rejected: a JWT or CWT signed by a guest key. The key would need its own attestation, which is the binding of layer 5.
- Where: Sections 3.4, 4.1, 4.8, 15.1.

### ENV-2. Four top-level claims, and the nonce is the envelope's

The envelope carries `eat_profile`, `eat_nonce` (16 to 64 bytes), `cvm_version` (the integer 1) and `submods`. In JSON `eat_nonce` is base64url text, and the array form of RFC 9711 is refused. Another profile or version is refused.

- Why: one nonce at the top makes "every attester answered this challenge" a single comparison per submodule.
- Where: Section 4.1. Cases: `envelope-nonce-too-short`, `envelope-nonce-too-long`, `envelope-profile-unknown`, `envelope-version-unknown` (the last two in layer 3).

### ENV-3. One submodule per attester, under a closed set of names

`submods` holds exactly one `cpu`, a `vtpm` exactly when the `cpu` binds through it, and zero or more `gpu/<ueid>` and `nvswitch/<ueid>`. Any other name is refused. An envelope holds at most 66 submodules, of which at most 32 are devices.

- Why: the name selects the appraiser, so an unknown name has no defined appraisal, and ignoring it would let evidence go unverified.
- Where: Section 4.2. Cases: `envelope-no-cpu-submodule`, `envelope-submodule-name-unknown`, `azure-cpu-without-vtpm`, `snp-vtpm-without-vtpm-binding`, `envelope-submodules-at-bound`, `envelope-submodules-over-bound`.

### ENV-4. The hardware report travels unmodified

`cvm_report` is a CMW record whose value is the report bytes exactly as the TEE produced them, typed by a profile media type (`application/vnd.confidential-ai.sev-snp-report`, `application/vnd.confidential-ai.tdx-quote`) with indicator 4. The Linux configfs-tsm JSON type is accepted on ingest and never emitted.

- Why: the verifier parses the bytes the hardware signed. A transcription of report fields into claims would have to be trusted or re-derived.
- Rejected: per-field evidence claims copied from the report.
- Where: Section 4.3. Cases: `snp-report-type-unknown`, `snp-report-type-for-other-tee`, `snp-report-indicator-not-evidence`.

### ENV-5. The platform is a hint, and the admitted combinations are a closed table

`cvm_platform` (vendor, TEE, generation, hosting) and `dbgstat` are hints. The verifier re-derives vendor, TEE, generation and debug state from the report and refuses a hint that contradicts them. `hosting` cannot be derived, so the table in Section 4.3 fixes which report types, binding modes and registers each TEE and hosting admits, and each admitted path is verified in full.

- Why: an attester's free choice never widens what a verifier accepts.
- Where: Sections 3.4, 4.3. Cases: `snp-generation-hint-agrees`, `snp-generation-hint-unknown`, `snp-platform-vendor-disagrees-with-tee`, `snp-dbgstat-hint-agrees`, `snp-dbgstat-hint-contradicts-report`, `snp-chain-claims-without-commitment`.

### ENV-6. The `vtpm` submodule carries the quote, the key's proof and the quoted PCRs

A `vtpm` submodule holds `cvm_tpm_quote` (the signed `TPMS_ATTEST`, its signature, the 24 PCR values of the bank, the bank), `cvm_tpm_ak` (how the attestation key is bound) and the PCRs it projects as registers.

- Why: the quote, the values it covers and the key's proof are verified together, so they travel together. Layer 12 gives the Azure rules.
- Where: Section 4.4. Cases: `azure-snp-quote-with-23-pcrs`, `azure-snp-register-differs-from-quoted-pcr`.

### ENV-7. JSON is the primary encoding, and each value has one encoding

Byte strings are base64url without padding and with zero trailing bits. Integers are exact and never floating point. A duplicate member, a `null`, an object written as an array and an enumerated value written as an object are refused, and an implementation whose JSON library admits any of them refuses them itself.

- Why: two verifiers must never read different claims from the same bytes. Each of these is a real difference between common JSON libraries.
- Where: Section 4.7. Cases: `envelope-byte-string-padded`, `envelope-byte-string-standard-alphabet`, `envelope-byte-string-noncanonical`, `envelope-duplicate-member`, `envelope-duplicate-member-in-cvm-object`, `envelope-duplicate-label-in-cmw-collection`, `envelope-null-member`, `envelope-object-as-array`, `envelope-enumerated-value-as-object`, `envelope-floating-point`.

### ENV-8. Unknown claims are ignored, unknown members of profile objects are refused

An unknown claim at the top level or in a submodule's claims set is ignored whatever it holds. An unknown member inside a `cvm_*` object is refused. `cvm_provenance` is reserved, and its value is ignored.

- Why: EAT extensibility applies to claims sets. The profile's own objects are closed, so a misspelled member cannot silently drop a requirement.
- Where: Section 4.7. Cases: `envelope-unknown-claim-ignored`, `snp-unknown-submodule-claim-ignored`, `snp-unknown-cvm-field-refused`, `snp-provenance-ignored`.

### ENV-9. Bounds are checked before parsing

The envelope is at most 10 MiB, JSON nests at most 32 levels, a CMW collection has at most 32 entries and one level of nesting, and a byte string is at most 1 MiB after decoding. Each bound is checked before the input it covers is parsed, and the nesting bound applies to ignored claims.

- Why: evidence is attacker-controlled, and an ignored claim can still exhaust a recursive parser.
- Where: Sections 4.7, 15.10. Cases: `envelope-at-size-bound`, `envelope-over-size-bound`, `envelope-nesting-at-bound`, `envelope-nesting-over-bound`, `envelope-field-at-bound`, `envelope-field-over-bound`, `envelope-cmw-collection-over-bound`.
