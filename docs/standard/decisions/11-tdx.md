# Layer 11: TDX, Google Cloud, dstack

Sections 9.2, 9.3 and 9.5, and Appendix B.5. Most of Section 9.2 transcribes Intel's quote format, PCK certificate profile and provisioning service; those facts are checked against the sources, the hardware run and the tests. The entries below are the choices this profile makes on top of them.

### TDX-1. Quote versions 4 and 5, with TDX 1.0 and 1.5 bodies

A version 4 quote and a version 5 quote with body type 2 (TDX 1.0, 584 bytes) or 3 (TDX 1.5, 648 bytes) are accepted, and the body size must equal its type's length. Body types 1 and 4 are refused with `report-invalid`.

- Why: these are the bodies Intel's quoting enclave produces for a TD today. Type 4 adds fields this version does not appraise.
- Where: Section 9.2.2. Case: `tdx-v4-quote-with-fixture-collateral` (layer 3). The corpus holds no version 5 quote (`UNCOVERED.md`).

### TDX-2. The TCB evaluation follows Intel's quote verification library at a pinned revision

Steps 1 to 4 of Section 9.2.3 specify the quote signature, the quoting enclave report, the PCK chain with both CRLs and the QE Identity. The TCB evaluation of step 5 (the TDX module identity, the platform level selection and the convergence of the statuses) follows Intel's library at the commit Section 19.1 names. Section 9.2.3 states three departures: a TDX 1.5 body is judged on `TEE_TCB_SVN` alone, the statuses a QE level may carry are not restricted, and neither are a module level's.

- Why: Intel's library is the behavior relying parties already depend on, and its level ordering and status convergence are not fully specified in prose anywhere else. Pinning a revision makes "as Intel does" a checkable statement.
- Where: Section 9.2.3. Cases: `tdx-tcb-info-for-another-fmspc`, `tdx-tcb-info-signature-forged` (layer 3). The module identity and level-ordering rules have unit tests and no case (`UNCOVERED.md`).

### TDX-3. The default accepted status is `UpToDate` alone

The effective Intel TCB status must be in `tcb.tdx_allowed_status`, which defaults to `["UpToDate"]`. `Revoked` can never be listed. An accepted status other than `UpToDate` is reported as `hardware` 32.

- Why: every other status means Intel knows of an issue the platform has not addressed, and accepting that is a relying party's decision to make by name.
- Where: Sections 9.2.3 (step 5), 12.4, 13.1. Cases: `tdx-tcb-status-not-allowed`, `policy-revoked-status-allowed` (layer 7).

### TDX-4. Debug is any of TD attribute bits 6:0

A TD is under debug when any bit of the debug group (3:0) or of the profiling group (6:4) is set, and is refused unless `allow_debug`. The bit assignments follow the TDX Module ABI specification.

- Why: under profiling the host observes the TD through performance counters and telemetry, which the ABI itself marks as exposing side-channel information. Treating it as debug keeps one rule for "the host can observe the guest".
- Where: Section 9.2.5. Case: `tdx-debug-attribute-refused` (layer 3), which sets the debug bit. The profiling group has no recording (`UNCOVERED.md`).

### TDX-5. Four more TD settings are strict by default

`SEPT_VE_DISABLE` must be set, every reserved attribute bit (mask `0x3FFFFFFF0780FF8E`) must be zero, and a migratable TD and a TD bound to a service TD are refused. Each has a named relaxation in `policy_bits`. The other defined bits (`ICSSD`, `SERVTD_EXT`, `LASS`, `PKS`, `KL`, `TPA`, `PERFMON`) are permitted, and `RESERVED_P` is ignored.

- Why: with `SEPT_VE_DISABLE` clear the host can inject exceptions into the guest kernel on private memory access, which Linux refuses to run under. A migratable TD and a TD bound to a service TD expose guest state to another party by design. A reserved bit set today is a feature this version cannot assess.
- Where: Sections 9.2.5, 13.1. No case: each needs a quote Intel's quoting enclave signed with that attribute (`UNCOVERED.md`).

### TDX-6. The generation is the FMSPC and the machine is the PPID

`cvm_platform.generation` is the PCK certificate's FMSPC, and `cvm_identity` is its PPID.

- Why: the FMSPC is what selects Intel's TCB Info, and the PPID is the one identifier the PCK chain authenticates per platform.
- Where: Sections 9.2.3, 9.2.4, 9.2.5.

### TDX-7. RTMRs are hardware registers, and a CCEL or CEL log replays to them

The four RTMRs of the signed quote are `tdx-rtmr` registers 0 to 3 with backing `hardware`. A `tdx-ccel` log maps `MrIndex` 1 to 4 to RTMR 0 to 3 and replays in SHA-384 from zero; RTMR 0 to 2 must reproduce, and RTMR 3 is reported with `replayed` false when it does not.

- Where: Sections 7.4, 9.2.6. Cases: `tdx-ccel-replays-every-rtmr`, `tdx-ccel-from-another-boot`, `tdx-register-differs-from-quote` (layer 9).

### TDX-8. dstack and Google Cloud reuse the TDX and SEV-SNP bindings

dstack evidence is the raw hardware report with hosting `dstack`, and its JSON event log is accepted with the digest rules of its two versions (version 2 carries the hashed bytes as `preimage`). Google Cloud evidence is bare-metal evidence with hosting `gcp`: the same report types, the configfs-tsm JSON included, and the same modes. The dstack attested-TLS certificate extensions are outside the profile.

- Why: both platforms expose the hardware report unchanged, so a new binding would only add surface. The dstack log is accepted as its guests produce it, so existing dstack deployments need no new agent.
- Where: Sections 5.5, 9.3, 9.5, Appendix B.5. Cases: `dstack-json-replays`, `dstack-json-runtime-event-altered`.
