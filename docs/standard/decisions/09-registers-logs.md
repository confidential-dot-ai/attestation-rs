# Layer 9: registers and logs

Sections 6 and 7: the model for runtime measurements and the logs that replay to them. The model is shared by TDX RTMRs, vTPM PCRs, Arm CCA REMs and the SEV-SNP software registers of layer 14.

### REG-1. A register is index, algorithm, value, source and backing

`cvm_registers` is an array of `{index, alg, value, source, backing}`. The source is one of `tdx-rtmr`, `snp-vmr`, `vtpm-pcr`, `cca-rem`, the algorithm is pinned per source, and each `(source, index)` appears at most once.

- Why: a register value means nothing without where it is held and what protects it. Naming both lets one policy cover every platform.
- Where: Sections 6.1, 6.2. Cases: `tdx-register-alg-not-sha384`, `tdx-register-value-wrong-length`, `tdx-register-repeated`, `tdx-register-index-out-of-range`, `azure-snp-register-outside-bank`.

### REG-2. Slots 0 to 3 mean the same on every platform

Slot 0 is firmware configuration, slot 1 what the firmware loads, slot 2 the kernel, command line and initial RAM disk, slot 3 runtime, following the TDX RTMR assignment. The launch measurement has its own claim and no register index. The UEFI `MrIndex` convention, which is offset by one, is converted on ingest.

- Why: a reference value for "the kernel" names slot 2 on TDX and on Arm CCA. On SEV-SNP software registers the kernel is covered by the launch measurement, and slots 0 to 2 hold only what the kernel records into them. vTPM PCRs keep their numbers and are told apart by `source`.
- Where: Sections 6.2, 6.3.

### REG-3. `backing` names what protects a register, and the policy sets a floor

The levels are `hardware`, `privileged-service`, `kernel-service` and `virtualized`. In evidence `backing` is a hint constrained by the source. In results it is what the verifier established, never higher than the evidence claimed. The policy's `min_backing` defaults to `hardware`, and the appraisal reports the weakest backing it saw.

- Why: a guarantee must not be downgraded from hardware to software without the policy saying so, and a relying party has to see which level it received.
- Rejected: one "runtime measurements" claim that treats a TDX RTMR and a software register as equal.
- Where: Sections 6.4, 13.1, 15.2. Cases: `tdx-register-backing-not-hardware`, `azure-snp-register-backing-hardware`, `azure-snp-backing-below-minimum` (layer 7).

### REG-4. The envelope's register values are never trusted

The authoritative values are the RTMRs in the signed quote, the REMs in the signed realm token, the PCRs under the quote's signed digest, and for `snp-vmr` the values the signed commitment reproduces from. Every envelope entry must equal them.

- Why: `cvm_registers[].value` is unsigned envelope data. A verifier that reads it without binding it fails open.
- Where: Sections 3.4, 6.5. Cases: `tdx-register-differs-from-quote`, `azure-snp-quoted-pcrs-altered`, `snp-registers-without-commitment`.

### REG-5. A log parses whole or is refused, and every format becomes CEL records

`cvm_log` is `{format, data}`. The admitted formats depend on the submodule: `tcg-cel-cbor`, `tcg-cel-json`, `tdx-ccel` and `dstack-json` on TDX, the two CEL encodings on SEV-SNP in `commitment` mode, `tpm2-event-log` on a vTPM. A verifier never uses the parsable prefix of a truncated log. The Confidential Containers `aael` format is refused in version 1.

- Why: one replay engine over one record type, with the existing firmware and agent formats accepted on ingest. The TCG Canonical Event Log is a published record format with a CBOR and a JSON encoding and an extension point for new content types.
- Where: Sections 7.1, 7.2. Cases: `tdx-cel-log-unparseable`, `tdx-aael-log-unsupported`, `azure-snp-vtpm-log-not-tpm2` (layer 12).

### REG-6. Runtime events use a `cvm` CEL content type

A `cvm` record carries `{seq, event}`, where `event` is deterministic CBOR `{domain, operation, content_digest, content?}` and the extended digest is `SHA-384("ats-mr-v1/record" || u64le(seq) || u16le(pcr) || event)`. `seq` orders records across registers. Domain `ats` is reserved for the profile's own records. The content type value is 200, taken through the CEL extension socket.

- Why: CEL numbers records per register, so the order across registers has to live in the content the digest covers. Binding `seq` and the slot into the digest stops a record from being replayed in another position.
- Where: Sections 7.3, 17.4, Appendix B.3 (layer 14).

### REG-7. Replay must reproduce, with one stated exception

Every register a log extends must replay to its authoritative value, or the verifier refuses with `replay-mismatch`. A register the log never extends counts as replayed exactly when it still holds its starting value. For `tdx-ccel`, RTMR 3 is reported with `replayed` false when it does not reproduce. The register array is required whenever a log is present.

- Why: a log that does not account for a register says nothing about it. The RTMR 3 exception exists because agents that extend it after boot do not all append to the CCEL.
- Where: Sections 6.1, 7.4. Cases: `tdx-ccel-replays-every-rtmr`, `tdx-cel-cbor-replays`, `tdx-cel-json-replays`, `tdx-ccel-from-another-boot`, `tdx-cel-log-from-another-boot`, `tdx-log-without-registers`.
