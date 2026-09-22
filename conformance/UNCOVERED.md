# Statements without a case

Normative statements of the design doc (sections 4 to 7) that no case in
`cases/` exercises yet, with what closes each. The list shrinks; an entry is
removed in the commit that adds its case.

| Section | Statement | What closes it |
| --- | --- | --- |
| 4.4, 4.5 | `commitment` binding on SNP, and every rule of section 4.9 (genesis, chain_len, boot record, claim records, slot owners) | evidence from the SNP register driver, which does not exist yet; the vectors of Appendix B cover the formulas until then |
| 4.5 | the `certificate` pattern and the `spki-sha256`, `x509-tbs-sha256` and `raw` key kinds | a recording made with a key binding |
| 4.5 | `nras-nonce` binding and every GPU and NVSwitch rule of sections 4.4, 5.3 and 7 | a recording of GPU evidence with its NRAS exchange; NVIDIA's recorded tokens in `crates/attestation/test_data/nvidia_gpu` carry no evidence |
| 4.5 | `cca-challenge` and the Arm CCA rules | Arm CCA hardware |
| 4.7 | `snp-vmr` and `cca-rem` registers, the `backing` floor | the driver and Arm hardware; the SNP floor can be shown once a recording carries a `kernel-service` register |
| 4.8 | `tcg-cel-cbor`, `tcg-cel-json`, `dstack-json` and `tpm2-event-log` on a live quote | a TDX recording with a CEL log, a dstack GetQuote recording with its quote, and an Azure recording that includes the vTPM event log; the unit tests of `tcg-cel` and `profile::cel` cover the parsing and replay rules against recorded logs without a quote |
| 4.10 | the size bounds (submodule count, CMW collection size, byte string and envelope limits) and CBOR encoding | synthetic envelopes at each bound; the CBOR encoding needs the CBOR entry point |
| 5.3 | `ear_all_submods_bound` false with an unbound submodule | a multi-submodule envelope with one failing binding |
| 6 | step 3 VLEK detection, step 6 `revoked` and `collateral-invalid` outcomes, TCB Info `nextUpdate` in the past | a VLEK recording; a CRL fixture that revokes the fixture's certificate; the fixture collateral evaluated after 2026-04-15 |
| 7 | `reference.registers`, `reference.host_data`, `reference.slot_owners`, `default_floor` selection per machine, `owner` policy | synthetic policies against the existing recordings; slot owners need the driver |
