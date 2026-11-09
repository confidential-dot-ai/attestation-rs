# Layer 14: SEV-SNP software registers (experimental)

Section 8 and Appendices B.2 and B.3: `ats-mr-v1`, runtime registers for SEV-SNP guests held by a register provider in the measured guest. The reference implementation verifies the construction against the vectors. No register provider exists yet, so no genuine evidence does either, and the entries below are provisional until one produces evidence.

### SWR-1. Registers are committed into the report data of every report

A provider holds 16 registers of 48 bytes. Each starts at a genesis value derived from a constant seed, changes only by `R = SHA-384(R || d)`, and every report the guest obtains carries `header16 || C` as its report data, where `C` commits to all 16 registers, the number of extensions and the caller's 64 bytes (`pad64(anchor)`).

- Why: SEV-SNP has a launch measurement and 64 bytes of report data, and no runtime registers. Committing the registers into the report data puts them under the hardware signature without a firmware change.
- Rejected: a seed taken from the guest's first report, which would make the provider wait for a firmware call. A constant seed lets it accept its first extend before any report exists.
- Where: Section 8.1, Appendix B.2. Case: `snp-commitment-without-chain` (the envelope's shape only; the recompute has no case, `UNCOVERED.md`).

### SWR-2. The 16-byte header is pinned in full

`header16` is the magic `ATS-MR-1`, a version, the algorithm, the register count, flags and reserved bytes. The verifier compares all 16 bytes with one value, and the policy members that carry the header and the seed accept only that value.

- Why: a byte the verifier did not pin would be free for a caller to choose next to the commitment.
- Where: Sections 8.1, 13.1, 15.4. Case: `policy-commitment-header-not-pinned` (layer 7).

### SWR-3. Every chain opens with a boot record

At initialization the provider draws a 32-byte `bootseed` and extends, as record 0 into slot 3, an `ats` `boot` event whose `content_digest` is `SHA-384(bootseed)`. The seed travels in the `bootseed` claim. A chain therefore has `chain_len` of at least 1.

- Why: the boot record distinguishes the chains of one launch for an honest kernel and gives chain memory something to compare.
- Where: Section 8.2, Appendix B.3.

### SWR-4. Workload slots are claimed at first use

Slots 4 to 15 are allocated by a claim record: the first record into a slot is an `ats` `claim` event naming `owner` and `purpose`. The provider authenticates the owner and refuses an extend from anyone else. The verifier reports owner and purpose per slot and applies `reference.slot_owners`.

- Why: twelve producers can share one register bank without agreeing on slot numbers in advance, and a relying party can require that a named producer wrote a slot.
- Where: Sections 8.3, 13.4, Appendix B.3. Against guest root, `owner` shows only which slot a record entered (Section 8.4, item 6).

### SWR-5. The guarantee is a property of the measured image

The commitment is worth something only if no software in the guest can obtain a signed report without the provider. Sections 8.4 to 8.6 state what the image must ensure: the provider's nine requirements, exclusive control of the report path (the VMPCK and the secrets page stay in the kernel), and a kernel restriction set that keeps root out of ring 0. A verifier establishes these transitively, by pinning a launch measurement whose publisher documents the build.

- Why: the verifier sees a report and a log, and cannot observe the kernel's configuration. The launch measurement is the only handle on it, which is why `commitment` requires the pin (BND-6).
- Where: Sections 8.4, 8.5, 8.6, 8.7. Case: `snp-commitment-without-launch-measurement`.

### SWR-6. Version 1 reports every software register as `virtualized`

Whatever the evidence claims, a version 1 verifier reports `snp-vmr` registers with backing `virtualized`. Promotion to `kernel-service` needs a way for a reference value to state that an image satisfies Sections 8.4 to 8.6, which a later revision defines.

- Why: the verifier cannot yet establish the kernel restriction set, and a kernel compromise defeats the construction (Section 15.4). Reporting the weakest level means a policy accepts these registers only by setting `min_backing` to `virtualized`; a `kernel-service` minimum does not admit them.
- Where: Sections 8.7, 15.4.

### SWR-7. Chain memory is optional

A verifier that keeps state may record, per `REPORT_ID`, the `bootseed`, the highest `chain_len` and the register bank. One that detects a restart or a fork must refuse with `replay-mismatch`. A stateless verifier conforms.

- Why: evidence alone cannot show that a provider's history was rewritten after a kernel compromise. `REPORT_ID` is the one identifier of a launch the kernel cannot choose.
- Where: Section 8.8. The reference implementation keeps no chain memory.
