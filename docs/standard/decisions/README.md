# Decision register

One file per layer of the review stack, from layer 2 on. Layer 1 holds the map and this page and decides nothing. Each entry records one choice the standard makes: what was chosen, why, what was rejected, and where the text and the corpus carry it. The register is a review aid. The standard governs, and an entry that disagrees with the text is a defect in the entry.

An entry has a stable identifier (a prefix for its layer and a number), a first paragraph that states the choice as the text makes it, and up to three bullets: `Why`, `Rejected`, and `Where` (sections, then the cases that exercise it, with the layer a case arrives in when that is a later one).

Status:

- An entry without a marker is in the text and in the reference implementation. Merging the layer that carries it accepts it.
- `(open)` marks a question with options and a recommendation. The text states the current choice until the question closes, and the module stays at draft while an entry is open.
- `(proposed)` marks a change the register proposes that the text does not make yet.

An entry changes only together with the text and the cases it names (Section 14.5). A withdrawn identifier is never reused.

| File | Module | Sections | Entries | Open or proposed |
| --- | --- | --- | --- | --- |
| [02-model.md](02-model.md) | Model | 1 to 3 | 8 | |
| [03-procedure-conformance.md](03-procedure-conformance.md) | Procedure and conformance | 11, 14 | 10 | PRC-9, PRC-10 (proposed) |
| [04-evidence.md](04-evidence.md) | Evidence | 4.1 to 4.4, 4.7, 4.8 | 9 | |
| [05-binding.md](05-binding.md) | Freshness and binding | 5.1 to 5.4 | 8 | BND-8 |
| [06-endorsements.md](06-endorsements.md) | Endorsements | 10 | 6 | |
| [07-policy.md](07-policy.md) | Policy | 13.1 to 13.4 | 8 | |
| [08-results.md](08-results.md) | Appraisal results | 12 | 10 | RES-7, RES-8, RES-9 |
| [09-registers-logs.md](09-registers-logs.md) | Registers and logs | 6, 7 | 7 | |
| [10-sev-snp.md](10-sev-snp.md) | SEV-SNP | 9.1 | 8 | |
| [11-tdx.md](11-tdx.md) | TDX, Google Cloud, dstack | 9.2, 9.3, 9.5 | 8 | |
| [12-azure.md](12-azure.md) | Azure | 9.4 | 6 | |
| [13-nvidia.md](13-nvidia.md) | NVIDIA devices | 4.5, 9.7, 13.5 | 8 | |
| [14-snp-software-registers.md](14-snp-software-registers.md) | SEV-SNP software registers | 8 | 7 | |
| [15-arm-cca.md](15-arm-cca.md) | Arm CCA | 4.6, 9.6 | 6 | |
| [16-certificate-cbor.md](16-certificate-cbor.md) | Certificate pattern and CBOR | 5.5, Appendix A | 5 | CBR-2 |
| [17-considerations.md](17-considerations.md) | Considerations | 15 to 17 | 9 | CON-2, CON-6 |
| [18-companions.md](18-companions.md) | Companions | 18, 19, Appendices C to E | 4 | |

127 entries: 118 in the text, 7 open, 2 proposed.
