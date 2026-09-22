# Conformance corpus

The executable form of the CVM attestation profile (design doc section 14): one
case per normative statement, each holding a profile envelope, a policy, the
collateral the appraisal may use, the evaluation time, and the decision the
profile requires, as an appraisal or a refusal code.

An implementation conforms to `tag:confidential.ai,2026:cvm#1` at the corpus
version in `VERSION` when it reproduces every case's decision under the
comparison rules of section 14.3. Nothing in a case reaches a network; the
evaluation time is an input.

| Path | Holds |
| --- | --- |
| `VERSION` | `<profile version>.<revision>`; any change to a case raises the revision |
| `cases/<id>.json` | one case, in the section 14.2 format |
| `inputs/` | the envelopes, policies, collateral and recorded NRAS exchanges the cases reference |
| `UNCOVERED.md` | the normative statements that have no case yet |

The Rust library is the reference implementation. Its runner is
`crates/attestation/tests/conformance.rs`: `cargo test -p attestation --features nvidia-gpu --test conformance`
checks every case, and `UPDATE_CONFORMANCE=1` rewrites the expected appraisals
from the reference implementation, which reviewers read as part of the change
that regenerated them. Other implementations only check.
