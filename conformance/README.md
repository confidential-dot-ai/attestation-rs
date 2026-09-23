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
| `inputs/` | the envelopes, policies, collateral and recorded NRAS exchanges the cases reference; an input whose path ends in `.gz` is gzip-compressed and is its decompressed content |
| `UNCOVERED.md` | the normative statements that have no case yet |

The corpus is data. Every implementation runs it with its own runner, in its
own repository, and pins it by the attestation-rs commit or tag it was taken
from. A runner reads a case's inputs, hands them to the implementation with
the evaluation time pinned and the case's collateral and NRAS exchanges as the
only ones available, and compares the decision: the appraisal as parsed JSON
with the members of section 14.3 removed, or the refusal's section 14.4 code.

The Rust library is the reference implementation:

```bash
cargo test -p attestation --features nvidia-gpu --test conformance
```

checks every case, and `UPDATE_CONFORMANCE=1` rewrites the cases and their
expected appraisals from the reference implementation, which reviewers read as
part of the change that regenerated them; `CONFORMANCE_EXPLAIN=1` prints each
decision with the implementation's reason. The same test file holds the CDDL
module (`schemas/cvm-profile-v1.cddl`) to the JSON Schemas and the parsers.

The wasm build decides every case through its `appraise_with` entry:

```bash
cargo test -p attestation-wasm --test conformance
```
