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

## Harnesses

The corpus ships a harness for Go and one for JavaScript. Each loads the
cases, checks them against the section 14.2 format, reads a case's inputs,
applies the comparison rules of section 14.3 and reports one outcome per
case: `pass`, `fail` (another decision) or `error` (no decision). Neither
carries an implementation; each proves its own plumbing with `go test` and
`node --test`, by replaying every case's expectation through itself.

An implementation supplies an appraiser: a function from a case's inputs (the
evaluation time, the envelope, the policy or none for the section 7 default,
the held collateral keyed as section 8 keys collateral, the recorded NRAS
exchanges) to the section 5 appraisal as JSON, or a refusal with its section
14.4 code. Any other failure is reported as an error, never as a decision.

### Go

```go
import conformance "github.com/confidential-dot-ai/attestation-rs/conformance"

type appraiser struct{}

func (appraiser) Appraise(ctx context.Context, in *conformance.Inputs) ([]byte, error) {
    // ... return the appraisal JSON, or &conformance.Refusal{Code: conformance.BindingMismatch, Reason: "..."}
}

func TestConformance(t *testing.T) {
    corpus, err := conformance.Load() // the corpus embedded at this module version
    if err != nil {
        t.Fatal(err)
    }
    conformance.Test(t, corpus, appraiser{})
}
```

The corpus is embedded in the module, so a Go implementation pins a corpus
version by pinning the module at the tag `conformance/v<version>.0`;
`conformance.LoadDir` reads a checkout instead. attestation-go runs this once
it has `appraise`.

### JavaScript

```js
import { format, loadCorpus, run } from "./conformance/index.mjs";

const corpus = await loadCorpus();
const report = await run(corpus, async (inputs) => {
  // ... return the appraisal JSON; to refuse, throw an Error whose `code` is the section 14.4 code
});
process.stdout.write(format(report));
process.exitCode = report.passed ? 0 : 1;
```

The wasm build is the JavaScript implementation. Its adapter is
`crates/attestation-wasm/conformance.mjs`, which calls the `appraise_with`
export with the case's inputs and reads the refusal code from the thrown
`Error`'s `code`:

```bash
cd crates/attestation-wasm && wasm-pack build --target nodejs --release && node conformance.mjs
```

Both harnesses need Node 21 or later and Go 1.22 or later. Neither reaches a
network.
