#!/usr/bin/env node
// Runs the conformance corpus (design doc section 14) against this wasm
// build's `appraise_with` and exits non-zero unless every case passes.
//
//   wasm-pack build --target nodejs --release
//   node conformance.mjs [path/to/conformance]
//
// The mapping of section 14.3: a refusal is a thrown Error whose `code` is
// the section 14.4 code; an error without a code did not decide.

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { format, loadCorpus, run } from "../../conformance/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const { appraise_with } = createRequire(import.meta.url)(join(here, "pkg", "attestation_wasm.js"));

const utf8 = new TextDecoder("utf-8", { fatal: true });
const b64 = (bytes) => Buffer.from(bytes).toString("base64");

const corpus = await loadCorpus(process.argv[2]);
const report = await run(corpus, async (inputs) => {
  const collateral = {};
  for (const [key, a] of Object.entries(inputs.collateral)) {
    collateral[key] = { body: b64(a.body) };
    if (a.signingChain) collateral[key].signing_chain = b64(a.signingChain);
  }
  const nras = inputs.nras.map((x) => ({ arch: x.arch, nonce: x.nonce, response: utf8.decode(x.response), jwks: utf8.decode(x.jwks) }));
  return appraise_with(
    utf8.decode(inputs.evidence),
    inputs.policy === null ? undefined : utf8.decode(inputs.policy),
    JSON.stringify({ now: inputs.now, collateral, nras }),
  );
});
process.stdout.write(format(report));
process.exitCode = report.passed ? 0 : 1;
