#!/usr/bin/env node
//
// Live SNP attestation → WASM verification example.
//
// 1. Generates fresh attestation evidence with a report_data nonce (native)
// 2. Asks the verifier which vendor URLs the evidence needs, and fetches them
// 3. Verifies the evidence and the report_data binding entirely in WASM
//
// Usage:
//   cargo build -p attestation-cli --features attest
//   cd crates/attestation-wasm && wasm-pack build --target nodejs
//   node example.mjs
//

import { execFileSync } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = join(__dirname, '..', '..');

const nonce = 'wasm-verify-' + Date.now();
const envelope = execFileSync(
  'cargo',
  [
    'run', '--manifest-path', join(workspaceRoot, 'Cargo.toml'),
    '-p', 'attestation-cli', '--features', 'attest', '--quiet', '--',
    'attest', '--platform', 'snp', '--report-data', nonce,
  ],
  { encoding: 'utf-8', timeout: 30000 }
).trim();

const wasm = await import('./pkg/attestation_wasm.js');

// Fetch the URLs the evidence needs, keeping the issuer-chain header Intel sends.
const ISSUER_CHAIN_HEADERS = [
  'TCB-Info-Issuer-Chain',
  'SGX-Enclave-Identity-Issuer-Chain',
  'SGX-PCK-CRL-Issuer-Chain',
];
const needed = JSON.parse(await wasm.collateral_needed(envelope));
const collateral = [];
for (const url of needed) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`${url}: ${resp.status}`);
  const header = ISSUER_CHAIN_HEADERS.map((h) => resp.headers.get(h)).find(Boolean);
  collateral.push({
    url,
    body: Buffer.from(await resp.arrayBuffer()).toString('base64'),
    issuer_chain: header ? decodeURIComponent(header) : undefined,
  });
}

const evaluate = (reportData) =>
  JSON.parse(
    // evaluate(envelope, platforms, report_data, init_data, rtmr3, min_tcb, collateral)
    wasm.evaluate(envelope, ['snp'], reportData, undefined, undefined, undefined,
      JSON.stringify(collateral))
  );

const result = await evaluate(new TextEncoder().encode(nonce));
console.log(JSON.stringify(result, null, 2));
const mismatch = await evaluate(new TextEncoder().encode('wrong-nonce'));

if (result.passed !== true || result.report_data_match !== true) {
  console.error('FAILED: evidence did not pass');
  process.exit(1);
}
if (mismatch.report_data_match !== false || mismatch.passed !== false) {
  console.error('FAILED: wrong nonce was not rejected');
  process.exit(1);
}
console.log('PASSED: live SNP evidence verified in WASM with report_data binding');
