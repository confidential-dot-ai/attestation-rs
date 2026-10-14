#!/usr/bin/env node
//
// Live SNP attestation → WASM verification example.
//
// 1. Generates fresh attestation evidence with report_data nonce (native)
// 2. Fetches the VCEK from AMD KDS
// 3. Verifies the evidence + report_data binding entirely in WASM
//
// Usage:
//   cargo build -p attestation-cli --features attest
//   cd crates/attestation-wasm && wasm-pack build --target nodejs
//   node example.mjs
//

import { execSync } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = join(__dirname, '..', '..');

// --- Step 1: Generate live evidence with a nonce ---
console.log('=== Step 1: Generating live SNP attestation evidence ===\n');

const nonce = 'wasm-verify-' + Date.now();
console.log(`Nonce: "${nonce}"`);

const cliOutput = execSync(
  `cargo run --manifest-path ${workspaceRoot}/Cargo.toml -p attestation-cli --features attest --quiet -- attest --platform snp --report-data "${nonce}"`,
  { encoding: 'utf-8', timeout: 30000 }
);

const evidence = JSON.parse(cliOutput.trim());
const reportB64 = evidence.attestation_report;
const reportBuf = Buffer.from(reportB64, 'base64');

console.log(`Report size: ${reportBuf.length} bytes`);

// Parse fields from raw report for display + VCEK fetch
const version = reportBuf.readUInt32LE(0);
const vmpl = reportBuf.readUInt32LE(0x1C);
const sigAlgo = reportBuf.readUInt32LE(0x34);
const reportData = reportBuf.slice(0x38, 0x78);
const measurement = reportBuf.slice(0x90, 0xC0);
const chipId = reportBuf.slice(0x1A0, 0x1E0);
const blSPL = reportBuf[0x180];
const teeSPL = reportBuf[0x181];
const snpSPL = reportBuf[0x186];
const ucodeSPL = reportBuf[0x187];

console.log(`\nReport fields:`);
console.log(`  Version:     ${version}`);
console.log(`  VMPL:        ${vmpl}`);
console.log(`  Sig algo:    ${sigAlgo} (1=ECDSA P-384)`);
console.log(`  TCB:         bl=${blSPL} tee=${teeSPL} snp=${snpSPL} ucode=${ucodeSPL}`);
console.log(`  Measurement: ${measurement.toString('hex').slice(0, 32)}...`);
console.log(`  Report data: ${reportData.toString('hex').slice(0, 32)}...`);
console.log(`  Chip ID:     ${chipId.toString('hex').slice(0, 32)}...`);

// --- Step 2: Fetch VCEK from AMD KDS ---
console.log('\n=== Step 2: Fetching VCEK from AMD KDS ===\n');

const chipIdHex = chipId.toString('hex');
const kdsUrl = `https://kdsintf.amd.com/vcek/v1/Genoa/${chipIdHex}?blSPL=${blSPL}&teeSPL=${teeSPL}&snpSPL=${snpSPL}&ucodeSPL=${ucodeSPL}`;
console.log(`KDS URL: ${kdsUrl.slice(0, 80)}...`);

const resp = await fetch(kdsUrl);
if (!resp.ok) throw new Error(`KDS fetch failed: ${resp.status} ${resp.statusText}`);
const vcekDer = Buffer.from(await resp.arrayBuffer());
console.log(`VCEK fetched: ${vcekDer.length} bytes (DER)`);

// Inject VCEK into evidence
evidence.cert_chain = { vcek: vcekDer.toString('base64') };

console.log(`Full evidence with cert chain: ${JSON.stringify(evidence).length} bytes`);

// --- Step 3: Verify in WASM with report_data binding ---
console.log('\n=== Step 3: Verifying in WASM (with report_data check) ===\n');

const wasm = await import('./pkg/attestation_wasm.js');
const nonceBytes = new TextEncoder().encode(nonce);

const t0 = performance.now();
const resultJson = wasm.verify_snp(JSON.stringify(evidence), 'genoa', nonceBytes);
const elapsed = (performance.now() - t0).toFixed(1);
const result = JSON.parse(resultJson);

console.log(`Verified in ${elapsed}ms\n`);
console.log(JSON.stringify(result, null, 2));

// --- Step 4: Verify report_data mismatch is caught ---
console.log('\n=== Step 4: Verifying wrong report_data is rejected ===\n');

const wrongNonce = new TextEncoder().encode('wrong-nonce');
const mismatchJson = wasm.verify_snp(JSON.stringify(evidence), 'genoa', wrongNonce);
const mismatch = JSON.parse(mismatchJson);
console.log(`report_data_match with wrong nonce: ${mismatch.report_data_match}`);
console.log(`issues: ${JSON.stringify(mismatch.issues)}`);

// --- Step 5: Verify without report_data check ---
console.log('\n=== Step 5: Verifying without report_data check ===\n');

const noCheckJson = wasm.verify_snp(JSON.stringify(evidence), 'genoa', undefined);
const noCheck = JSON.parse(noCheckJson);
console.log(`report_data_match (no check): ${noCheck.report_data_match}`);

// --- Summary ---
console.log('\n=== Summary ===\n');
console.log(`Signature valid:      ${result.signature_valid}`);
console.log(`Report data match:    ${result.report_data_match}`);
console.log(`Platform:             ${result.platform}`);
console.log(`Report version:       ${result.report_version}`);
console.log(`Launch digest:        ${result.claims.launch_digest}`);
console.log(`Report data (hex):    ${result.claims.report_data}`);
console.log(`Init data (hex):      ${result.claims.init_data}`);
console.log(`TCB:                  bl=${result.claims.tcb.bootloader} tee=${result.claims.tcb.tee} snp=${result.claims.tcb.snp} ucode=${result.claims.tcb.microcode}`);
console.log(`VMPL:                 ${result.claims.platform_data.vmpl}`);
console.log(`Debug allowed:        ${result.claims.platform_data.policy.debug_allowed}`);

if (!result.signature_valid) {
  console.error('\nFAILED: signature not valid');
  process.exit(1);
}
if (result.report_data_match !== true) {
  console.error('\nFAILED: report_data did not match nonce');
  process.exit(1);
}
if (mismatch.report_data_match !== false || mismatch.passed !== false) {
  console.error('\nFAILED: wrong nonce was not rejected');
  process.exit(1);
}

console.log('\nPASSED: live SNP evidence verified in WASM with report_data binding');
