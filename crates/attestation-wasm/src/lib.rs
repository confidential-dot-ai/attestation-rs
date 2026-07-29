use wasm_bindgen::prelude::*;

use attestation::platforms::az_snp::evidence::AzSnpEvidence;
use attestation::platforms::az_snp::verify::verify_report;
use attestation::platforms::az_tdx::evidence::AzTdxEvidence;
use attestation::platforms::az_tdx::verify::verify_evidence as verify_az_tdx_evidence;
use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::claims::extract_claims;
use attestation::platforms::snp::verify::{
    parse_report, verify_cert_chain, verify_report_signature,
};
use attestation::platforms::tdx::evidence::TdxEvidence;
use attestation::platforms::tdx::verify::verify_evidence as verify_tdx_evidence;
use attestation::types::{ProcessorGeneration, VerifyParams};
use attestation::utils::{constant_time_eq, pad_report_data};

/// Verify attestation evidence from a self-describing envelope — the generic,
/// platform-dispatching entry point and the preferred API for JS embedders.
///
/// `envelope_json` is the core [`attestation::AttestationEvidence`] envelope:
/// `{ "platform": "<tag>", "evidence": { ... } }`, where `platform` is one of
/// the compiled-in platform tags (`snp`, `tdx`, `az-snp`, `az-tdx`, `gcp-snp`,
/// `gcp-tdx` with default features) and `evidence` is that platform's evidence
/// payload, verbatim. Dispatch happens in the Rust core
/// (`Verifier::verify_platform`), so JS callers need no per-platform routing —
/// but they MUST assert the platform themselves by comparing the result's
/// `platform` field against the one they expect, never trusting a
/// server-chosen tag to pick the verification path.
///
/// Runs in offline mode ([`attestation::Verifier::offline`]): quote signatures
/// and cert chains verify against the bundled AMD/Intel roots (SNP evidence
/// must carry its VEK inline, as c8s evidence does), the SNP processor
/// generation is auto-detected from the report's CPUID fields (v3+ reports),
/// and the network-backed collateral checks (PCK CRL, TCB status, QE identity)
/// are skipped — `collateral_verified` stays `false`. Debug guests are always
/// rejected (`allow_debug` is never exposed to the browser; fail closed).
///
/// The freshness semantics of `expected_report_data` are per-platform, handled
/// inside each core verifier: for bare-metal platforms it is checked against
/// the hardware quote's `report_data` (zero-padded, constant-time); for the
/// Azure vTPM platforms it is checked against the vTPM quote's `extraData`.
/// Either way a supplied-but-mismatched anchor fails closed.
///
/// - `envelope_json`: `{ platform, evidence }` envelope JSON
/// - `expected_report_data`: optional freshness anchor bytes
/// - `expected_init_data_hash`: optional init-data binding (SNP HOST_DATA /
///   TDX MRCONFIGID / vTPM PCR[8])
///
/// Returns the [`attestation::types::VerificationResult`] as JSON, or throws
/// on any check failure.
#[wasm_bindgen]
pub async fn verify(
    envelope_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        ..VerifyParams::default()
    };

    let result = attestation::Verifier::offline()
        .verify(envelope_json.as_bytes(), &params)
        .await
        .map_err(|e| JsError::new(&format!("verify: {e}")))?;

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

/// Verify live SNP evidence in WASM.
///
/// - `evidence_json`: evidence JSON with inline cert_chain.vcek
/// - `generation`: processor generation ("milan", "genoa", "turin")
/// - `expected_report_data`: optional raw bytes to check against report_data in the report
///
/// Returns verification result as JSON.
#[wasm_bindgen]
pub fn verify_snp(
    evidence_json: &str,
    generation: &str,
    expected_report_data: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let gen = match generation {
        "milan" | "Milan" => ProcessorGeneration::Milan,
        "genoa" | "Genoa" => ProcessorGeneration::Genoa,
        "turin" | "Turin" => ProcessorGeneration::Turin,
        _ => return Err(JsError::new(&format!("unknown generation: {generation}"))),
    };

    let evidence: attestation::platforms::snp::evidence::SnpEvidence =
        serde_json::from_str(evidence_json)
            .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    use base64::Engine;
    let report_bytes = base64::engine::general_purpose::STANDARD
        .decode(&evidence.attestation_report)
        .map_err(|e| JsError::new(&format!("base64 decode report: {e}")))?;

    let report =
        parse_report(&report_bytes).map_err(|e| JsError::new(&format!("parse report: {e}")))?;

    // Get VCEK from evidence
    let vcek_der = match &evidence.cert_chain {
        Some(chain) => base64::engine::general_purpose::STANDARD
            .decode(&chain.vcek)
            .map_err(|e| JsError::new(&format!("base64 decode vcek: {e}")))?,
        None => return Err(JsError::new("evidence missing cert_chain.vcek")),
    };

    // Verify cert chain (bundled ARK/ASK -> VCEK)
    let (ark, ask) = get_bundled_certs(gen);
    verify_cert_chain(ark, ask, &vcek_der)
        .map_err(|e| JsError::new(&format!("cert chain verify: {e}")))?;

    // Verify report signature
    verify_report_signature(&report_bytes, &vcek_der)
        .map_err(|e| JsError::new(&format!("report signature: {e}")))?;

    // Guest-policy enforcement — mirrors the native `verify_report` path
    // (`platforms/snp/verify.rs`: VMPL==0 and debug-policy rejection). Without
    // these, a malicious host can launch the *correctly-measured* image as a
    // debug-enabled or non-VMPL-0 SNP guest: the launch_digest still matches a
    // pinned allowlist, the VCEK chain and report signature are genuine, and
    // report_data still binds the session key — yet the hypervisor can read the
    // guest's memory (debug) or a lower-privilege VMPL can, so it extracts the
    // session key and reads the "confidential" channel. The browser entry has no
    // `allow_debug` opt-in: it fails closed. (SEV-SNP guest policy lives in the
    // report, not the launch measurement, so a measurement pin cannot catch this.)
    if report.vmpl != 0 {
        return Err(JsError::new(&format!(
            "VMPL check failed: report VMPL is {} (expected 0)",
            report.vmpl
        )));
    }
    if report.policy.debug_allowed() {
        return Err(JsError::new(
            "SNP guest policy permits debug (host can read guest memory); rejecting (fail closed)",
        ));
    }

    // Check report_data binding
    let report_data_match = expected_report_data.map(|expected| {
        let padded = pad_report_data(&expected, 64).unwrap_or_default();
        constant_time_eq(&report.report_data[..], &padded)
    });

    // Extract claims
    let claims = extract_claims(&report);

    let result = serde_json::json!({
        "signature_valid": true,
        "platform": "snp",
        "report_version": report.version,
        "report_data_match": report_data_match,
        "claims": claims,
    });

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

/// Verify Azure SEV-SNP (az-snp) vTPM attestation evidence in WASM.
///
/// Unlike [`verify_snp`], which only checks the bare SNP hardware report, this
/// verifies the full az-snp evidence: the HCL-wrapped SNP report **and** the
/// vTPM quote that binds freshness. The freshness anchor for az-snp lives in
/// the TPM quote's `extraData` (qualifyingData), not in the SNP `report_data`
/// — the SNP `report_data` instead binds the vTPM attestation key (AK).
///
/// Verification (mirrors the native async path, minus the CRL revocation check
/// which needs an async cert provider — so `collateral_verified` is always
/// `false` here):
/// 1. Verify the TPM quote signature with the AK extracted from HCL var_data.
/// 2. Check the quote's `extraData` equals `expected_report_data` (freshness),
///    failing closed when an anchor is supplied and does not match.
/// 3. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
/// 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
/// 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
///    SNP report signature, then enforce VMPL/debug/TCB policy.
///
/// - `evidence_json`: az-snp evidence JSON (`{ version, tpm_quote, hcl_report, vcek }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
///
/// Returns the verification result as JSON, or throws on any check failure.
#[wasm_bindgen]
pub fn verify_az_snp(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let evidence: AzSnpEvidence = serde_json::from_str(evidence_json)
        .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    // Run the full az-snp verification core, freshness included. When an anchor is
    // supplied, the core binds the TPM quote's extraData (qualifyingData) to it and
    // fails closed on a mismatch — defense in depth, rather than downgrading the
    // freshness check to a non-throwing bool for the JS policy layer to interpret.
    // The core still populates report_data_match (Some(true) when an anchor was
    // supplied and matched, None otherwise) for the result shape.
    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        ..VerifyParams::default()
    };

    let verified = verify_report(&evidence, &params)
        .map_err(|e| JsError::new(&format!("az-snp verify: {e}")))?;

    // Serialize the VerificationResult, then graft on report_version, matching the
    // shape verify_snp returns so the JS policy layer reads it uniformly.
    let mut result = serde_json::to_value(&verified.result)
        .map_err(|e| JsError::new(&format!("json serialize: {e}")))?;
    result["report_version"] = serde_json::json!(verified.report_version);

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

/// Verify bare-metal Intel TDX (tdx) DCAP attestation evidence in WASM.
///
/// This is the direct-DCAP counterpart of [`verify_az_tdx`]: no vTPM in the
/// path, so the freshness anchor lives directly in the TD quote's 64-byte
/// `report_data` (zero-padded), as produced by attesters that bind
/// `SHA-384(anchor)` — e.g. a serving-cert SPKI + nonce, or a session
/// public key + nonce. Verification (see `platforms/tdx/verify.rs`):
/// 1. Parse the TD quote (v4/v5) and verify its ECDSA P-256 signature.
/// 2. Verify the full DCAP chain: PCK cert chain to the pinned Intel SGX Root
///    CA, QE report signature, and QE report binding.
/// 3. Enforce the TD debug-attribute policy (reject debug TDs — no opt-in here).
/// 4. Bind `report_data` to `expected_report_data` (padded, constant-time),
///    failing closed when an anchor is supplied and does not match.
/// 5. Optionally bind MRCONFIGID to `expected_init_data_hash`.
/// 6. When the evidence carries a `cc_eventlog`, replay it against RTMR0–3 and
///    fail closed on any divergence.
///
/// Like the other vTPM-less entry points, the DCAP **collateral** checks (PCK
/// CRL, TCB status, TD-QE identity) need an async provider and are skipped in
/// WASM, so `collateral_verified` is always `false`. The measurement surfaces
/// as `claims.launch_digest` = hex(MRTD); MRTD/RTMR pinning is the JS policy
/// layer's job.
///
/// - `evidence_json`: tdx evidence JSON (`{ quote, cc_eventlog? }`, base64 std)
/// - `expected_report_data`: optional raw bytes the TD quote `report_data`
///   must equal after zero-padding to 64 bytes
/// - `expected_init_data_hash`: optional bytes to bind against MRCONFIGID
///
/// Returns the verification result as JSON, or throws on any check failure.
///
/// `async` for the same reason as [`verify_az_tdx`]: the shared core is
/// `async` for its optional collateral provider; with a `None` provider it
/// performs no actual awaiting. Callers `await` the returned Promise.
#[wasm_bindgen]
pub async fn verify_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let evidence: TdxEvidence = serde_json::from_str(&evidence_json)
        .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        ..VerifyParams::default()
    };

    // None collateral provider: CRL/TCB/QE-identity checks are skipped (same
    // trade-off the other WASM entry points document), collateral_verified
    // stays false.
    let result = verify_tdx_evidence(&evidence, &params, None)
        .await
        .map_err(|e| JsError::new(&format!("tdx verify: {e}")))?;

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

/// Verify Azure TDX (az-tdx) vTPM attestation evidence in WASM.
///
/// The Azure TDX shape mirrors az-snp: the freshness anchor lives in the vTPM
/// quote's `extraData` (qualifyingData), while the Intel-signed TD quote's
/// `report_data` binds the vTPM attestation key (AK). Verification order
/// (see `platforms/az_tdx/verify.rs`):
/// 1. Parse the HCL report and require `report_type == TDX`.
/// 2. Verify the vTPM quote signature with the AK extracted from HCL var_data.
/// 3. Check the quote's `extraData` equals `expected_report_data` (freshness),
///    failing closed when an anchor is supplied and does not match.
/// 4. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
/// 5. Parse the TD quote, verify its ECDSA signature, and verify the DCAP chain
///    to the pinned Intel SGX Root CA.
/// 6. Enforce the TD debug-attribute policy (reject debug TDs — no opt-in here).
/// 7. Bind the AK to the TEE: `td_report.report_data[..32] == SHA-256(var_data)`.
///
/// Like [`verify_az_snp`], the DCAP **collateral** checks (PCK CRL, TCB status,
/// TD-QE identity) need an async provider and are skipped in WASM, so
/// `collateral_verified` is always `false`. The measurement surfaces as
/// `claims.launch_digest` = hex(MRTD); MRTD/RTMR pinning is the JS policy
/// layer's job (a mismatch is reported, not fatal, in the core).
///
/// - `evidence_json`: az-tdx evidence JSON (`{ version, tpm_quote, hcl_report, td_quote }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
///
/// Returns the verification result as JSON, or throws on any check failure.
///
/// This is `async` (unlike `verify_az_snp`, whose core is sync) because the
/// shared az-tdx core is `async` for its optional collateral provider; with a
/// `None` provider it performs no actual awaiting. Callers `await` the returned
/// Promise.
#[wasm_bindgen]
pub async fn verify_az_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let evidence: AzTdxEvidence = serde_json::from_str(&evidence_json)
        .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        ..VerifyParams::default()
    };

    // None collateral provider: CRL/TCB/QE-identity checks are skipped (same
    // trade-off verify_az_snp documents), collateral_verified stays false.
    let result = verify_az_tdx_evidence(&evidence, &params, None)
        .await
        .map_err(|e| JsError::new(&format!("az-tdx verify: {e}")))?;

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}
