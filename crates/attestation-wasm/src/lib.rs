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
use attestation::types::{ProcessorGeneration, VerifyParams};
use attestation::utils::{constant_time_eq, pad_report_data};

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

    serde_json::to_string_pretty(&result)
        .map_err(|e| JsError::new(&format!("json serialize: {e}")))
}
