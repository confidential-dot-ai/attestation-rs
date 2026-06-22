use wasm_bindgen::prelude::*;

use attestation::platforms::az_snp::evidence::AzSnpEvidence;
use attestation::platforms::az_snp::verify::verify_report;
use attestation::platforms::snp::certs::get_bundled_certs;
use attestation::platforms::snp::verify::{
    parse_report, verify_cert_chain, verify_report_signature,
};
use attestation::types::{ProcessorGeneration, VerifyParams};
use attestation::utils::{constant_time_eq, pad_report_data};

/// Verify live SNP evidence in WASM.
///
/// The WASM surface is canonical-only: the caller supplies the freshness anchor
/// as raw bytes, the verifier returns the new `VerifyResult` (canonical anchors
/// + vendor-specific parsed report). Vendor-precise pinning (min_tcb, AK
/// thumbprint, ...) is not surfaced — JS callers who need that build their own
/// dispatcher on top of this.
///
/// - `evidence_json`: evidence JSON with inline cert_chain.vcek
/// - `generation`: processor generation ("milan", "genoa", "turin")
/// - `expected_nonce`: optional raw bytes to compare against report_data
///
/// Returns the canonical verification result as JSON.
#[wasm_bindgen]
pub fn verify_snp(
    evidence_json: &str,
    generation: &str,
    expected_nonce: Option<Vec<u8>>,
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

    // Canonical anchor comparison: nonce vs report_data, zero-padded.
    let nonce_match = expected_nonce.map(|expected| {
        let padded = pad_report_data(&expected, 64).unwrap_or_default();
        constant_time_eq(&report.report_data[..], &padded)
    });

    // Build a stable canonical result shape with the parsed report payload.
    let result = serde_json::json!({
        "signature_valid": true,
        "collateral_verified": false,
        "platform": "snp",
        "report_version": report.version,
        "nonce_match": nonce_match,
        "launch_measurement": hex::encode(&report.measurement[..]),
        "report_data": hex::encode(&report.report_data[..]),
        "measurement": hex::encode(&report.measurement[..]),
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
/// 2. Check the quote's `extraData` equals `expected_nonce` (freshness anchor).
/// 3. Verify the PCR digest.
/// 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
/// 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
///    SNP report signature, then enforce VMPL/debug policy.
///
/// - `evidence_json`: az-snp evidence JSON
/// - `expected_nonce`: optional raw bytes the TPM quote `extraData` must equal
///
/// Returns the canonical [`VerifyResult`](attestation::VerifyResult) as JSON.
#[wasm_bindgen]
pub fn verify_az_snp(
    evidence_json: &str,
    expected_nonce: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let evidence: AzSnpEvidence = serde_json::from_str(evidence_json)
        .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    // Canonical-only on the WASM side. The verifier internally enforces
    // freshness via constant-time equality and surfaces the outcome on
    // `nonce_match`; no vendor-precise pinning here.
    let params = VerifyParams {
        nonce: expected_nonce,
        ..VerifyParams::default()
    };

    let verified = verify_report(&evidence, &params)
        .map_err(|e| JsError::new(&format!("az-snp verify: {e}")))?;

    // Serialize the canonical VerifyResult, augmented with report_version for
    // backward-compat with the existing JS dashboard.
    let mut result = serde_json::to_value(&verified.result)
        .map_err(|e| JsError::new(&format!("json serialize: {e}")))?;
    result["report_version"] = serde_json::json!(verified.report_version);

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}
