use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};

use az_cvm_vtpm::{hcl, tdx, vtpm};
use zerocopy::IntoBytes;

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::{azure_vtpm_available, TpmQuote};
use crate::utils::pad_report_data;

use super::evidence::AzTdxEvidence;

const IMDS_QUOTE_URL: &str = "http://169.254.169.254/acc/tdquote";

#[derive(serde::Deserialize)]
struct QuoteResponse {
    quote: String,
}

/// Fetch TD quote from Azure IMDS.
async fn get_td_quote_from_imds(td_report: &tdx::TdReport) -> Result<Vec<u8>> {
    let report_b64 = BASE64URL.encode(td_report.as_bytes());
    let body = serde_json::json!({ "report": report_b64 });

    // Microsoft requires IMDS clients to bypass proxies; reqwest honors
    // HTTP_PROXY and similar settings unless told not to.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .no_proxy()
        .build()
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("build HTTP client: {}", e)))?;
    let response = client
        .post(IMDS_QUOTE_URL)
        .json(&body)
        .send()
        .await
        .map_err(|e| AttestationError::HardwareAccessFailed(format!("IMDS POST failed: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        return Err(AttestationError::HardwareAccessFailed(format!(
            "IMDS returned {}: {}",
            status, body_text
        )));
    }

    let quote_resp: QuoteResponse = response.json().await.map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("IMDS response parse failed: {}", e))
    })?;

    crate::utils::decode_base64url(&quote_resp.quote).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("IMDS quote base64 decode failed: {}", e))
    })
}

/// Check if Azure TDX platform is available.
pub fn is_available() -> bool {
    if !azure_vtpm_available() {
        return false;
    }
    let report = match vtpm::get_report() {
        Ok(report) => report,
        Err(e) => {
            log::debug!("Azure TDX detection failed: {}", e);
            return false;
        }
    };

    match hcl::HclReport::new(report) {
        Ok(hcl_report) => hcl_report.report_type() == hcl::ReportType::Tdx,
        Err(e) => {
            log::debug!("Azure TDX HCL report parsing failed: {}", e);
            false
        }
    }
}

/// Convert az-cvm-vtpm Quote to our TpmQuote format.
fn quote_to_tpm_quote(q: vtpm::Quote) -> TpmQuote {
    TpmQuote {
        signature: hex::encode(q.signature()),
        message: hex::encode(q.message()),
        pcrs: q.pcrs_sha256().map(hex::encode).collect(),
    }
}

/// Generate Azure TDX attestation evidence with explicit quote method.
///
/// The `method` parameter is ignored — Azure TDX always uses IMDS for
/// quote generation, not ConfigFS TSM or vsock.
pub async fn generate_evidence_with(
    report_data: &[u8],
    _method: crate::platforms::tdx::attest::TdxQuoteMethod,
) -> Result<AzTdxEvidence> {
    generate_evidence(report_data).await
}

/// Generate Azure TDX attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzTdxEvidence> {
    // Validate size fits in 64-byte report_data field, but do NOT pad:
    // TPM2B_DATA (used by vtpm::get_quote) has a smaller max size than 64 bytes
    // on Azure vTPMs, so we must pass the original unpadded data as the nonce.
    let _ = pad_report_data(report_data, 64)?;

    // 1. Write report_data to TPM NV index, wait for HCL to regenerate TD report,
    //    then read the updated HCL report from vTPM NVRAM.
    let hcl_report_bytes = vtpm::get_report_with_report_data(report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!(
            "vtpm::get_report_with_report_data failed: {}",
            e
        ))
    })?;

    // 2. Encode HCL report before passing ownership to parser
    let hcl_report_b64 = BASE64URL.encode(&hcl_report_bytes);

    // 3. Parse HCL envelope and extract TD report
    let hcl_report = hcl::HclReport::new(hcl_report_bytes).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("HclReport::new failed: {}", e))
    })?;
    let td_report: tdx::TdReport = hcl_report.try_into().map_err(|e: hcl::HclError| {
        AttestationError::HardwareAccessFailed(format!(
            "failed to extract TdReport from HCL: {}",
            e
        ))
    })?;

    // 4. Get TD quote from Azure IMDS (signed by Intel QE)
    let td_quote_bytes = get_td_quote_from_imds(&td_report).await?;

    // 5. Generate TPM quote with report_data as nonce (unpadded)
    let quote = vtpm::get_quote(report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_quote failed: {}", e))
    })?;
    let tpm_quote = quote_to_tpm_quote(quote);

    // 6. Assemble evidence
    Ok(AzTdxEvidence {
        version: 1,
        tpm_quote,
        hcl_report: hcl_report_b64,
        td_quote: BASE64URL.encode(&td_quote_bytes),
    })
}
