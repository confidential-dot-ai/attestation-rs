use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use serde::Deserialize;

use az_cvm_vtpm::{hcl, vtpm};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::{azure_vtpm_available, TpmQuote};
use crate::utils::pad_report_data;

use super::evidence::AzSnpEvidence;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";

#[derive(Deserialize)]
struct ImdsCertificates {
    #[serde(rename = "vcekCert")]
    vcek: String,
}

/// Check if Azure SNP platform is available.
pub fn is_available() -> bool {
    if !azure_vtpm_available() {
        return false;
    }
    let report = match vtpm::get_report() {
        Ok(report) => report,
        Err(e) => {
            log::debug!("Azure SNP detection failed: {}", e);
            return false;
        }
    };

    match hcl::HclReport::new(report) {
        Ok(hcl_report) => hcl_report.report_type() == hcl::ReportType::Snp,
        Err(e) => {
            log::debug!("Azure SNP HCL report parsing failed: {}", e);
            false
        }
    }
}

/// Convert a PEM-encoded certificate to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let (_label, der) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|e| {
        AttestationError::CertFetchError(format!("failed to decode VCEK PEM: {}", e))
    })?;
    Ok(der)
}

/// Convert az-cvm-vtpm Quote to our TpmQuote format.
fn quote_to_tpm_quote(q: vtpm::Quote) -> TpmQuote {
    TpmQuote {
        signature: hex::encode(q.signature()),
        message: hex::encode(q.message()),
        pcrs: q.pcrs_sha256().map(hex::encode).collect(),
    }
}

async fn get_imds_certs() -> Result<ImdsCertificates> {
    reqwest::Client::new()
        .get(IMDS_CERT_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|e| AttestationError::CertFetchError(format!("IMDS request failed: {}", e)))?
        .error_for_status()
        .map_err(|e| AttestationError::CertFetchError(format!("IMDS returned error: {}", e)))?
        .json()
        .await
        .map_err(|e| {
            AttestationError::CertFetchError(format!("failed to parse IMDS cert response: {}", e))
        })
}

/// Generate Azure SNP attestation evidence.
pub async fn generate_evidence(report_data: &[u8]) -> Result<AzSnpEvidence> {
    // Validate size fits the Azure vTPM TPM2B_DATA limit (50 bytes, smaller
    // than the 64-byte SNP report_data field), but do NOT pad: vtpm::get_quote
    // puts the data verbatim into the TPM nonce, and the verifier matches the
    // original unpadded report_data against the unpadded nonce
    // (tpm_common::verify_tpm_nonce requires equal lengths). Padding here would
    // make the quote's nonce longer than the expected report_data and fail
    // verification. Mirrors az_tdx/attest.
    let _ = pad_report_data(report_data, 50)?;

    // 1. Read HCL report from vTPM NVRAM
    let hcl_report_bytes = vtpm::get_report().map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_report failed: {}", e))
    })?;

    // 2. Generate TPM quote with report_data as nonce (unpadded)
    let quote = vtpm::get_quote(report_data).map_err(|e| {
        AttestationError::HardwareAccessFailed(format!("vtpm::get_quote failed: {}", e))
    })?;
    let tpm_quote = quote_to_tpm_quote(quote);

    // 3. Fetch VCEK certificate from Azure IMDS
    let certs = get_imds_certs().await?;
    let vcek_der = pem_to_der(&certs.vcek)?;

    // 4. Assemble evidence
    Ok(AzSnpEvidence {
        version: 1,
        tpm_quote,
        hcl_report: BASE64URL.encode(&hcl_report_bytes),
        vcek: BASE64URL.encode(&vcek_der),
    })
}
