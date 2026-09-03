use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use serde::Deserialize;

use az_cvm_vtpm::{hcl, vtpm};

use crate::error::{AttestationError, Result};
use crate::platforms::tpm_common::{azure_vtpm_available, TpmQuote};
use crate::utils::pad_report_data;

use super::evidence::AzSnpEvidence;

const IMDS_CERT_URL: &str = "http://169.254.169.254/metadata/THIM/amd/certification";

/// IMDS is a per-VM service Azure documents as throttled and subject to
/// transient unavailability, and this fetch sits on the evidence path: one
/// blip otherwise fails the whole attestation. Bounded at three tries so a
/// hard outage still surfaces quickly rather than hanging the caller.
const IMDS_ATTEMPTS: u32 = 3;
const IMDS_RETRY_DELAY: Duration = Duration::from_millis(200);

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

/// Whether another attempt could plausibly answer differently. Throttling and
/// server-side faults are worth retrying; any other 4xx is a stable answer.
fn status_is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// One IMDS attempt. The flag says whether a retry is worth doing.
async fn fetch_imds_certs(
    client: &reqwest::Client,
) -> std::result::Result<ImdsCertificates, (AttestationError, bool)> {
    let response = client
        .get(IMDS_CERT_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|e| {
            // The request is an idempotent GET, so any send-side failure is
            // safe to repeat.
            let transient = e.is_timeout() || e.is_connect() || e.is_request();
            (
                AttestationError::CertFetchError(format!("IMDS request failed: {}", e)),
                transient,
            )
        })?;

    let status = response.status();
    if !status.is_success() {
        let retryable = status_is_retryable(status);
        let body = response.text().await.unwrap_or_default();
        return Err((
            AttestationError::CertFetchError(format!("IMDS returned {}: {}", status, body)),
            retryable,
        ));
    }

    response.json().await.map_err(|e| {
        (
            AttestationError::CertFetchError(format!("failed to parse IMDS cert response: {}", e)),
            false,
        )
    })
}

/// Calls `attempt_fn` until it succeeds, returns an error it marked
/// non-retryable, or spends the attempt budget. `base_delay` doubles per retry.
async fn retry_transient<T, F, Fut>(
    attempts: u32,
    base_delay: Duration,
    mut attempt_fn: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, (AttestationError, bool)>>,
{
    let mut delay = base_delay;
    let mut attempt = 1;

    loop {
        // Three outcomes, and only the last one continues: success and a
        // give-up both leave here, so the tail below is purely the backoff.
        let err = match attempt_fn().await {
            Ok(value) => return Ok(value),
            Err((err, retryable)) if !retryable || attempt >= attempts => return Err(err),
            Err((err, _)) => err,
        };

        log::warn!(
            "IMDS VCEK fetch attempt {}/{} failed, retrying in {:?}: {}",
            attempt,
            attempts,
            delay,
            err
        );
        tokio::time::sleep(delay).await;
        delay *= 2;
        attempt += 1;
    }
}

async fn get_imds_certs() -> Result<ImdsCertificates> {
    // Same budget as the az_tdx IMDS call, which this one previously lacked
    // entirely: without a timeout a stalled connect blocks evidence generation.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AttestationError::CertFetchError(format!("build HTTP client: {}", e)))?;

    retry_transient(IMDS_ATTEMPTS, IMDS_RETRY_DELAY, || {
        fetch_imds_certs(&client)
    })
    .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use std::cell::Cell;

    #[test]
    fn throttling_and_server_faults_are_retryable() {
        assert!(status_is_retryable(StatusCode::TOO_MANY_REQUESTS));
        assert!(status_is_retryable(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(status_is_retryable(StatusCode::SERVICE_UNAVAILABLE));
        assert!(status_is_retryable(StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn stable_client_errors_are_not_retryable() {
        // A malformed or unauthorized THIM request answers the same way every
        // time; retrying only multiplies the latency of a fixed failure.
        assert!(!status_is_retryable(StatusCode::BAD_REQUEST));
        assert!(!status_is_retryable(StatusCode::NOT_FOUND));
        assert!(!status_is_retryable(StatusCode::FORBIDDEN));
    }

    fn transient() -> (AttestationError, bool) {
        (
            AttestationError::CertFetchError("IMDS unreachable".into()),
            true,
        )
    }

    fn fatal() -> (AttestationError, bool) {
        (
            AttestationError::CertFetchError("IMDS returned 400".into()),
            false,
        )
    }

    // Zero delay keeps these instant; the backoff schedule is a tuning knob,
    // the loop's stop conditions are the behaviour worth pinning.
    #[tokio::test]
    async fn a_transient_failure_is_retried_until_it_succeeds() {
        let calls = Cell::new(0);
        let out = retry_transient(3, Duration::ZERO, || {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < 3 {
                    Err(transient())
                } else {
                    Ok(n)
                }
            }
        })
        .await;

        assert_eq!(out.unwrap(), 3);
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test]
    async fn the_attempt_budget_is_the_cap() {
        let calls = Cell::new(0);
        let out: Result<u32> = retry_transient(3, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            async { Err(transient()) }
        })
        .await;

        assert!(out.is_err());
        assert_eq!(calls.get(), 3, "must not exceed the budget");
    }

    #[tokio::test]
    async fn a_non_retryable_error_returns_on_the_first_attempt() {
        let calls = Cell::new(0);
        let out: Result<u32> = retry_transient(3, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            async { Err(fatal()) }
        })
        .await;

        assert!(out.is_err());
        assert_eq!(calls.get(), 1, "a stable answer must not be retried");
    }
}
