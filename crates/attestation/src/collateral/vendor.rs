//! Fetching documents from the vendors over HTTPS.

use std::time::Duration;

use super::document::{DocKey, Raw};
use crate::error::Unavailable;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BODY: usize = 5 * 1024 * 1024;
/// The longest Retry-After waited out inside one call; a longer one is
/// returned to the caller.
const MAX_RETRY_AFTER: u64 = 5;
/// Wait before the one retry: 200 ms plus up to 200 ms of jitter.
const RETRY_DELAY_MS: u64 = 200;

pub(crate) struct Vendor {
    client: reqwest::Client,
    /// Test seam: fetch `{base}/{host}/{path}` instead of `https://{host}/{path}`.
    base: Option<String>,
    #[cfg(feature = "nvidia-gpu")]
    pub(crate) nras: Nras,
}

impl Vendor {
    pub(crate) fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()
                .expect("HTTP client with static config"),
            base: None,
            #[cfg(feature = "nvidia-gpu")]
            nras: Nras::from_env(),
        }
    }

    pub(crate) fn with_base(mut self, base: &str) -> Self {
        self.base = Some(base.trim_end_matches('/').to_string());
        self
    }

    fn url(&self, url: String) -> String {
        match (&self.base, url.strip_prefix("https://")) {
            (Some(base), Some(rest)) => format!("{base}/{rest}"),
            _ => url,
        }
    }

    /// GET the document, retrying once on network errors, 408, 429 and 5xx
    /// (honouring a short Retry-After), never on 404/410. A hung vendor
    /// costs about 10 s.
    pub(crate) async fn fetch(&self, key: &DocKey) -> Result<Raw, Unavailable> {
        #[cfg(feature = "nvidia-gpu")]
        let url = match key {
            DocKey::NrasJwks(_) => {
                crate::platforms::nvidia_gpu::provider::jwks_url_for_endpoint(&self.nras.gpu_url)
                    .unwrap_or_else(|_| key.url())
            }
            _ => key.url(),
        };
        #[cfg(not(feature = "nvidia-gpu"))]
        let url = key.url();
        let url = self.url(url);
        let header = key.issuer_chain_header();
        let err = match self.get_once(&url, header).await {
            Ok(raw) => return Ok(raw),
            Err(e) => e,
        };
        let wait = match &err {
            Unavailable::RateLimited {
                retry_after: Some(s),
            } if *s > MAX_RETRY_AFTER => return Err(err),
            Unavailable::RateLimited {
                retry_after: Some(s),
            } => Duration::from_secs(*s),
            Unavailable::RateLimited { retry_after: None } | Unavailable::Unreachable { .. } => {
                retry_delay()
            }
            Unavailable::Status { status } if *status == 408 || *status >= 500 => retry_delay(),
            _ => return Err(err),
        };
        tokio::time::sleep(wait).await;
        self.get_once(&url, header).await
    }

    async fn get_once(&self, url: &str, header: Option<&str>) -> Result<Raw, Unavailable> {
        let unreachable = |e: reqwest::Error| Unavailable::Unreachable {
            detail: e.to_string(),
        };
        let response = self.client.get(url).send().await.map_err(unreachable)?;
        check_status(&response)?;
        let issuer_chain = header
            .and_then(|h| response.headers().get(h))
            .and_then(|v| v.to_str().ok())
            .map(percent_decode);
        let body = read_body(response).await?;
        Ok(Raw { body, issuer_chain })
    }
}

fn check_status(response: &reqwest::Response) -> Result<(), Unavailable> {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    match status {
        200..=299 => Ok(()),
        404 | 410 => Err(Unavailable::NotFound { status }),
        429 => Err(Unavailable::RateLimited { retry_after }),
        _ if retry_after.is_some() => Err(Unavailable::RateLimited { retry_after }),
        _ => Err(Unavailable::Status { status }),
    }
}

async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, Unavailable> {
    let too_large = || Unavailable::Unreachable {
        detail: format!("body exceeds {MAX_BODY} bytes"),
    };
    if response
        .content_length()
        .is_some_and(|l| l > MAX_BODY as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Unavailable::Unreachable {
            detail: format!("body: {e}"),
        })?
    {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Intel PCS percent-encodes the PEM in its issuer-chain headers.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// NVIDIA's remote attestation service. Its verdict is per evidence, so it
/// is called, not stored.
#[cfg(feature = "nvidia-gpu")]
pub(crate) struct Nras {
    pub(crate) gpu_url: String,
    pub(crate) switch_url: String,
    allow_hold_cert: bool,
    service_key: Option<String>,
}

#[cfg(feature = "nvidia-gpu")]
impl Nras {
    fn from_env() -> Self {
        use crate::platforms::nvidia_gpu::provider::{NRAS_GPU_URL, NRAS_SWITCH_URL};
        let env = |name: &str| std::env::var(name).ok();
        Self {
            gpu_url: env("NV_NRAS_GPU_URL").unwrap_or_else(|| NRAS_GPU_URL.into()),
            switch_url: env("NV_NRAS_SWITCH_URL").unwrap_or_else(|| NRAS_SWITCH_URL.into()),
            allow_hold_cert: env("NV_ALLOW_HOLD_CERT").as_deref() == Some("true"),
            service_key: env("NVIDIA_ATTESTATION_SERVICE_KEY"),
        }
    }
}

#[cfg(feature = "nvidia-gpu")]
impl Vendor {
    /// POST evidence to NRAS. 429 and 5xx are `CollateralUnavailable`; any
    /// other failure status is final.
    pub(crate) async fn nras_attest(
        &self,
        request: &crate::platforms::nvidia_gpu::provider::NrasRequest,
    ) -> crate::error::Result<serde_json::Value> {
        use crate::error::AttestationError;
        let url = match request.arch {
            crate::types::NvidiaGpuArch::Ls10 => &self.nras.switch_url,
            _ => &self.nras.gpu_url,
        };
        let mut req = self.client.post(self.url(url.clone())).json(request);
        if self.nras.allow_hold_cert {
            req = req.header(
                crate::platforms::nvidia_gpu::provider::HEADER_OCSP_ALLOW_CERT_HOLD,
                "true",
            );
        }
        if let Some(key) = &self.nras.service_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }
        let unavailable = |reason| AttestationError::CollateralUnavailable {
            document: "NRAS attestation".into(),
            reason,
        };
        let response = req.send().await.map_err(|e| {
            unavailable(Unavailable::Unreachable {
                detail: e.to_string(),
            })
        })?;
        let status = response.status();
        match check_status(&response) {
            Ok(()) => {}
            Err(reason @ (Unavailable::RateLimited { .. } | Unavailable::Status { .. }))
                if status.is_server_error() || status.as_u16() == 429 =>
            {
                return Err(unavailable(reason))
            }
            Err(_) => {
                let body = read_body(response).await.unwrap_or_default();
                let preview = String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned();
                return Err(AttestationError::NrasRequestFailed(format!(
                    "status {status}: {preview}"
                )));
            }
        }
        let body = read_body(response).await.map_err(unavailable)?;
        serde_json::from_slice(&body)
            .map_err(|e| AttestationError::NrasResponseParse(e.to_string()))
    }
}

fn retry_delay() -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    Duration::from_millis(RETRY_DELAY_MS + u64::from(nanos) % RETRY_DELAY_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_chain_headers_are_percent_decoded() {
        let encoded = "-----BEGIN%20CERTIFICATE-----%0AMIIB%2BzCC%0A-----END%20CERTIFICATE-----%0A";
        assert_eq!(
            percent_decode(encoded),
            "-----BEGIN CERTIFICATE-----\nMIIB+zCC\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn a_base_url_reroutes_every_vendor_host() {
        let v = Vendor::new().with_base("http://127.0.0.1:8080/");
        assert_eq!(
            v.url("https://kdsintf.amd.com/vcek/v1/Genoa/crl".into()),
            "http://127.0.0.1:8080/kdsintf.amd.com/vcek/v1/Genoa/crl"
        );
    }
}
