//! The one place collateral is fetched from a vendor.

use super::artifact::{validity, Collateral, Origin};
use super::error::{CollateralError, CollateralResult};
use super::key::{CollateralKey, CollateralKind};
use super::{
    pcs_issuer_chain_from_header, snp_cert_chain_url, snp_crl_url, snp_vcek_url, HttpTimeouts,
    INTEL_ENCLAVE_IDENTITY_ISSUER_CHAIN_HEADER, INTEL_TCB_INFO_ISSUER_CHAIN_HEADER,
};
use chrono::Utc;

/// Maximum response body (5 MiB); the largest real artifact, a PCK CRL, is well under 1 MiB.
pub const MAX_RESPONSE_SIZE: usize = 5 * 1024 * 1024;

/// Vendor endpoints. `upstream_override` rebases every URL's scheme and host
/// onto one origin, which is how tests point the fetcher at a loopback server.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub amd_kds_vcek_base: String,
    pub intel_sgx_pcs_base: String,
    pub intel_tdx_pcs_base: String,
    pub intel_root_ca_crl_url: String,
    pub upstream_override: Option<String>,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            amd_kds_vcek_base: super::AMD_KDS_VCEK_BASE.to_string(),
            intel_sgx_pcs_base: super::INTEL_PCS_V4_BASE.to_string(),
            intel_tdx_pcs_base: super::INTEL_TDX_PCS_V4_BASE.to_string(),
            intel_root_ca_crl_url: super::INTEL_ROOT_CA_CRL_URL.to_string(),
            upstream_override: None,
        }
    }
}

impl Endpoints {
    /// Every fetch goes to `origin` instead of the vendor host.
    pub fn with_upstream_override(mut self, origin: impl Into<String>) -> Self {
        self.upstream_override = Some(origin.into());
        self
    }

    fn rebase(&self, url: String) -> String {
        let Some(base) = &self.upstream_override else {
            return url;
        };
        let path_start = url
            .find("://")
            .map(|i| i + 3)
            .and_then(|i| url[i..].find('/').map(|j| i + j))
            .unwrap_or(url.len());
        format!("{}{}", base.trim_end_matches('/'), &url[path_start..])
    }

    /// The URL a key is fetched from, before any rebase.
    pub fn vendor_url(&self, key: &CollateralKey) -> CollateralResult<String> {
        Ok(match key {
            CollateralKey::SnpVcek {
                generation,
                chip_id,
                tcb,
            } => {
                let url = snp_vcek_url(*generation, chip_id, tcb).map_err(|e| {
                    CollateralError::NoUrl {
                        key: key.clone(),
                        reason: e.to_string(),
                    }
                })?;
                url.replacen(super::AMD_KDS_VCEK_BASE, &self.amd_kds_vcek_base, 1)
            }
            CollateralKey::SnpCertChain { generation } => snp_cert_chain_url(*generation).replacen(
                super::AMD_KDS_VCEK_BASE,
                &self.amd_kds_vcek_base,
                1,
            ),
            CollateralKey::SnpCrl { generation } => snp_crl_url(*generation).replacen(
                super::AMD_KDS_VCEK_BASE,
                &self.amd_kds_vcek_base,
                1,
            ),
            CollateralKey::TdxTcbInfo { fmspc } => {
                format!("{}/tcb?fmspc={fmspc}", self.intel_tdx_pcs_base)
            }
            CollateralKey::TdxQeIdentity { td: true } => {
                format!("{}/qe/identity", self.intel_tdx_pcs_base)
            }
            CollateralKey::TdxQeIdentity { td: false } => {
                format!("{}/qe/identity", self.intel_sgx_pcs_base)
            }
            CollateralKey::TdxPckCrl { ca } => {
                format!("{}/pckcrl?ca={}", self.intel_sgx_pcs_base, ca.as_str())
            }
            CollateralKey::TdxRootCrl => self.intel_root_ca_crl_url.clone(),
            CollateralKey::NrasJwks { url } => url.clone(),
        })
    }

    pub fn url(&self, key: &CollateralKey) -> CollateralResult<String> {
        self.vendor_url(key).map(|u| self.rebase(u))
    }
}

pub struct Fetcher {
    client: reqwest::Client,
    endpoints: Endpoints,
}

impl Fetcher {
    pub fn new(timeouts: &HttpTimeouts, endpoints: Endpoints) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeouts.request_timeout)
            .connect_timeout(timeouts.connect_timeout)
            .build()
            .expect("reqwest client with static configuration");
        Fetcher { client, endpoints }
    }

    pub fn with_client(client: reqwest::Client, endpoints: Endpoints) -> Self {
        Fetcher { client, endpoints }
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// Fetch, validate and canonicalize one artifact. `now` is the caller's
    /// clock, so the expiry check and `fetched_at` agree with the cache.
    pub async fn fetch(
        &self,
        key: &CollateralKey,
        now: chrono::DateTime<Utc>,
    ) -> CollateralResult<Collateral> {
        let url = self.endpoints.url(key)?;
        let fetch_err = |reason: String| CollateralError::Fetch {
            key: key.clone(),
            reason,
        };
        log::info!("fetching {key} from {url}");
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| fetch_err(format!("request: {e}")))?
            .error_for_status()
            .map_err(|e| fetch_err(format!("status: {e}")))?;

        // Signed PCS bodies arrive with their Intel signing chain in a header.
        // The verifier checks the signature only when handed that chain, so a
        // body without it is refused rather than evaluated unsigned.
        let header = match key.kind() {
            CollateralKind::TdxTcbInfo => Some(INTEL_TCB_INFO_ISSUER_CHAIN_HEADER),
            CollateralKind::TdxQeIdentity => Some(INTEL_ENCLAVE_IDENTITY_ISSUER_CHAIN_HEADER),
            _ => None,
        };
        let signing_chain = match header {
            Some(h) => Some(
                response
                    .headers()
                    .get(h)
                    .and_then(|v| v.to_str().ok())
                    .map(pcs_issuer_chain_from_header)
                    .ok_or(CollateralError::Unsigned {
                        key: key.clone(),
                        header: h,
                    })?,
            ),
            None => None,
        };

        if let Some(len) = response.content_length() {
            if len as usize > MAX_RESPONSE_SIZE {
                return Err(CollateralError::TooLarge {
                    key: key.clone(),
                    size: len as usize,
                    max: MAX_RESPONSE_SIZE,
                });
            }
        }
        let mut bytes = response
            .bytes()
            .await
            .map_err(|e| fetch_err(format!("body: {e}")))?
            .to_vec();
        if bytes.len() > MAX_RESPONSE_SIZE {
            return Err(CollateralError::TooLarge {
                key: key.clone(),
                size: bytes.len(),
                max: MAX_RESPONSE_SIZE,
            });
        }

        // Intel serves PCK CRLs as PEM; the verifier consumes DER.
        if matches!(
            key.kind(),
            CollateralKind::TdxPckCrl | CollateralKind::TdxRootCrl
        ) && crate::utils::is_pem(&bytes)
        {
            bytes =
                crate::utils::decode_pem_to_der(&bytes).map_err(|e| CollateralError::Parse {
                    key: key.clone(),
                    reason: format!("CRL PEM: {e}"),
                })?;
        }

        let fetched_at = now;
        let valid_until = validity::valid_until(key, &bytes)?;
        if let Some(until) = valid_until {
            if until <= fetched_at {
                return Err(CollateralError::Expired {
                    key: key.clone(),
                    valid_until: until,
                });
            }
        }
        Ok(Collateral {
            key: key.clone(),
            bytes,
            signing_chain,
            fetched_at,
            valid_until,
            origin: Origin::Fetched,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProcessorGeneration;

    #[test]
    fn urls_follow_the_library_rules_and_rebase_only_scheme_and_host() {
        let e = Endpoints::default();
        assert_eq!(
            e.url(&CollateralKey::SnpCrl {
                generation: ProcessorGeneration::Genoa
            })
            .unwrap(),
            "https://kdsintf.amd.com/vcek/v1/Genoa/crl"
        );
        assert_eq!(
            e.url(&CollateralKey::TdxTcbInfo {
                fmspc: "50806f000000".into()
            })
            .unwrap(),
            "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000"
        );
        assert_eq!(
            e.url(&CollateralKey::TdxQeIdentity { td: true }).unwrap(),
            "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
        );
        assert_eq!(
            e.url(&CollateralKey::TdxQeIdentity { td: false }).unwrap(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity"
        );
        assert_eq!(
            e.url(&CollateralKey::TdxPckCrl {
                ca: super::super::key::PckCa::Platform
            })
            .unwrap(),
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform"
        );
        let r = Endpoints::default().with_upstream_override("http://127.0.0.1:9/");
        assert_eq!(
            r.url(&CollateralKey::TdxRootCrl).unwrap(),
            "http://127.0.0.1:9/IntelSGXRootCA.der"
        );
        assert_eq!(
            r.url(&CollateralKey::TdxPckCrl {
                ca: super::super::key::PckCa::Processor
            })
            .unwrap(),
            "http://127.0.0.1:9/sgx/certification/v4/pckcrl?ca=processor"
        );
        let turin_no_fmc = CollateralKey::SnpVcek {
            generation: ProcessorGeneration::Turin,
            chip_id: [1; 64],
            tcb: crate::types::SnpTcb {
                bootloader: 1,
                tee: 1,
                snp: 1,
                microcode: 1,
                fmc: None,
            },
        };
        assert!(matches!(
            e.url(&turin_no_fmc),
            Err(CollateralError::NoUrl { .. })
        ));
    }
}
