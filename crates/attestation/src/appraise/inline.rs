//! Inline endorsements (`cvm_endorsements`, section 4.6) as a collateral
//! source behind the verifier's providers. Inline artifacts are inputs, never
//! authority: the verifier's own collateral is used when it has any, and an
//! inline copy only stands in when a provider is absent or fails. Every inline
//! artifact is parsed as the kind its label names, bound to the parameters the
//! verifier asks for, and checked to be inside its window before use. The VEK
//! is the exception that is taken inline first: it is bound to the report by
//! the chain and the TCB cross-check, and a masked chip id has no other source.

use crate::collateral::artifact::validity;
use crate::collateral::{
    CertProvider, CollateralKey, PckCa, SignedCollateral, TdxCollateralProvider,
};
use crate::error::{AttestationError, Result};
use crate::profile::{CmwCollection, CmwEntry};
use crate::types::{ProcessorGeneration, SnpTcb};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub struct InlineCollateral<'a> {
    endorsements: Option<&'a CmwCollection>,
    cert: &'a dyn CertProvider,
    tdx: Option<&'a dyn TdxCollateralProvider>,
    now: DateTime<Utc>,
}

/// The inline form of a signed PCS body (section 4.6): the exact response
/// bytes and the PEM issuer chain, both byte strings.
#[derive(serde::Deserialize)]
struct InlinePcs {
    body: crate::profile::Bytes,
    issuer_chain: crate::profile::Bytes,
}

impl<'a> InlineCollateral<'a> {
    pub fn new(
        endorsements: Option<&'a CmwCollection>,
        cert: &'a dyn CertProvider,
        tdx: Option<&'a dyn TdxCollateralProvider>,
        now: DateTime<Utc>,
    ) -> Self {
        InlineCollateral {
            endorsements,
            cert,
            tdx,
            now,
        }
    }

    pub fn tdx(&self) -> Option<&'a dyn TdxCollateralProvider> {
        self.tdx
    }

    /// Whether the envelope carries an entry under this label.
    pub fn has(&self, label: &str) -> bool {
        self.entry(label).is_some()
    }

    /// The raw bytes under a label, unchecked; callers bind them themselves.
    pub fn raw(&self, label: &str) -> Option<&'a [u8]> {
        self.entry(label)
    }

    fn entry(&self, label: &str) -> Option<&'a [u8]> {
        match self.endorsements?.entries.get(label)? {
            CmwEntry::Record(r) => Some(r.value.as_slice()),
            CmwEntry::Collection(_) => None,
        }
    }

    /// An inline artifact bound to `key` and inside its window, or `None`
    /// with a warning.
    fn bound(&self, label: &str, key: &CollateralKey, bytes: &[u8]) -> Option<Vec<u8>> {
        match validity::inspect(key, bytes) {
            Ok(until) if until.is_some_and(|u| self.now >= u) => {
                log::warn!("inline {label} is past its window ({until:?}); not used");
                None
            }
            Ok(_) => Some(bytes.to_vec()),
            Err(e) => {
                log::warn!("inline {label} rejected: {e}; not used");
                None
            }
        }
    }

    fn signed(&self, label: &str, key: &CollateralKey) -> Option<SignedCollateral> {
        let raw = self.entry(label)?;
        let pcs: InlinePcs = match serde_json::from_slice(raw) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("inline {label} is not {{body, issuer_chain}}: {e}; not used");
                return None;
            }
        };
        let body = self.bound(label, key, pcs.body.as_slice())?;
        if pcs.issuer_chain.is_empty() {
            log::warn!("inline {label} carries no issuer chain; not used");
            return None;
        }
        Some(SignedCollateral {
            body,
            signing_chain: pcs.issuer_chain.0.clone(),
        })
    }

    fn no_source(&self, what: &str) -> AttestationError {
        AttestationError::CertFetchError(format!(
            "{what} is needed but the verifier has no provider and the envelope carries no usable inline copy"
        ))
    }

    /// The provider's answer when it has one, else the inline copy.
    async fn provider_first<T, F>(
        &self,
        from_provider: F,
        inline: Option<T>,
        what: &str,
    ) -> Result<T>
    where
        F: std::future::Future<Output = Option<Result<T>>>,
    {
        match from_provider.await {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => match inline {
                Some(v) => {
                    log::warn!("{what}: provider failed ({e}); using the inline copy");
                    Ok(v)
                }
                None => Err(e),
            },
            None => inline.ok_or_else(|| self.no_source(what)),
        }
    }
}

#[async_trait]
impl CertProvider for InlineCollateral<'_> {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        let key = CollateralKey::SnpVcek {
            generation: processor_gen,
            chip_id: *chip_id,
            tcb: *reported_tcb,
        };
        if let Some(bytes) = self.entry("snp.vek") {
            if let Some(v) = self.bound("snp.vek", &key, bytes) {
                return Ok(v);
            }
            // A VLEK is not keyed by chip id, so the binding is the chain and
            // the TCB cross-check the SNP path runs; only its window is
            // checked here.
            #[cfg(feature = "snp")]
            if crate::platforms::snp::verify::is_vlek_cert(bytes).unwrap_or(false)
                && crate::platforms::snp::verify::verify_vek_validity_period(bytes).is_ok()
            {
                return Ok(bytes.to_vec());
            }
        }
        self.cert
            .get_snp_vcek(processor_gen, chip_id, reported_tcb)
            .await
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.cert.get_snp_cert_chain(processor_gen).await
    }

    async fn get_snp_crl(&self, processor_gen: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
        let key = CollateralKey::SnpCrl {
            generation: processor_gen,
        };
        let inline = self
            .entry("snp.crl")
            .and_then(|b| self.bound("snp.crl", &key, b));
        match self.cert.get_snp_crl(processor_gen).await {
            Ok(Some(crl)) => Ok(Some(crl)),
            Ok(None) => Ok(inline),
            Err(e) => match inline {
                Some(crl) => {
                    log::warn!("SNP CRL: provider failed ({e}); using the inline copy");
                    Ok(Some(crl))
                }
                None => Err(e),
            },
        }
    }
}

#[async_trait]
impl TdxCollateralProvider for InlineCollateral<'_> {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral> {
        let inline =
            CollateralKey::tdx_tcb_info(fmspc).and_then(|k| self.signed("tdx.tcb_info", &k));
        let provider = async {
            match self.tdx {
                Some(p) => Some(p.get_tcb_info(fmspc).await),
                None => None,
            }
        };
        self.provider_first(provider, inline, "TCB Info").await
    }

    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        let provider = async {
            match self.tdx {
                Some(p) => Some(p.get_qe_identity().await),
                None => None,
            }
        };
        self.provider_first(provider, None, "QE Identity").await
    }

    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        let inline = self.signed(
            "tdx.qe_identity",
            &CollateralKey::TdxQeIdentity { td: true },
        );
        let provider = async {
            match self.tdx {
                Some(p) => Some(p.get_td_qe_identity().await),
                None => None,
            }
        };
        self.provider_first(provider, inline, "TD QE Identity")
            .await
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        let inline = self
            .entry("tdx.root_crl")
            .and_then(|b| self.bound("tdx.root_crl", &CollateralKey::TdxRootCrl, b));
        let provider = async {
            match self.tdx {
                Some(p) => Some(p.get_root_ca_crl().await),
                None => None,
            }
        };
        self.provider_first(provider, inline, "Intel root CRL")
            .await
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        let inline = match (self.entry("tdx.pck_crl"), PckCa::parse(ca)) {
            (Some(b), Some(kind)) => {
                self.bound("tdx.pck_crl", &CollateralKey::TdxPckCrl { ca: kind }, b)
            }
            _ => None,
        };
        let provider = async {
            match self.tdx {
                Some(p) => Some(p.get_pck_crl(ca).await),
                None => None,
            }
        };
        self.provider_first(provider, inline, "PCK CRL").await
    }

    fn now(&self) -> DateTime<Utc> {
        self.tdx.map_or(self.now, |p| p.now())
    }
}
