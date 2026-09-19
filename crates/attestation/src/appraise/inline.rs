//! Inline endorsements (`cvm_endorsements`, section 4.6) as a collateral
//! source in front of the verifier's providers. Inline artifacts are inputs,
//! never authority: each is parsed as the kind its label names, bound to the
//! parameters the verifier asks for, and checked to be inside its window
//! before it is used; anything else falls through to the providers.

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

    fn entry(&self, label: &str) -> Option<&'a [u8]> {
        match self.endorsements?.entries.get(label)? {
            CmwEntry::Record(r) => Some(r.value.as_slice()),
            CmwEntry::Collection(_) => None,
        }
    }

    /// An inline artifact bound to `key` and inside its window, or `None`
    /// (with a warning) so the caller falls back to its provider.
    fn bound(&self, label: &str, key: &CollateralKey, bytes: &[u8]) -> Option<Vec<u8>> {
        match validity::inspect(key, bytes) {
            Ok(until) if until.is_some_and(|u| self.now >= u) => {
                log::warn!("inline {label} is past its window ({until:?}); using the provider");
                None
            }
            Ok(_) => Some(bytes.to_vec()),
            Err(e) => {
                log::warn!("inline {label} rejected: {e}; using the provider");
                None
            }
        }
    }

    fn signed(&self, label: &str, key: &CollateralKey) -> Option<SignedCollateral> {
        let raw = self.entry(label)?;
        let pcs: InlinePcs = match serde_json::from_slice(raw) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("inline {label} is not {{body, issuer_chain}}: {e}; using the provider");
                return None;
            }
        };
        let body = self.bound(label, key, pcs.body.as_slice())?;
        if pcs.issuer_chain.is_empty() {
            log::warn!("inline {label} carries no issuer chain; using the provider");
            return None;
        }
        Some(SignedCollateral {
            body,
            signing_chain: pcs.issuer_chain.0.clone(),
        })
    }

    fn tdx_or_err(&self) -> Result<&'a dyn TdxCollateralProvider> {
        self.tdx.ok_or_else(|| {
            AttestationError::CertFetchError(
                "TDX collateral is needed but the verifier has no provider and the envelope carries no usable inline copy".to_string(),
            )
        })
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
            // A VLEK is also carried here; it is not keyed by chip id, so the
            // binding check is the chain and TCB cross-check the SNP path runs.
            if let Some(v) = self.bound("snp.vek", &key, bytes) {
                return Ok(v);
            }
            #[cfg(feature = "snp")]
            if crate::platforms::snp::verify::is_vlek_cert(bytes).unwrap_or(false) {
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
        if let Some(bytes) = self.entry("snp.crl") {
            if let Some(v) = self.bound("snp.crl", &key, bytes) {
                return Ok(Some(v));
            }
        }
        self.cert.get_snp_crl(processor_gen).await
    }
}

#[async_trait]
impl TdxCollateralProvider for InlineCollateral<'_> {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral> {
        if let Some(key) = CollateralKey::tdx_tcb_info(fmspc) {
            if let Some(s) = self.signed("tdx.tcb_info", &key) {
                return Ok(s);
            }
        }
        self.tdx_or_err()?.get_tcb_info(fmspc).await
    }

    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        self.tdx_or_err()?.get_qe_identity().await
    }

    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        if let Some(s) = self.signed(
            "tdx.qe_identity",
            &CollateralKey::TdxQeIdentity { td: true },
        ) {
            return Ok(s);
        }
        self.tdx_or_err()?.get_td_qe_identity().await
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        if let Some(bytes) = self.entry("tdx.root_crl") {
            if let Some(v) = self.bound("tdx.root_crl", &CollateralKey::TdxRootCrl, bytes) {
                return Ok(v);
            }
        }
        self.tdx_or_err()?.get_root_ca_crl().await
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        if let (Some(bytes), Some(ca_kind)) = (self.entry("tdx.pck_crl"), PckCa::parse(ca)) {
            if let Some(v) = self.bound(
                "tdx.pck_crl",
                &CollateralKey::TdxPckCrl { ca: ca_kind },
                bytes,
            ) {
                return Ok(v);
            }
        }
        self.tdx_or_err()?.get_pck_crl(ca).await
    }
}
