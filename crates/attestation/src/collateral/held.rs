//! Collateral the caller already holds, served by key.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::{CertProvider, CollateralKey, Fmspc, SignedCollateral, TdxCollateralProvider};
use crate::error::{AttestationError, Result};
use crate::types::{ProcessorGeneration, SnpTcb};

/// One artifact: the bytes an endpoint serves, or a signed Intel body with
/// the chain that signs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldArtifact {
    Bytes(Vec<u8>),
    Signed(SignedCollateral),
}

/// A provider over collateral the caller holds, keyed by the text form of
/// [`CollateralKey`] (`snp_crl/Genoa`, `tdx_tcb_info/<fmspc>`, `tdx_root_crl`,
/// ...). A key it does not hold fails as unavailable collateral, so an
/// appraisal can use nothing beyond what the caller fixed: this is how a
/// conformance case (profile section 14.2) fixes its collateral. The AMD
/// vendor chain is never served; the roots are embedded.
#[derive(Debug, Clone, Default)]
pub struct HeldCollateral {
    artifacts: BTreeMap<String, HeldArtifact>,
    now: Option<DateTime<Utc>>,
}

impl HeldCollateral {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `bytes` under `key`, replacing an earlier artifact at that key.
    #[must_use]
    pub fn with_bytes(mut self, key: impl Into<String>, bytes: Vec<u8>) -> Self {
        self.artifacts
            .insert(key.into(), HeldArtifact::Bytes(bytes));
        self
    }

    /// Hold a signed Intel body with its signing chain under `key`.
    #[must_use]
    pub fn with_signed(
        mut self,
        key: impl Into<String>,
        body: Vec<u8>,
        signing_chain: Vec<u8>,
    ) -> Self {
        self.artifacts.insert(
            key.into(),
            HeldArtifact::Signed(SignedCollateral {
                body,
                signing_chain,
            }),
        );
        self
    }

    #[must_use]
    pub fn with_artifact(mut self, key: impl Into<String>, artifact: HeldArtifact) -> Self {
        self.artifacts.insert(key.into(), artifact);
        self
    }

    /// The instant [`TdxCollateralProvider::now`] answers with. The appraisal
    /// judges windows by the verifier's own clock (`Verifier::with_clock`);
    /// pin both to the same instant to fix an evaluation.
    #[must_use]
    pub fn at(mut self, now: DateTime<Utc>) -> Self {
        self.now = Some(now);
        self
    }

    pub fn get(&self, key: &str) -> Option<&HeldArtifact> {
        self.artifacts.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.artifacts.keys().map(String::as_str)
    }

    /// Whether any Intel artifact is held; a verifier without one skips the
    /// TDX collateral checks under its offline rules.
    pub fn holds_tdx(&self) -> bool {
        self.artifacts.keys().any(|k| k.starts_with("tdx_"))
    }

    fn bytes(&self, key: &str) -> Result<Vec<u8>> {
        match self.artifacts.get(key) {
            Some(HeldArtifact::Bytes(b)) => Ok(b.clone()),
            Some(HeldArtifact::Signed(_)) => Err(AttestationError::CertFetchError(format!(
                "{key}: a signed artifact is held where bytes were expected"
            ))),
            None => Err(AttestationError::CertFetchError(format!(
                "{key}: no such collateral is held"
            ))),
        }
    }

    fn signed(&self, key: &str) -> Result<SignedCollateral> {
        match self.artifacts.get(key) {
            Some(HeldArtifact::Signed(s)) => Ok(s.clone()),
            Some(HeldArtifact::Bytes(_)) => Err(AttestationError::CertFetchError(format!(
                "{key}: bytes are held where a signed artifact was expected"
            ))),
            None => Err(AttestationError::CertFetchError(format!(
                "{key}: no such collateral is held"
            ))),
        }
    }
}

#[async_trait]
impl CertProvider for HeldCollateral {
    async fn get_snp_vcek(
        &self,
        generation: ProcessorGeneration,
        chip_id: &[u8; 64],
        tcb: &SnpTcb,
    ) -> Result<Vec<u8>> {
        let key = CollateralKey::SnpVcek {
            generation,
            chip_id: *chip_id,
            tcb: *tcb,
        };
        self.bytes(&key.id())
    }

    async fn get_snp_cert_chain(
        &self,
        generation: ProcessorGeneration,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(AttestationError::CertFetchError(format!(
            "{}: held collateral serves no vendor chain; the roots are embedded",
            CollateralKey::SnpCertChain { generation }.id()
        )))
    }

    async fn get_snp_crl(&self, generation: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
        let key = CollateralKey::SnpCrl { generation }.id();
        match self.artifacts.get(&key) {
            Some(_) => self.bytes(&key).map(Some),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl TdxCollateralProvider for HeldCollateral {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<SignedCollateral> {
        let fmspc = Fmspc::new(fmspc).ok_or_else(|| {
            AttestationError::CertFetchError(format!("tdx_tcb_info: {fmspc:?} is not an FMSPC"))
        })?;
        self.signed(&CollateralKey::TdxTcbInfo { fmspc }.id())
    }

    async fn get_qe_identity(&self) -> Result<SignedCollateral> {
        self.signed(&CollateralKey::TdxQeIdentity { td: false }.id())
    }

    async fn get_td_qe_identity(&self) -> Result<SignedCollateral> {
        self.signed(&CollateralKey::TdxQeIdentity { td: true }.id())
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        self.bytes(&CollateralKey::TdxRootCrl.id())
    }

    async fn get_pck_crl(&self, ca: &str) -> Result<Vec<u8>> {
        // The text form takes any CA name so a request names what it wanted.
        self.bytes(&format!("tdx_pck_crl/{ca}"))
    }

    fn now(&self) -> DateTime<Utc> {
        self.now.unwrap_or_else(Utc::now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcb() -> SnpTcb {
        SnpTcb {
            bootloader: 10,
            tee: 0,
            snp: 27,
            microcode: 27,
            fmc: None,
        }
    }

    #[tokio::test]
    async fn serves_only_what_it_holds() {
        let held = HeldCollateral::new()
            .with_bytes("snp_crl/Genoa", vec![1])
            .with_bytes("tdx_root_crl", vec![2])
            .with_signed("tdx_tcb_info/50806f000000", vec![3], vec![4]);
        assert!(held.holds_tdx());
        assert_eq!(
            held.get_snp_crl(ProcessorGeneration::Genoa).await.unwrap(),
            Some(vec![1])
        );
        assert_eq!(
            held.get_snp_crl(ProcessorGeneration::Milan).await.unwrap(),
            None,
            "a CRL not held is absent, never an error"
        );
        assert_eq!(held.get_root_ca_crl().await.unwrap(), vec![2]);
        let info = held.get_tcb_info("50806F000000").await.unwrap();
        assert_eq!((info.body, info.signing_chain), (vec![3], vec![4]));
        for err in [
            held.get_snp_vcek(ProcessorGeneration::Genoa, &[0; 64], &tcb())
                .await
                .unwrap_err(),
            held.get_snp_cert_chain(ProcessorGeneration::Genoa)
                .await
                .unwrap_err(),
            held.get_td_qe_identity().await.unwrap_err(),
            held.get_pck_crl("platform").await.unwrap_err(),
            held.get_tcb_info("not-an-fmspc").await.unwrap_err(),
        ] {
            assert!(
                matches!(err, AttestationError::CertFetchError(_)),
                "unavailable, never another failure: {err}"
            );
        }
    }

    #[tokio::test]
    async fn shape_mismatch_is_unavailable() {
        let held = HeldCollateral::new()
            .with_signed("tdx_root_crl", vec![1], vec![2])
            .with_bytes("tdx_qe_identity/td", vec![3]);
        assert!(matches!(
            held.get_root_ca_crl().await.unwrap_err(),
            AttestationError::CertFetchError(_)
        ));
        assert!(matches!(
            held.get_td_qe_identity().await.unwrap_err(),
            AttestationError::CertFetchError(_)
        ));
    }

    #[test]
    fn pinned_clock() {
        let now = DateTime::parse_from_rfc3339("2026-03-17T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(HeldCollateral::new().at(now).now(), now);
        assert!(!HeldCollateral::new().holds_tdx());
    }
}
