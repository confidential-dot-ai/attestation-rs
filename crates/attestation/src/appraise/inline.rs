//! Inline endorsements (`cvm_endorsements`, section 10.1) as a collateral
//! source behind the verifier's providers. Inline artifacts are inputs, never
//! authority: the verifier's own collateral is used when it has any, and an
//! inline copy only stands in when a provider is absent or fails. Every inline
//! artifact is parsed as the kind its label names, bound to the parameters the
//! verifier asks for, and checked to be inside its window before use. The VEK
//! is the exception that is taken inline first, once it is bound to the
//! report: a VCEK by the chip identifier and reported TCB it certifies, a VLEK
//! by the TCB, since KDS serves VLEKs only to the cloud provider.

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

/// The inline form of a signed PCS body (section 10.1): the exact response
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

    #[cfg_attr(not(feature = "tdx"), allow(dead_code))]
    pub fn tdx(&self) -> Option<&'a dyn TdxCollateralProvider> {
        self.tdx
    }

    /// Whether the envelope carries an entry under this label.
    #[cfg_attr(not(any(feature = "snp", feature = "tdx")), allow(dead_code))]
    pub fn has(&self, label: &str) -> bool {
        self.entry(label).is_some()
    }

    /// The inline `snp.vek` when it is a VLEK bound to the report (section
    /// 10.2): inside its window and certifying the reported TCB.
    #[cfg(feature = "snp")]
    pub fn inline_vlek(
        &self,
        chip_id: &[u8; 64],
        reported: &SnpTcb,
        processor_gen: ProcessorGeneration,
    ) -> Option<Vec<u8>> {
        self.bound_vek(true, chip_id, reported, processor_gen)
    }

    /// The inline `snp.vek` when it is a VEK of the requested key type, inside
    /// its window, that certifies the parameters naming it: the chip
    /// identifier (a VCEK) and the reported TCB. Any other is ignored as if
    /// absent (section 10.2), so the verifier's own source can serve.
    #[cfg(feature = "snp")]
    fn bound_vek(
        &self,
        vlek: bool,
        chip_id: &[u8; 64],
        reported: &SnpTcb,
        processor_gen: ProcessorGeneration,
    ) -> Option<Vec<u8>> {
        use crate::platforms::snp::verify::{
            is_vlek_cert, verify_vek_endorses, verify_vek_validity_period_at,
        };
        let bytes = self.entry("snp.vek")?;
        let why = match is_vlek_cert(bytes) {
            Err(e) => e.to_string(),
            Ok(is_vlek) if is_vlek != vlek => "is not the key type the report names".to_string(),
            Ok(_) => match verify_vek_validity_period_at(bytes, self.now)
                .and_then(|()| verify_vek_endorses(bytes, chip_id, reported, processor_gen))
            {
                Ok(()) => return Some(bytes.to_vec()),
                Err(e) => e.to_string(),
            },
        };
        log::warn!("inline snp.vek is not the report's VEK ({why}); not used");
        None
    }

    /// The raw bytes under a label, unchecked; callers bind them themselves.
    #[cfg_attr(not(feature = "snp"), allow(dead_code))]
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
        // The key binds the generation and the window; the VEK's own
        // extensions bind the chip identifier and the reported TCB.
        #[cfg(feature = "snp")]
        if let Some(bytes) = self.entry("snp.vek") {
            if self.bound("snp.vek", &key, bytes).is_some() {
                if let Some(v) = self.bound_vek(false, chip_id, reported_tcb, processor_gen) {
                    return Ok(v);
                }
            }
        }
        #[cfg(not(feature = "snp"))]
        let _ = key;
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

    /// The appraisal's evaluation time (section 14): one clock for every
    /// window, whatever clock the provider keeps for its own serving.
    fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

#[cfg(all(test, feature = "snp"))]
mod tests {
    use super::*;
    use crate::collateral::HeldCollateral;
    use crate::profile::CmwRecord;
    use std::collections::BTreeMap;

    const VLEK: &[u8] = include_bytes!("../../test_data/snp/test-vlek.der");
    const VCEK_GENOA: &[u8] = include_bytes!("../../test_data/snp/live-vcek-genoa.der");
    /// The TCB and chip of the report the Genoa VCEK endorses.
    const GENOA_TCB: SnpTcb = SnpTcb {
        bootloader: 10,
        tee: 0,
        snp: 27,
        microcode: 27,
        fmc: None,
    };
    /// The TCB the Milan VLEK certifies.
    const VLEK_TCB: SnpTcb = SnpTcb {
        bootloader: 4,
        tee: 0,
        snp: 24,
        microcode: 217,
        fmc: None,
    };

    fn genoa_chip() -> [u8; 64] {
        let report = include_bytes!("../../test_data/snp/live-report-v5-genoa.bin");
        report[0x1A0..0x1E0].try_into().unwrap()
    }

    fn endorsements(vek: &[u8]) -> CmwCollection {
        CmwCollection {
            collection_type: Some("tag:confidential.ai,2026:cvm-endorsements#1".into()),
            entries: BTreeMap::from([(
                "snp.vek".to_string(),
                CmwEntry::Record(CmwRecord::new(
                    "application/pkix-cert",
                    vek.to_vec(),
                    Some(2),
                )),
            )]),
        }
    }

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().into()
    }

    #[tokio::test]
    async fn an_inline_vcek_is_used_only_for_its_chip_and_tcb() {
        let held = HeldCollateral::new();
        let e = endorsements(VCEK_GENOA);
        let inline = InlineCollateral::new(Some(&e), &held, None, at("2026-09-22T00:00:00Z"));
        let chip = genoa_chip();
        let got = inline
            .get_snp_vcek(ProcessorGeneration::Genoa, &chip, &GENOA_TCB)
            .await
            .expect("the report's own VCEK is used");
        assert_eq!(got, VCEK_GENOA);
        // Another TCB or another chip: ignored, and the empty provider has none.
        let other_tcb = SnpTcb {
            microcode: 26,
            ..GENOA_TCB
        };
        let mut other_chip = chip;
        other_chip[0] ^= 1;
        for (chip, tcb) in [(chip, other_tcb), (other_chip, GENOA_TCB)] {
            let err = inline
                .get_snp_vcek(ProcessorGeneration::Genoa, &chip, &tcb)
                .await
                .expect_err("an inline VCEK that does not name this report is not used");
            assert_eq!(
                err.refusal_code(),
                Some(crate::error::RefusalCode::CollateralUnavailable),
                "{err}"
            );
        }
    }

    #[test]
    fn an_inline_vlek_is_used_only_for_its_tcb() {
        let held = HeldCollateral::new();
        let e = endorsements(VLEK);
        let inline = InlineCollateral::new(Some(&e), &held, None, at("2025-06-01T00:00:00Z"));
        let chip = [0u8; 64];
        assert_eq!(
            inline.inline_vlek(&chip, &VLEK_TCB, ProcessorGeneration::Milan),
            Some(VLEK.to_vec())
        );
        let other = SnpTcb {
            snp: 23,
            ..VLEK_TCB
        };
        assert_eq!(
            inline.inline_vlek(&chip, &other, ProcessorGeneration::Milan),
            None
        );
        // Outside its window it is ignored as well.
        let late = InlineCollateral::new(Some(&e), &held, None, at("2026-01-01T00:00:00Z"));
        assert_eq!(
            late.inline_vlek(&chip, &VLEK_TCB, ProcessorGeneration::Milan),
            None
        );
        // A VLEK never stands in for a VCEK.
        let vcek_e = endorsements(VCEK_GENOA);
        let vcek = InlineCollateral::new(Some(&vcek_e), &held, None, at("2026-09-22T00:00:00Z"));
        assert_eq!(
            vcek.inline_vlek(&genoa_chip(), &GENOA_TCB, ProcessorGeneration::Genoa),
            None
        );
    }
}
