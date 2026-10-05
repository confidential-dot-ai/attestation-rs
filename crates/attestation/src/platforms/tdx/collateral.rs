//! Caller-supplied TDX DCAP collateral, verified rather than trusted.
//!
//! For verifiers that cannot reach Intel PCS themselves (the browser: PCS
//! sends no CORS headers), the caller fetches the collateral and hands over
//! the bytes. Nothing here trusts the transport: TCB Info and QE Identity are
//! signature-checked by the core against their issuer chains (always
//! supplied, so that check is never skipped), both CRLs are signature-checked
//! against the quote's verified PCK chain, and every item must be current at
//! the verification time `at`. Certificate validity (the PCK chain and both
//! issuer chains) is checked by the core against the current time, not `at`.

use async_trait::async_trait;
use x509_parser::time::ASN1Time;

use super::dcap;
use crate::collateral::TdxCollateralProvider;
use crate::error::{AttestationError, Result};

fn reject(msg: impl std::fmt::Display) -> AttestationError {
    AttestationError::CertChainError(msg.to_string())
}

/// Intel PCS v4 collateral for one TDX quote, as fetched by the caller.
///
/// The JSON bodies must be passed verbatim: Intel's signatures cover the raw
/// `tcbInfo` / `enclaveIdentity` bytes.
#[derive(Debug, Clone)]
pub struct StaticTdxCollateral {
    /// Body of `GET /tdx/certification/v4/tcb?fmspc=<fmspc>`.
    pub tcb_info: Vec<u8>,
    /// PEM `TCB-Info-Issuer-Chain` response header, URL-decoded.
    pub tcb_info_issuer_chain: Vec<u8>,
    /// Body of `GET /tdx/certification/v4/qe/identity`.
    pub qe_identity: Vec<u8>,
    /// PEM `SGX-Enclave-Identity-Issuer-Chain` response header, URL-decoded.
    pub qe_identity_issuer_chain: Vec<u8>,
    /// PCK CRL (DER or PEM) of the CA that issued the quote's PCK certificate:
    /// `GET /sgx/certification/v4/pckcrl?ca=platform|processor`.
    pub pck_crl: Vec<u8>,
    /// Intel SGX Root CA CRL (DER or PEM).
    pub root_ca_crl: Vec<u8>,
    /// Verification time, Unix seconds. TCB Info, QE Identity and both CRLs
    /// must be current at it; certificates are checked against the current
    /// time regardless.
    pub at: i64,
}

/// The validity fields shared by the signed TCB Info and QE Identity bodies.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedBody {
    id: String,
    issue_date: String,
    next_update: String,
    #[serde(default)]
    fmspc: Option<String>,
}

impl StaticTdxCollateral {
    fn at(&self) -> Result<ASN1Time> {
        ASN1Time::from_timestamp(self.at)
            .map_err(|e| reject(format!("verification time {}: {e}", self.at)))
    }

    /// Parse the signed body under `key` and require its id and validity
    /// window. The signature itself is checked by the core afterwards.
    fn check_body(&self, json: &[u8], key: &str, want_id: &str) -> Result<SignedBody> {
        let mut envelope: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(json).map_err(|e| reject(format!("{key} JSON: {e}")))?;
        let body = envelope
            .remove(key)
            .ok_or_else(|| reject(format!("{key} JSON has no {key:?} object")))?;
        let body: SignedBody =
            serde_json::from_value(body).map_err(|e| reject(format!("{key} fields: {e}")))?;
        if body.id != want_id {
            return Err(reject(format!(
                "{key} id is {:?}, want {want_id:?}",
                body.id
            )));
        }
        let issued = timestamp(&body.issue_date, key, "issueDate")?;
        let next = timestamp(&body.next_update, key, "nextUpdate")?;
        if issued > self.at {
            return Err(reject(format!(
                "{key} issueDate {} is after the verification time",
                body.issue_date
            )));
        }
        if next < self.at {
            return Err(reject(format!(
                "{key} is stale: nextUpdate {} is before the verification time",
                body.next_update
            )));
        }
        Ok(body)
    }
}

fn timestamp(value: &str, key: &str, field: &str) -> Result<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|t| t.timestamp())
        .map_err(|e| reject(format!("{key} {field} {value:?}: {e}")))
}

#[async_trait]
impl TdxCollateralProvider for StaticTdxCollateral {
    async fn get_tcb_info(&self, fmspc: &str) -> Result<Vec<u8>> {
        let body = self.check_body(&self.tcb_info, "tcbInfo", "TDX")?;
        // Intel signs TCB Info per FMSPC; a genuine one for another platform
        // must not grade this one.
        match body.fmspc.as_deref() {
            Some(f) if f.eq_ignore_ascii_case(fmspc) => Ok(self.tcb_info.clone()),
            other => Err(reject(format!(
                "tcbInfo is for FMSPC {other:?}, the quote's PCK certificate is {fmspc}"
            ))),
        }
    }

    async fn get_qe_identity(&self) -> Result<Vec<u8>> {
        Err(reject("the SGX QE Identity is not part of TDX collateral"))
    }

    async fn get_td_qe_identity(&self) -> Result<Vec<u8>> {
        self.check_body(&self.qe_identity, "enclaveIdentity", "TD_QE")?;
        Ok(self.qe_identity.clone())
    }

    async fn get_root_ca_crl(&self) -> Result<Vec<u8>> {
        Ok(self.root_ca_crl.clone())
    }

    async fn get_pck_crl(&self, _ca: &str) -> Result<Vec<u8>> {
        Ok(self.pck_crl.clone())
    }

    async fn get_tcb_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.tcb_info_issuer_chain.clone()))
    }

    async fn get_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.qe_identity_issuer_chain.clone()))
    }

    async fn get_td_qe_identity_signing_chain(&self) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.qe_identity_issuer_chain.clone()))
    }

    // The core calls this after verify_dcap_chain has verified the same PCK
    // chain to the pinned Intel root, so its CA certificates are authentic
    // issuers to check the CRLs against.
    async fn check_pck_revocation(&self, pck_cert_chain_pem: &[u8]) -> Result<()> {
        let certs = dcap::parse_pem_to_der(pck_cert_chain_pem)?;
        if certs.len() < 3 {
            return Err(reject(format!(
                "PCK chain has {} certificates, want 3",
                certs.len()
            )));
        }
        let at = self.at()?;
        let pck_crl = dcap::verify_crl(&self.pck_crl, &certs[1], at, "PCK CRL")?;
        let root_crl = dcap::verify_crl(&self.root_ca_crl, &certs[2], at, "Root CA CRL")?;
        dcap::check_cert_revocation_from_der(&certs, &pck_crl)?;
        dcap::check_intermediate_ca_revocation_from_der(&certs, &root_crl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::tdx::evidence::TdxEvidence;
    use crate::platforms::tdx::verify::verify_evidence;
    use crate::types::{TdxTcbStatus, VerifyParams};
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    // A c8s TDX node's quote (FMSPC 00a06d080000) and the Intel PCS v4
    // collateral fetched for it on 2026-10-05. Every item is current between
    // 2026-10-05T14:40:24Z and 2026-11-04T14:22:24Z.
    const QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_00a06d080000.dat");
    const TCB_INFO: &[u8] =
        include_bytes!("../../../test_data/collateral/2026-10-05/tcb_info_00a06d080000.json");
    const TCB_CHAIN: &[u8] =
        include_bytes!("../../../test_data/collateral/2026-10-05/tcb_signing_chain.pem");
    const QE_IDENTITY: &[u8] =
        include_bytes!("../../../test_data/collateral/2026-10-05/td_qe_identity.json");
    const QE_CHAIN: &[u8] =
        include_bytes!("../../../test_data/collateral/2026-10-05/qe_identity_signing_chain.pem");
    const PCK_CRL: &[u8] =
        include_bytes!("../../../test_data/collateral/2026-10-05/pck_crl_platform.der");
    const ROOT_CRL: &[u8] =
        include_bytes!("../../../test_data/collateral/2026-10-05/root_ca_crl.der");

    /// 2026-10-06T00:00:00Z.
    const AT: i64 = 1_791_244_800;

    fn collateral() -> StaticTdxCollateral {
        StaticTdxCollateral {
            tcb_info: TCB_INFO.to_vec(),
            tcb_info_issuer_chain: TCB_CHAIN.to_vec(),
            qe_identity: QE_IDENTITY.to_vec(),
            qe_identity_issuer_chain: QE_CHAIN.to_vec(),
            pck_crl: PCK_CRL.to_vec(),
            root_ca_crl: ROOT_CRL.to_vec(),
            at: AT,
        }
    }

    async fn verify(c: StaticTdxCollateral) -> Result<crate::types::VerificationResult> {
        let evidence = TdxEvidence {
            quote: BASE64.encode(QUOTE),
            cc_eventlog: None,
        };
        verify_evidence(&evidence, &VerifyParams::default(), Some(&c)).await
    }

    async fn rejection(c: StaticTdxCollateral) -> String {
        match verify(c).await {
            Ok(r) => panic!("collateral accepted: {:?}", r.tcb_status),
            Err(e) => e.to_string(),
        }
    }

    fn replace(haystack: &[u8], from: &str, to: &str) -> Vec<u8> {
        let s = std::str::from_utf8(haystack).unwrap();
        assert!(s.contains(from), "fixture lacks {from:?}");
        s.replacen(from, to, 1).into_bytes()
    }

    #[tokio::test]
    async fn current_collateral_grades_the_quote() {
        let r = verify(collateral()).await.expect("verify");
        assert!(r.collateral_verified);
        let status = r.tcb_status.expect("tcb_status");
        assert_eq!(status.fmspc, "00a06d080000");
        assert_eq!(status.tcb_status, TdxTcbStatus::UpToDate);
    }

    #[tokio::test]
    async fn stale_collateral_is_rejected() {
        let err = rejection(StaticTdxCollateral {
            at: AT + 60 * 86_400,
            ..collateral()
        })
        .await;
        assert!(err.contains("stale"), "{err}");
    }

    #[tokio::test]
    async fn collateral_issued_after_the_verification_time_is_rejected() {
        let err = rejection(StaticTdxCollateral {
            at: AT - 30 * 86_400,
            ..collateral()
        })
        .await;
        assert!(err.contains("after the verification time"), "{err}");
    }

    #[tokio::test]
    async fn tcb_info_for_another_fmspc_is_rejected() {
        let err = rejection(StaticTdxCollateral {
            tcb_info: replace(TCB_INFO, "00a06d080000", "50806f000000"),
            ..collateral()
        })
        .await;
        assert!(err.contains("FMSPC"), "{err}");
    }

    #[tokio::test]
    async fn tampered_tcb_info_fails_its_signature() {
        let err = rejection(StaticTdxCollateral {
            tcb_info: replace(TCB_INFO, "\"OutOfDate\"", "\"UpToDate\""),
            ..collateral()
        })
        .await;
        assert!(err.contains("TCB Info signature"), "{err}");
    }

    #[tokio::test]
    async fn qe_identity_in_place_of_tcb_info_is_rejected() {
        let err = rejection(StaticTdxCollateral {
            tcb_info: QE_IDENTITY.to_vec(),
            ..collateral()
        })
        .await;
        assert!(err.contains("tcbInfo"), "{err}");
    }

    #[tokio::test]
    async fn tampered_pck_crl_fails_its_signature() {
        let mut crl = PCK_CRL.to_vec();
        let last = crl.len() - 1;
        crl[last] ^= 1;
        let err = rejection(StaticTdxCollateral {
            pck_crl: crl,
            ..collateral()
        })
        .await;
        assert!(err.contains("PCK CRL signature"), "{err}");
    }

    #[tokio::test]
    async fn a_crl_from_another_issuer_is_rejected() {
        let err = rejection(StaticTdxCollateral {
            pck_crl: ROOT_CRL.to_vec(),
            ..collateral()
        })
        .await;
        assert!(err.contains("PCK CRL is issued by"), "{err}");
    }
}
