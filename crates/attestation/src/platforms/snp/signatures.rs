//! The AMD certificate and report signature checks.
//!
//! These replace sev 7's `crypto_nossl` feature, which pinned p384 0.13 and
//! with it crypto-bigint 0.5 (RUSTSEC-2026-0387). They make the same checks
//! as sev 7.1.0 (`certs/snp/cert_nossl.rs`, `certs/snp/chain.rs`,
//! `certs/snp/ca/mod.rs` and the `Verifiable` impls in
//! `firmware/guest/types/snp.rs`), and additionally require the report's
//! SIGNATURE_ALGO to be ECDSA P-384 with SHA-384 and the signature's R and S
//! to be zero beyond their 48 significant bytes. The differential test in
//! this module holds them to sev's recorded verdicts.

use der::oid::db::rfc5912::ID_RSASSA_PSS;
use der::referenced::OwnedToRef;
use der::{Decode, Encode};
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::signature::Verifier as _;
use sha2::Digest;
use x509_cert::Certificate;

/// SIGNATURE_ALGO for ECDSA P-384 with SHA-384, the only one the SNP ABI
/// defines, and where the report carries it.
const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
const SIG_ALGO_OFFSET: usize = 0x34;

/// The report bytes the signature covers.
const SIGNED_LEN: usize = 0x2A0;

/// Bytes in each little-endian R and S field of the report signature, and the
/// significant ones for P-384.
const SIG_COMPONENT_LEN: usize = 72;
const P384_SCALAR_LEN: usize = 48;

/// Where R and S sit in the report: right after the signed bytes.
const SIG_R_OFFSET: usize = SIGNED_LEN;
const SIG_S_OFFSET: usize = SIGNED_LEN + SIG_COMPONENT_LEN;

/// Parse a DER certificate.
pub(crate) fn parse_cert(der: &[u8]) -> Result<Certificate, String> {
    Certificate::from_der(der).map_err(|e| format!("invalid DER: {e}"))
}

/// `signer`'s RSA key made `signee`'s RSASSA-PSS SHA-384 signature over its
/// TBSCertificate. The PSS salt is the hash length (48 bytes).
pub(crate) fn verify_cert_signature(
    signer: &Certificate,
    signee: &Certificate,
) -> Result<(), String> {
    if signee.signature_algorithm.oid != ID_RSASSA_PSS {
        return Err(format!(
            "unsupported signature algorithm: {}",
            signee.signature_algorithm.oid
        ));
    }
    let spki = signer
        .tbs_certificate
        .subject_public_key_info
        .owned_to_ref();
    let key =
        rsa::RsaPublicKey::try_from(spki).map_err(|e| format!("invalid RSA public key: {e}"))?;
    let message = signee
        .tbs_certificate
        .to_der()
        .map_err(|e| format!("failed to encode tbs_certificate as DER: {e}"))?;
    verify_rsa_pss_sha384(key, &message, signee.signature.raw_bytes())
        .map_err(|e| format!("signer certificate does not RSA sign signee certificate: {e}"))
}

/// AMD's RSASSA-PSS, for certificates and the Milan CRL: SHA-384 as hash and
/// MGF1 hash, salt the hash length (48 bytes).
pub(crate) fn verify_rsa_pss_sha384(
    key: rsa::RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let signature = rsa::pss::Signature::try_from(signature)
        .map_err(|e| format!("invalid RSA signature: {e}"))?;
    rsa::pss::VerifyingKey::<sha2::Sha384>::new(key)
        .verify(message, &signature)
        .map_err(|e| e.to_string())
}

/// ARK signs itself, ARK signs the ASK (or ASVK), and that signs the VEK.
pub(crate) fn verify_chain(
    ark: &Certificate,
    ask: &Certificate,
    vek: &Certificate,
) -> Result<(), String> {
    verify_cert_signature(ark, ark)?;
    verify_cert_signature(ark, ask)?;
    verify_cert_signature(ask, vek)
}

/// `vek`'s P-384 key signed the raw `report`: ECDSA with SHA-384 over its
/// first 0x2A0 bytes, exactly as the firmware signed them.
pub(crate) fn verify_report(vek: &Certificate, report: &[u8]) -> Result<(), String> {
    if report.len() < SIG_S_OFFSET + SIG_COMPONENT_LEN {
        return Err(format!("report is {} bytes, too short", report.len()));
    }
    let field = |at: usize| -> &[u8; SIG_COMPONENT_LEN] {
        report[at..at + SIG_COMPONENT_LEN]
            .try_into()
            .expect("length checked above")
    };
    let sig_algo = u32::from_le_bytes(
        report[SIG_ALGO_OFFSET..SIG_ALGO_OFFSET + 4]
            .try_into()
            .expect("length checked above"),
    );
    if sig_algo != SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(format!("unsupported report signature algorithm {sig_algo}"));
    }
    let r = scalar_be(field(SIG_R_OFFSET)).map_err(|e| format!("signature R: {e}"))?;
    let s = scalar_be(field(SIG_S_OFFSET)).map_err(|e| format!("signature S: {e}"))?;
    let signature = p384::ecdsa::Signature::from_scalars(r, s)
        .map_err(|e| format!("failed to deserialize signature from scalars: {e}"))?;
    let digest = sha2::Sha384::digest(&report[..SIGNED_LEN]);
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
        vek.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
    .map_err(|e| format!("failed to deserialize public key from sec1 bytes: {e}"))?;
    key.verify_prehash(&digest, &signature)
        .map_err(|e| format!("VEK does not sign the attestation report: {e}"))
}

/// A report signature component, 72 little-endian bytes, as the 48
/// big-endian bytes of a P-384 scalar. The high 24 bytes must be zero.
fn scalar_be(le: &[u8; SIG_COMPONENT_LEN]) -> Result<p384::FieldBytes, String> {
    if le[P384_SCALAR_LEN..].iter().any(|&b| b != 0) {
        return Err("non-zero bytes beyond the P-384 scalar".into());
    }
    let mut be = [0u8; P384_SCALAR_LEN];
    for (out, b) in be.iter_mut().zip(le[..P384_SCALAR_LEN].iter().rev()) {
        *out = *b;
    }
    Ok(be.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::snp::sev_vectors::{
        vectors, Input, INTEL_ROOT, LIVE_VCEK_GENOA, TEST_REPORT, TEST_VCEK,
    };
    use std::collections::BTreeMap;

    const R: usize = SIG_R_OFFSET;
    const S: usize = SIG_S_OFFSET;

    const VERDICTS: &str = include_str!("../../../test_data/snp/sev-7.1.0-verdicts.json");

    /// The vectors where this verifier is deliberately stricter than sev:
    /// non-zero bytes above the 48 significant bytes of R or S, which sev
    /// drops unread.
    fn stricter_than_sev(id: &str) -> bool {
        id.starts_with("report-tamper/")
            && ["/r-pad-48", "/r-pad-71", "/s-pad-48"]
                .iter()
                .any(|t| id.ends_with(t))
    }

    fn verdict(input: &Input) -> Result<(), String> {
        match input {
            Input::Chain(a, b, c) => {
                verify_chain(&parse_cert(a)?, &parse_cert(b)?, &parse_cert(c)?)
            }
            Input::Pair(a, b) => verify_cert_signature(&parse_cert(a)?, &parse_cert(b)?),
            Input::Report(r, k) => {
                // sev parsed the report before checking it.
                crate::platforms::snp::verify::parse_report(r).map_err(|e| e.to_string())?;
                verify_report(&parse_cert(k)?, r)
            }
        }
    }

    /// Every vector gets sev 7.1.0's verdict, except the documented
    /// stricter ones, which sev accepts and this rejects.
    #[test]
    fn agrees_with_sev_7_1_0() {
        let recorded: BTreeMap<String, bool> = serde_json::from_str(VERDICTS).unwrap();
        let vectors = vectors();
        assert_eq!(
            vectors.len(),
            recorded.len(),
            "the vector set changed; re-record sev's verdicts"
        );
        let mut accepted = 0;
        let mut stricter = 0;
        for v in &vectors {
            let sev = *recorded
                .get(&v.id)
                .unwrap_or_else(|| panic!("no recorded verdict for {}", v.id));
            let ours = verdict(&v.input).is_ok();
            if stricter_than_sev(&v.id) {
                assert!(sev && !ours, "{}: sev {sev}, ours {ours}", v.id);
                stricter += 1;
            } else {
                assert_eq!(ours, sev, "{}", v.id);
            }
            accepted += usize::from(ours);
        }
        // Guard against a vector set that trivially agrees.
        assert_eq!(stricter, 12);
        assert_eq!(accepted, 32);
    }

    #[test]
    fn a_report_is_signed_by_its_vcek_only() {
        let vcek = parse_cert(TEST_VCEK).unwrap();
        verify_report(&vcek, TEST_REPORT).unwrap();
        let other = parse_cert(LIVE_VCEK_GENOA).unwrap();
        let err = verify_report(&other, TEST_REPORT).unwrap_err();
        assert!(err.contains("does not sign"), "{err}");
    }

    #[test]
    fn an_unsupported_signature_algorithm_is_refused_before_the_signature() {
        let mut bytes = TEST_REPORT.to_vec();
        bytes[SIG_ALGO_OFFSET] = 2;
        let err = verify_report(&parse_cert(TEST_VCEK).unwrap(), &bytes).unwrap_err();
        assert!(
            err.contains("unsupported report signature algorithm 2"),
            "{err}"
        );
    }

    #[test]
    fn padding_above_the_scalar_is_refused() {
        let (scalar, last) = (P384_SCALAR_LEN, SIG_COMPONENT_LEN - 1);
        for at in [R + scalar, R + last, S + scalar, S + last] {
            let mut bytes = TEST_REPORT.to_vec();
            bytes[at] = 1;
            let err = verify_report(&parse_cert(TEST_VCEK).unwrap(), &bytes).unwrap_err();
            assert!(err.contains("beyond the P-384 scalar"), "{at:#x}: {err}");
        }
    }

    #[test]
    fn out_of_range_scalars_are_refused() {
        for (name, range, v) in [
            ("R zero", R..R + SIG_COMPONENT_LEN, 0),
            ("S zero", S..S + SIG_COMPONENT_LEN, 0),
            ("R above n", R..R + P384_SCALAR_LEN, 0xff),
        ] {
            let mut bytes = TEST_REPORT.to_vec();
            bytes[range].iter_mut().for_each(|b| *b = v);
            let err = verify_report(&parse_cert(TEST_VCEK).unwrap(), &bytes).unwrap_err();
            assert!(err.contains("from scalars"), "{name}: {err}");
        }
    }

    #[test]
    fn a_vek_on_another_curve_is_refused() {
        let ark = parse_cert(crate::platforms::snp::certs::get_ark(
            crate::types::ProcessorGeneration::Milan,
        ))
        .unwrap();
        let p256 = parse_cert(INTEL_ROOT).unwrap();
        for vek in [ark, p256] {
            let err = verify_report(&vek, TEST_REPORT).unwrap_err();
            assert!(err.contains("sec1"), "{err}");
        }
    }

    #[test]
    fn a_certificate_not_signed_with_rsa_pss_is_refused() {
        // The Intel root is ECDSA-signed.
        let intel = parse_cert(INTEL_ROOT).unwrap();
        let err = verify_cert_signature(&intel, &intel).unwrap_err();
        assert!(err.contains("unsupported signature algorithm"), "{err}");
    }

    #[test]
    fn a_non_rsa_signer_is_refused() {
        let intel = parse_cert(INTEL_ROOT).unwrap();
        let vcek = parse_cert(TEST_VCEK).unwrap();
        let err = verify_cert_signature(&intel, &vcek).unwrap_err();
        assert!(err.contains("invalid RSA public key"), "{err}");
    }
}
