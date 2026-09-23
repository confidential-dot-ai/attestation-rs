//! DCAP (Data Center Attestation Primitives) chain verification for TDX quotes.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::Decode;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use scroll::Pread;
use sha2::{Digest, Sha256};
use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::der_parser::der::parse_der_sequence;
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

use crate::error::{AttestationError, Result};
use crate::types::{DcapVerificationStatus, TdxTcbStatus};

use super::verify::{QuoteVersion, QUOTE_HEADER_SIZE, REPORT_BODY_SIZE};

/// Intel SGX Root CA public key (ECDSA P-256, uncompressed SEC1).
///
/// This is the trust anchor for all DCAP attestation. Every legitimate
/// PCK certificate chain terminates at this root key.
const INTEL_SGX_ROOT_CA_PUB_DER: &[u8] = &[
    0x04, // SEC1 uncompressed point prefix
    // X coordinate (32 bytes)
    0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda, 0x10,
    0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25, 0xf5,
    // Y coordinate (32 bytes)
    0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a, 0xac,
    0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73, 0x94,
];

/// QE (Quoting Enclave) report body size in bytes.
const QE_REPORT_BODY_SIZE: usize = 384;

/// Cert data type: ECDSA signature aux data (contains QE report + nested cert chain).
const CERT_DATA_TYPE_ECDSA_SIG_AUX: u16 = 6;

/// Cert data type: PCK certificate chain (PEM-encoded leaf + intermediate + root).
const CERT_DATA_TYPE_PCK_CHAIN: u16 = 5;

/// Parsed auth data from a TDX quote (v4+).
pub struct QuoteAuthData<'a> {
    /// ECDSA P-256 attestation public key (64 bytes: X || Y)
    pub attestation_pub_key: &'a [u8],
    /// QE report body (384 bytes)
    pub qe_report_body: &'a [u8],
    /// QE report ECDSA P-256 signature (64 bytes)
    pub qe_report_signature: &'a [u8],
    /// QE authentication data (variable length)
    pub qe_auth_data: &'a [u8],
    /// PEM-encoded PCK certificate chain
    pub pck_cert_chain_pem: &'a [u8],
}

/// Parse the full auth data section from a TDX quote.
///
/// Layout for v4+:
/// ```text
/// [body_end + 0]:  sig_data_len (4 bytes LE)
/// [body_end + 4]:  ECDSA signature (64 bytes) — already verified by verify_quote_signature
/// [body_end + 68]: attestation public key (64 bytes)
/// [body_end + 132]: cert_data_type (2 bytes LE) — must be 6 (EcdsaSigAuxData)
/// [body_end + 134]: cert_data_size (4 bytes LE)
/// [body_end + 138]: cert_data contents:
///     [+0]:   QE report body (384 bytes)
///     [+384]: QE report signature (64 bytes)
///     [+448]: qe_auth_data_size (2 bytes LE)
///     [+450]: qe_auth_data (variable)
///     [+450+auth_size]: nested cert_data_type (2 bytes LE) — must be 5 (PckCertChain)
///     [+452+auth_size]: nested cert_data_size (4 bytes LE)
///     [+456+auth_size]: PEM cert chain data
/// ```
pub fn parse_auth_data<'a>(quote_bytes: &'a [u8], body_end: usize) -> Result<QuoteAuthData<'a>> {
    let err = |msg: String| AttestationError::QuoteParseFailed(msg);

    // The declared auth data length bounds everything below and must fit the
    // quote; bytes after it are ignored, as Intel's QVL ignores them.
    let sig_data_len = quote_bytes
        .pread_with::<u32>(body_end, scroll::LE)
        .map_err(|e| err(format!("sig_data_len: {e}")))? as usize;
    let auth_end = (body_end + 4)
        .checked_add(sig_data_len)
        .filter(|end| *end <= quote_bytes.len())
        .ok_or_else(|| {
            err(format!(
                "sig_data_len {sig_data_len} exceeds the {} bytes after the body",
                quote_bytes.len().saturating_sub(body_end + 4)
            ))
        })?;
    let quote_bytes = &quote_bytes[..auth_end];

    // Skip past sig_data_len(4) + signature(64)
    let attest_key_offset = body_end + 4 + 64;
    if quote_bytes.len() < attest_key_offset + 64 {
        return Err(err("quote too short for attestation key".into()));
    }
    let attestation_pub_key = &quote_bytes[attest_key_offset..attest_key_offset + 64];

    // Read outer cert_data header (type 6)
    let cert_type_offset = attest_key_offset + 64;
    if quote_bytes.len() < cert_type_offset + 6 {
        return Err(err("quote too short for cert data header".into()));
    }
    let cert_data_type = quote_bytes
        .pread_with::<u16>(cert_type_offset, scroll::LE)
        .map_err(|e| err(format!("cert_data_type: {e}")))?;
    if cert_data_type != CERT_DATA_TYPE_ECDSA_SIG_AUX {
        return Err(err(format!(
            "expected cert_data_type {CERT_DATA_TYPE_ECDSA_SIG_AUX} (EcdsaSigAuxData), got {cert_data_type}"
        )));
    }
    let cert_data_size = quote_bytes
        .pread_with::<u32>(cert_type_offset + 2, scroll::LE)
        .map_err(|e| err(format!("cert_data_size: {e}")))? as usize;

    let cert_data_start = cert_type_offset + 6;
    if quote_bytes.len() < cert_data_start + cert_data_size {
        return Err(err(format!(
            "quote too short for cert data: need {} bytes at offset {}, have {}",
            cert_data_size,
            cert_data_start,
            quote_bytes.len()
        )));
    }
    let cert_data = &quote_bytes[cert_data_start..cert_data_start + cert_data_size];

    // Parse QE report body (384 bytes)
    if cert_data.len() < QE_REPORT_BODY_SIZE + 64 {
        return Err(err("cert data too short for QE report + signature".into()));
    }
    let qe_report_body = &cert_data[..QE_REPORT_BODY_SIZE];
    let qe_report_signature = &cert_data[QE_REPORT_BODY_SIZE..QE_REPORT_BODY_SIZE + 64];

    // Parse QE auth data
    let auth_size_offset = QE_REPORT_BODY_SIZE + 64;
    if cert_data.len() < auth_size_offset + 2 {
        return Err(err("cert data too short for qe_auth_data_size".into()));
    }
    let qe_auth_data_size = cert_data
        .pread_with::<u16>(auth_size_offset, scroll::LE)
        .map_err(|e| err(format!("qe_auth_data_size: {e}")))? as usize;

    let qe_auth_data_start = auth_size_offset + 2;
    if cert_data.len() < qe_auth_data_start + qe_auth_data_size {
        return Err(err("cert data too short for qe_auth_data".into()));
    }
    let qe_auth_data = &cert_data[qe_auth_data_start..qe_auth_data_start + qe_auth_data_size];

    // Parse nested cert data (type 5 = PckCertChain)
    let nested_offset = qe_auth_data_start + qe_auth_data_size;
    if cert_data.len() < nested_offset + 6 {
        return Err(err("cert data too short for nested cert data header".into()));
    }
    let nested_type = cert_data
        .pread_with::<u16>(nested_offset, scroll::LE)
        .map_err(|e| err(format!("nested cert_data_type: {e}")))?;
    if nested_type != CERT_DATA_TYPE_PCK_CHAIN {
        return Err(err(format!(
            "expected nested cert_data_type {CERT_DATA_TYPE_PCK_CHAIN} (PckCertChain), got {nested_type}"
        )));
    }
    let nested_size = cert_data
        .pread_with::<u32>(nested_offset + 2, scroll::LE)
        .map_err(|e| err(format!("nested cert_data_size: {e}")))? as usize;

    let pem_start = nested_offset + 6;
    if cert_data.len() < pem_start + nested_size {
        return Err(err("cert data too short for PEM cert chain".into()));
    }
    let pck_cert_chain_pem = &cert_data[pem_start..pem_start + nested_size];

    Ok(QuoteAuthData {
        attestation_pub_key,
        qe_report_body,
        qe_report_signature,
        qe_auth_data,
        pck_cert_chain_pem,
    })
}

/// Verify that the attestation key is bound into the QE report.
///
/// The QE report's user_report_data must equal:
///   SHA-256(attestation_pub_key || qe_auth_data) || 32 zero bytes
pub fn verify_qe_report_binding(auth_data: &QuoteAuthData) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(auth_data.attestation_pub_key);
    hasher.update(auth_data.qe_auth_data);
    let digest = hasher.finalize();

    // user_report_data is at offset 320 in the QE report body (64 bytes)
    let user_report_data = &auth_data.qe_report_body[320..384];

    // First 32 bytes must match the hash
    if !crate::utils::constant_time_eq(&user_report_data[..32], &digest) {
        return Err(AttestationError::SignatureVerificationFailed(
            "QE report binding failed: SHA-256(attest_key || auth_data) != report_data[0:32]"
                .into(),
        ));
    }

    // Last 32 bytes must be zero
    if user_report_data[32..64].iter().any(|&b| b != 0) {
        return Err(AttestationError::SignatureVerificationFailed(
            "QE report binding failed: report_data[32:64] is not zero-padded".into(),
        ));
    }

    Ok(())
}

/// Verify the QE report signature using the PCK leaf certificate's public key.
///
/// The PCK leaf cert signs the 384-byte QE report body with ECDSA P-256.
pub fn verify_qe_report_signature(
    auth_data: &QuoteAuthData,
    pck_pub_key: &VerifyingKey,
) -> Result<()> {
    let sig = Signature::from_slice(auth_data.qe_report_signature).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("QE report signature parse: {e}"))
    })?;

    pck_pub_key
        .verify(auth_data.qe_report_body, &sig)
        .map_err(|e| {
            AttestationError::SignatureVerificationFailed(format!(
                "QE report signature verification: {e}"
            ))
        })
}

/// Validate the PCK certificate chain and return the PCK leaf's public key.
///
/// Expects a PEM blob with 3 certificates:
///   [0] PCK leaf cert
///   [1] PCK Platform CA (intermediate)
///   [2] Intel SGX Root CA
///
/// Validates:
///   - Root CA public key matches hardcoded Intel trust anchor
///   - Root CA self-signs correctly
///   - Intermediate is signed by Root CA
///   - Leaf is signed by Intermediate
///
/// Returns the PCK leaf's ECDSA P-256 public key for QE report signature verification.
#[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
pub fn verify_pck_cert_chain(pem_data: &[u8]) -> Result<VerifyingKey> {
    verify_pck_cert_chain_at(pem_data, chrono::Utc::now())
}

/// [`verify_pck_cert_chain`] with validity judged at `now`.
pub fn verify_pck_cert_chain_at(
    pem_data: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<VerifyingKey> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| {
        AttestationError::CertChainError(format!("PEM data is not valid UTF-8: {e}"))
    })?;

    // Split PEM into individual DER-encoded certificates
    let der_certs = split_pem_to_der(pem_str)?;

    if der_certs.len() < 3 {
        return Err(AttestationError::CertChainError(format!(
            "expected at least 3 certificates in PCK chain, got {}",
            der_certs.len()
        )));
    }

    // Parse certificates to extract TBS data and public keys
    let leaf_cert = parse_x509_cert(&der_certs[0], "PCK leaf")?;
    let intermediate_cert = parse_x509_cert(&der_certs[1], "PCK Platform CA")?;
    let root_cert = parse_x509_cert(&der_certs[2], "Intel SGX Root CA")?;

    // Step 1: Verify Root CA public key matches hardcoded Intel key
    let root_pub_key = extract_p256_pub_key(&root_cert.pub_key_bytes, "Root CA")?;
    let intel_root_key = VerifyingKey::from_sec1_bytes(INTEL_SGX_ROOT_CA_PUB_DER)
        .map_err(|e| AttestationError::CertChainError(format!("Intel Root CA key parse: {e}")))?;

    if root_pub_key.to_encoded_point(false) != intel_root_key.to_encoded_point(false) {
        return Err(AttestationError::CertChainError(
            "Root CA public key does not match Intel SGX Root CA".into(),
        ));
    }

    // Step 2: Verify Root CA self-signature
    verify_cert_signature(&root_cert, &root_pub_key, "Root CA self-signature")?;

    // Step 3: Verify Intermediate is signed by Root CA
    let intermediate_pub_key =
        extract_p256_pub_key(&intermediate_cert.pub_key_bytes, "Intermediate CA")?;
    verify_cert_signature(&intermediate_cert, &root_pub_key, "Intermediate cert")?;

    // Step 4: Verify Leaf is signed by Intermediate
    verify_cert_signature(&leaf_cert, &intermediate_pub_key, "PCK leaf cert")?;

    // Step 5: Verify certificate validity periods
    for (der, label) in [
        (&der_certs[0], "PCK leaf"),
        (&der_certs[1], "PCK Platform CA"),
        (&der_certs[2], "Intel SGX Root CA"),
    ] {
        verify_cert_validity_period(der, label, now)?;
    }

    extract_p256_pub_key(&leaf_cert.pub_key_bytes, "PCK leaf")
}

/// Validate a 2-cert signing chain (Signing Cert → Root CA) and return
/// the signing certificate's ECDSA P-256 public key.
///
/// Used for verifying Intel's ECDSA signatures on TCB Info and QE Identity
/// JSON. The signing chain is obtained from Intel PCS response headers
/// (`TCB-Info-Issuer-Chain` / `SGX-Enclave-Identity-Issuer-Chain`).
///
/// Validates, as Intel's QVL does (`TCBSigningChain::verify`):
///   - exactly two certificates: the TCB signing certificate, then the root
///   - Root CA public key matches hardcoded Intel trust anchor, and its CN
///     names the SGX Root CA
///   - Root CA self-signs correctly
///   - the signing certificate's CN names the SGX TCB Signing role, its
///     issuer is the root's subject, and the root signs it
///   - the Root CA CRL (signed by the pinned root, inside its window) does
///     not revoke the signing certificate
///   - Both certificates are within their validity periods
#[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
pub fn verify_signing_cert_chain(pem_data: &[u8], root_ca_crl_der: &[u8]) -> Result<VerifyingKey> {
    verify_signing_cert_chain_at(pem_data, root_ca_crl_der, chrono::Utc::now())
}

/// [`verify_signing_cert_chain`] with validity judged at `now`.
pub fn verify_signing_cert_chain_at(
    pem_data: &[u8],
    root_ca_crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<VerifyingKey> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| {
        AttestationError::CollateralInvalid(format!("signing chain PEM not UTF-8: {e}"))
    })?;

    let der_certs = split_pem_to_der(pem_str)?;

    if der_certs.len() != 2 {
        return Err(AttestationError::CollateralInvalid(format!(
            "expected the TCB signing certificate and the root in the signing chain, got {} certificates",
            der_certs.len()
        )));
    }

    // The role checks: a certificate the root signed for another purpose
    // (a PCK CA) must not sign TCB Info or QE Identity.
    let (_, signing_x509) = X509Certificate::from_der(&der_certs[0])
        .map_err(|e| AttestationError::CollateralInvalid(format!("TCB Signing parse: {e}")))?;
    let (_, root_x509) = X509Certificate::from_der(&der_certs[1]).map_err(|e| {
        AttestationError::CollateralInvalid(format!("signing chain root parse: {e}"))
    })?;
    if !common_name_contains(signing_x509.subject(), "SGX TCB Signing") {
        return Err(AttestationError::CollateralInvalid(format!(
            "signing certificate {} is not an Intel SGX TCB Signing certificate",
            signing_x509.subject()
        )));
    }
    if !common_name_contains(root_x509.subject(), "SGX Root CA") {
        return Err(AttestationError::CollateralInvalid(format!(
            "signing chain root {} is not the Intel SGX Root CA",
            root_x509.subject()
        )));
    }
    if signing_x509.issuer().as_raw() != root_x509.subject().as_raw() {
        return Err(AttestationError::CollateralInvalid(
            "the TCB signing certificate's issuer is not the root's subject".into(),
        ));
    }

    let signing_cert = parse_x509_cert(&der_certs[0], "TCB Signing")?;
    let root_cert = parse_x509_cert(&der_certs[1], "Intel SGX Root CA")?;

    // Verify Root CA public key matches hardcoded Intel key
    let root_pub_key = extract_p256_pub_key(&root_cert.pub_key_bytes, "Root CA")?;
    let intel_root_key = VerifyingKey::from_sec1_bytes(INTEL_SGX_ROOT_CA_PUB_DER)
        .map_err(|e| AttestationError::CertChainError(format!("Intel Root CA key parse: {e}")))?;

    if root_pub_key.to_encoded_point(false) != intel_root_key.to_encoded_point(false) {
        return Err(AttestationError::CollateralInvalid(
            "signing chain Root CA public key does not match Intel SGX Root CA".into(),
        ));
    }

    // Verify Root CA self-signature
    verify_cert_signature(
        &root_cert,
        &root_pub_key,
        "signing chain Root CA self-signature",
    )?;

    // Verify signing cert is signed by Root CA
    verify_cert_signature(&signing_cert, &root_pub_key, "TCB Signing cert")?;

    // Verify validity periods
    for (der, label) in [
        (&der_certs[0], "TCB Signing"),
        (&der_certs[1], "Intel SGX Root CA"),
    ] {
        verify_cert_validity_period(der, label, now)?;
    }

    // The Root CA CRL, signed by the pinned root, must not revoke the signer.
    let crl_der = normalize_crl_to_der(root_ca_crl_der)?;
    let (_, crl) = CertificateRevocationList::from_der(&crl_der)
        .map_err(|e| AttestationError::CollateralInvalid(format!("Root CA CRL parse: {e}")))?;
    verify_intel_crl(&crl, &root_pub_key, now, "Intel SGX Root CA")?;
    let serial = signing_x509.raw_serial();
    if crl
        .iter_revoked_certificates()
        .any(|r| r.raw_serial() == serial)
    {
        return Err(AttestationError::Revoked(
            "the TCB signing certificate is revoked by the Root CA CRL".into(),
        ));
    }

    extract_p256_pub_key(&signing_cert.pub_key_bytes, "TCB Signing")
}

/// Whether any CN attribute of `name` contains `phrase` (QVL's
/// `commonNameContains`).
fn common_name_contains(name: &x509_parser::x509::X509Name<'_>, phrase: &str) -> bool {
    name.iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .any(|cn| cn.contains(phrase))
}

/// Minimal X.509 certificate data needed for chain verification.
struct CertData {
    /// Raw TBS (To-Be-Signed) certificate bytes (the signed content)
    tbs_bytes: Vec<u8>,
    /// ECDSA signature on the TBS data
    signature_bytes: Vec<u8>,
    /// Subject public key bytes (SEC1 encoded)
    pub_key_bytes: Vec<u8>,
}

/// Parse a DER-encoded X.509 certificate and extract the fields we need.
fn parse_x509_cert(der: &[u8], label: &str) -> Result<CertData> {
    // X.509 Certificate structure (DER/ASN.1):
    //   SEQUENCE {
    //     tbsCertificate      TBSCertificate,        -- SEQUENCE
    //     signatureAlgorithm  AlgorithmIdentifier,   -- SEQUENCE
    //     signatureValue      BIT STRING
    //   }
    //
    // We need:
    //   - The raw bytes of tbsCertificate (for signature verification)
    //   - The signatureValue (the actual ECDSA signature)
    //   - The subjectPublicKeyInfo from tbsCertificate

    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| AttestationError::CertChainError(format!("{label} cert DER parse: {e}")))?;

    // Extract TBS bytes: re-encode the TBS certificate to DER
    let tbs_bytes = der::Encode::to_der(&cert.tbs_certificate)
        .map_err(|e| AttestationError::CertChainError(format!("{label} TBS DER encode: {e}")))?;

    // Extract signature bytes (strip leading zero byte if present for ASN.1 BIT STRING)
    let sig_bits = cert.signature.raw_bytes();
    let signature_bytes = sig_bits.to_vec();

    // Extract subject public key bytes
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pub_key_raw = spki.subject_public_key.raw_bytes();
    let pub_key_bytes = pub_key_raw.to_vec();

    Ok(CertData {
        tbs_bytes,
        signature_bytes,
        pub_key_bytes,
    })
}

/// Extract a P-256 verifying key from SEC1-encoded public key bytes.
fn extract_p256_pub_key(pub_key_bytes: &[u8], label: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_sec1_bytes(pub_key_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("{label} public key parse: {e}")))
}

/// Verify a certificate's signature using the issuer's public key.
fn verify_cert_signature(cert: &CertData, issuer_key: &VerifyingKey, label: &str) -> Result<()> {
    // The signature in X.509 is DER-encoded (ASN.1 SEQUENCE of two INTEGERs)
    let sig = Signature::from_der(&cert.signature_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("{label} signature parse: {e}")))?;

    issuer_key.verify(&cert.tbs_bytes, &sig).map_err(|e| {
        AttestationError::CertChainError(format!("{label} signature verification: {e}"))
    })
}

/// Verify a certificate's validity period (NotBefore/NotAfter) at `now`.
fn verify_cert_validity_period(
    der: &[u8],
    label: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
        AttestationError::CertChainError(format!("{label} x509 parse for validity: {e}"))
    })?;

    let validity = cert.validity();
    let now = asn1_time(now)?;

    if now < validity.not_before {
        return Err(AttestationError::CertChainError(format!(
            "{} certificate is not yet valid (notBefore: {})",
            label, validity.not_before
        )));
    }
    if now > validity.not_after {
        return Err(AttestationError::CertChainError(format!(
            "{} certificate has expired (notAfter: {})",
            label, validity.not_after
        )));
    }

    Ok(())
}

/// Parse a PEM-encoded certificate chain into individual DER-encoded blobs.
///
/// Use this to preparse PEM data once, then pass the result to `_from_der`
/// variants of functions like [`extract_fmspc_from_pck_der`],
/// [`determine_ca_type_from_der`], etc.
pub fn parse_pem_to_der(pem_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pem_str = std::str::from_utf8(pem_data)
        .map_err(|e| AttestationError::CertChainError(format!("PEM not UTF-8: {e}")))?;
    split_pem_to_der(pem_str)
}

/// Split a PEM string into individual DER-encoded certificate blobs.
fn split_pem_to_der(pem_str: &str) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;

    for line in pem_str.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            current.clear();
        } else if line.contains("END CERTIFICATE") {
            in_cert = false;
            let der = BASE64
                .decode(current.trim())
                .map_err(|e| AttestationError::CertChainError(format!("PEM base64 decode: {e}")))?;
            certs.push(der);
        } else if in_cert {
            current.push_str(line.trim());
        }
    }

    if certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "PEM data contains no certificate blocks".into(),
        ));
    }

    Ok(certs)
}

/// Compute where the quote body ends (i.e., where auth data begins).
pub fn compute_body_end(quote_bytes: &[u8], quote_version: QuoteVersion) -> Result<usize> {
    match quote_version {
        QuoteVersion::V4 => Ok(QUOTE_HEADER_SIZE + REPORT_BODY_SIZE),
        QuoteVersion::V5Tdx10 | QuoteVersion::V5Tdx15 => {
            let body_size = quote_bytes
                .pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
                .map_err(|e| AttestationError::QuoteParseFailed(format!("v5 body size: {e}")))?
                as usize;
            Ok(QUOTE_HEADER_SIZE + 6 + body_size)
        }
    }
}

/// Run the full DCAP chain verification on a TDX quote.
///
/// This is a convenience function that runs all Phase 1 DCAP checks:
/// 1. Parse auth data from the quote
/// 2. Validate PCK certificate chain to Intel Root CA
/// 3. Verify QE report signature with PCK leaf key
/// 4. Verify QE report binding (attestation key bound into QE report)
/// 5. Check PCK certificate against CRL (if provided)
///
/// `pck_crl_der`: optional DER-encoded CRL from Intel PCS. When provided,
/// the PCK leaf certificate is checked for revocation.
pub fn verify_dcap_chain(
    quote_bytes: &[u8],
    quote_version: QuoteVersion,
    pck_crl_der: Option<&[u8]>,
) -> Result<()> {
    verify_dcap_chain_at(quote_bytes, quote_version, pck_crl_der, chrono::Utc::now())
}

/// [`verify_dcap_chain`] with certificate validity judged at `now`.
pub fn verify_dcap_chain_at(
    quote_bytes: &[u8],
    quote_version: QuoteVersion,
    pck_crl_der: Option<&[u8]>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let body_end = compute_body_end(quote_bytes, quote_version)?;
    let auth = parse_auth_data(quote_bytes, body_end)?;
    let pck_pub_key = verify_pck_cert_chain_at(auth.pck_cert_chain_pem, now)?;
    verify_qe_report_signature(&auth, &pck_pub_key)?;
    verify_qe_report_binding(&auth)?;

    if let Some(crl_der) = pck_crl_der {
        check_cert_revocation(auth.pck_cert_chain_pem, crl_der)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 2: TCB status evaluation, FMSPC extraction, CRL checking
// ---------------------------------------------------------------------------

/// SGX Extensions OID: 1.2.840.113741.1.13.1
const SGX_EXTENSIONS_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];

/// FMSPC OID: 1.2.840.113741.1.13.1.4
const FMSPC_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];
/// PPID OID: 1.2.840.113741.1.13.1.1 (16-byte Platform Provisioning ID).
const PPID_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 1];

/// The 16-byte PPID from the PCK leaf certificate's SGX extension, the
/// platform identity the profile reports as `cvm_identity.ppid`.
pub fn extract_ppid_from_pck(pem_data: &[u8]) -> Result<[u8; 16]> {
    let der_certs = parse_pem_to_der(pem_data)?;
    let leaf = der_certs.first().ok_or_else(|| {
        AttestationError::CertChainError("no certificates found in PEM data".into())
    })?;
    let (_, cert) = X509Certificate::from_der(leaf)
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf x509 parse: {e}")))?;
    let sgx_ext_oid = x509_parser::oid_registry::Oid::from(SGX_EXTENSIONS_OID).map_err(|e| {
        AttestationError::CertChainError(format!("invalid SGX_EXTENSIONS_OID: {e:?}"))
    })?;
    let ppid_oid = x509_parser::oid_registry::Oid::from(PPID_OID)
        .map_err(|e| AttestationError::CertChainError(format!("invalid PPID_OID: {e:?}")))?;
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid == sgx_ext_oid)
        .ok_or_else(|| {
            AttestationError::CertChainError(
                "SGX extensions OID not found in PCK certificate".into(),
            )
        })?;
    let value = extract_sgx_extension_octets(ext.value, &ppid_oid, "PPID")?;
    <[u8; 16]>::try_from(value.as_slice()).map_err(|_| {
        AttestationError::CertChainError(format!("PPID is {} bytes, expected 16", value.len()))
    })
}

/// PCE-ID OID: 1.2.840.113741.1.13.1.3 (2-byte Provisioning Certification
/// Enclave identifier, which a TCB Info's `pceId` must equal).
const PCE_ID_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 3];

/// The 2-byte PCE-ID from the PCK leaf certificate's SGX extension.
pub fn extract_pce_id_from_der(der_certs: &[Vec<u8>]) -> Result<[u8; 2]> {
    let leaf = der_certs.first().ok_or_else(|| {
        AttestationError::CertChainError("no certificates found in PEM data".into())
    })?;
    let (_, cert) = X509Certificate::from_der(leaf)
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf x509 parse: {e}")))?;
    let sgx_ext_oid = x509_parser::oid_registry::Oid::from(SGX_EXTENSIONS_OID).map_err(|e| {
        AttestationError::CertChainError(format!("invalid SGX_EXTENSIONS_OID: {e:?}"))
    })?;
    let pce_id_oid = x509_parser::oid_registry::Oid::from(PCE_ID_OID)
        .map_err(|e| AttestationError::CertChainError(format!("invalid PCE_ID_OID: {e:?}")))?;
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid == sgx_ext_oid)
        .ok_or_else(|| {
            AttestationError::CertChainError(
                "SGX extensions OID not found in PCK certificate".into(),
            )
        })?;
    let value = extract_sgx_extension_octets(ext.value, &pce_id_oid, "PCE-ID")?;
    <[u8; 2]>::try_from(value.as_slice()).map_err(|_| {
        AttestationError::CertChainError(format!("PCE-ID is {} bytes, expected 2", value.len()))
    })
}

/// The OCTET STRING value stored under `wanted` in an SGX extension: an ASN.1
/// SEQUENCE of SEQUENCE { OID, value } entries.
fn extract_sgx_extension_octets(
    data: &[u8],
    wanted: &x509_parser::oid_registry::Oid<'_>,
    name: &str,
) -> Result<Vec<u8>> {
    use x509_parser::der_parser::ber::{parse_ber, BerObjectContent};
    let (_, outer) = parse_ber(data)
        .map_err(|e| AttestationError::CertChainError(format!("SGX extension parse: {e}")))?;
    let BerObjectContent::Sequence(items) = &outer.content else {
        return Err(AttestationError::CertChainError(
            "SGX extension is not a SEQUENCE".into(),
        ));
    };
    for item in items {
        let BerObjectContent::Sequence(inner) = &item.content else {
            continue;
        };
        if inner.len() < 2 {
            continue;
        }
        let BerObjectContent::OID(oid) = &inner[0].content else {
            continue;
        };
        if oid != wanted {
            continue;
        }
        return match &inner[1].content {
            BerObjectContent::OctetString(v) => Ok(v.to_vec()),
            _ => Err(AttestationError::CertChainError(format!(
                "{name} OID found but value is not an OCTET STRING"
            ))),
        };
    }
    Err(AttestationError::CertChainError(format!(
        "{name} OID not found in SGX extension"
    )))
}

/// Extract the FMSPC (Family-Model-Stepping-Platform-CustomSKU) from a PCK leaf cert.
///
/// The FMSPC is a 6-byte value embedded in the SGX extensions of the PCK certificate,
/// under OID 1.2.840.113741.1.13.1.4. It identifies the platform for TCB Info lookup.
pub fn extract_fmspc_from_pck(pem_data: &[u8]) -> Result<String> {
    let der_certs = parse_pem_to_der(pem_data)?;
    extract_fmspc_from_pck_der(&der_certs)
}

/// Extract the FMSPC from pre-parsed DER certificate chain.
/// See [`extract_fmspc_from_pck`] for details.
pub fn extract_fmspc_from_pck_der(der_certs: &[Vec<u8>]) -> Result<String> {
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found in PEM data".into(),
        ));
    }

    let (_, cert) = X509Certificate::from_der(&der_certs[0])
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf x509 parse: {e}")))?;

    // Find the SGX extensions OID in the cert extensions
    let sgx_ext_oid = x509_parser::oid_registry::Oid::from(SGX_EXTENSIONS_OID).map_err(|e| {
        AttestationError::CertChainError(format!("invalid SGX_EXTENSIONS_OID: {e:?}"))
    })?;

    for ext in cert.extensions() {
        if ext.oid == sgx_ext_oid {
            // The SGX extension value is an ASN.1 SEQUENCE of SEQUENCE { OID, value }
            return extract_fmspc_from_sgx_extension(ext.value);
        }
    }

    Err(AttestationError::CertChainError(
        "SGX extensions OID not found in PCK certificate".into(),
    ))
}

/// Parse the SGX extension ASN.1 blob and extract the FMSPC value.
fn extract_fmspc_from_sgx_extension(data: &[u8]) -> Result<String> {
    let fmspc_oid = x509_parser::oid_registry::Oid::from(FMSPC_OID)
        .map_err(|e| AttestationError::CertChainError(format!("invalid FMSPC_OID: {e:?}")))?;

    // Parse outer SEQUENCE
    let (_, seq) = parse_der_sequence(data)
        .map_err(|e| AttestationError::CertChainError(format!("SGX extension parse: {e}")))?;

    // Each element is a SEQUENCE { OID, value }
    for item in seq.ref_iter() {
        if let BerObjectContent::Sequence(ref inner) = item.content {
            if inner.len() >= 2 {
                if let BerObjectContent::OID(ref oid) = inner[0].content {
                    if *oid == fmspc_oid {
                        // The value is an OCTET STRING containing 6 bytes
                        if let BerObjectContent::OctetString(fmspc_bytes) = &inner[1].content {
                            if fmspc_bytes.len() == 6 {
                                return Ok(hex::encode(fmspc_bytes));
                            }
                            return Err(AttestationError::CertChainError(format!(
                                "FMSPC found but has unexpected length {} (expected 6)",
                                fmspc_bytes.len()
                            )));
                        }
                        return Err(AttestationError::CertChainError(
                            "FMSPC OID found but value is not an OCTET STRING".into(),
                        ));
                    }
                }
            }
        }
    }

    Err(AttestationError::CertChainError(
        "FMSPC OID not found in SGX extension".into(),
    ))
}

/// Intel PCS v4 TCB Info JSON signed envelope.
///
/// Uses `RawValue` for the `tcbInfo` field to preserve the exact bytes
/// Intel signed — `serde_json` without `preserve_order` uses `BTreeMap`
/// which reorders keys alphabetically, breaking signature verification.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoSignedEnvelope<'a> {
    #[serde(borrow)]
    tcb_info: &'a serde_json::value::RawValue,
    signature: String,
}

/// The TDX TCB Info as PCS v4 publishes it (`tcbInfo`, version 3, id `TDX`).
/// Unknown members are ignored, as Intel's QVL ignores them.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoJson {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    fmspc: String,
    pce_id: String,
    tcb_type: u32,
    tcb_evaluation_data_number: u32,
    tdx_module: Option<TdxModuleJson>,
    tdx_module_identities: Option<Vec<TdxModuleIdentityJson>>,
    tcb_levels: Vec<TcbLevelJson>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleJson {
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleIdentityJson {
    id: String,
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
    tcb_levels: Vec<TdxModuleLevelJson>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleLevelJson {
    tcb: IsvSvnJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct IsvSvnJson {
    isvsvn: u16,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelJson {
    tcb: TcbComponentsJson,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbComponentsJson {
    sgxtcbcomponents: Vec<SvnComponent>,
    pcesvn: u16,
    tdxtcbcomponents: Option<Vec<SvnComponent>>,
}

#[derive(Debug, serde::Deserialize)]
struct SvnComponent {
    svn: u8,
}

/// The TDX module's expected identity: `tcbInfo.tdxModule`, or one entry of
/// `tdxModuleIdentities` with the levels its SVN is judged by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxModuleIdentity {
    pub id: String,
    pub mrsigner: [u8; 48],
    pub attributes: [u8; 8],
    /// Descending by ISVSVN.
    pub levels: Vec<TdxModuleLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxModuleLevel {
    pub isvsvn: u16,
    pub status: String,
    pub advisory_ids: Vec<String>,
}

/// One platform TCB level of a TDX TCB Info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxTcbLevel {
    pub sgx: [u8; 16],
    pub pcesvn: u16,
    pub tdx: [u8; 16],
    pub status: String,
    pub advisory_ids: Vec<String>,
}

/// A TDX TCB Info whose signature, signing chain and shape were verified.
#[derive(Debug, Clone)]
pub struct TdxTcbInfo {
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    pub next_update: chrono::DateTime<chrono::Utc>,
    pub tcb_evaluation_data_number: u32,
    pub tdx_module: TdxModuleIdentity,
    pub tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    /// Descending by (SGX components, PCESVN, TDX components), as QVL orders
    /// them; two equal levels make the TCB Info invalid.
    pub levels: Vec<TdxTcbLevel>,
}

/// The platform values a TCB Info is bound to and judged against, from the
/// PCK leaf's SGX extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckTcb {
    pub fmspc: [u8; 6],
    pub pce_id: [u8; 2],
    pub cpusvn: [u8; 16],
    pub pcesvn: u16,
}

/// The QE Identity TCB level the quoting enclave's ISVSVN selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeTcbLevel {
    pub status: TdxTcbStatus,
    pub advisory_ids: Vec<String>,
    pub next_update: chrono::DateTime<chrono::Utc>,
}

/// The evaluated TCB: the converged status and the advisories of the
/// platform level, the QE level and the TDX module level, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxTcbVerdict {
    pub tcb_status: TdxTcbStatus,
    pub advisory_ids: Vec<String>,
}

fn collateral_err(msg: impl Into<String>) -> AttestationError {
    AttestationError::CollateralInvalid(msg.into())
}

fn fixed_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| collateral_err(format!("{what}: {e}")))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| collateral_err(format!("{what} is {} bytes, expected {N}", bytes.len())))
}

fn rfc3339(s: &str, what: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| collateral_err(format!("{what} {s:?}: {e}")))
}

fn sixteen(components: &[SvnComponent], what: &str) -> Result<[u8; 16]> {
    if components.len() != 16 {
        return Err(collateral_err(format!(
            "{what} has {} entries, expected 16",
            components.len()
        )));
    }
    let mut out = [0u8; 16];
    for (o, c) in out.iter_mut().zip(components) {
        *o = c.svn;
    }
    Ok(out)
}

fn module_identity(
    id: String,
    mrsigner: &str,
    attributes: &str,
    attributes_mask: &str,
    levels: Vec<TdxModuleLevelJson>,
) -> Result<TdxModuleIdentity> {
    // The mask is parsed for its shape; QVL does not apply it either.
    fixed_hex::<8>(attributes_mask, "TDX module attributesMask")?;
    let mut levels = levels
        .into_iter()
        .map(|l| {
            rfc3339(&l.tcb_date, "TDX module tcbDate")?;
            Ok(TdxModuleLevel {
                isvsvn: l.tcb.isvsvn,
                status: l.tcb_status,
                advisory_ids: l.advisory_ids,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    levels.sort_by_key(|l| std::cmp::Reverse(l.isvsvn));
    if levels.windows(2).any(|w| w[0].isvsvn == w[1].isvsvn) {
        return Err(collateral_err(format!(
            "TDX module identity {id} repeats a TCB level"
        )));
    }
    Ok(TdxModuleIdentity {
        mrsigner: fixed_hex(mrsigner, "TDX module mrsigner")?,
        attributes: fixed_hex(attributes, "TDX module attributes")?,
        id,
        levels,
    })
}

/// Parse and check the inner `tcbInfo` object of a TDX TCB Info, the rules
/// of Intel's QVL `TcbInfo::parse` for version 3 and id `TDX`.
pub fn parse_tdx_tcb_info(tcb_info: &str) -> Result<TdxTcbInfo> {
    let raw: TcbInfoJson = serde_json::from_str(tcb_info)
        .map_err(|e| collateral_err(format!("TCB Info parse: {e}")))?;
    if raw.version != 3 {
        return Err(collateral_err(format!(
            "TCB Info version {} is not 3",
            raw.version
        )));
    }
    if raw.id != "TDX" {
        return Err(collateral_err(format!(
            "TCB Info id {:?} is not TDX",
            raw.id
        )));
    }
    if raw.tcb_type != 0 {
        return Err(collateral_err(format!(
            "TCB Info tcbType {} is not 0",
            raw.tcb_type
        )));
    }
    rfc3339(&raw.issue_date, "TCB Info issueDate")?;
    let next_update = rfc3339(&raw.next_update, "TCB Info nextUpdate")?;
    let module = raw
        .tdx_module
        .ok_or_else(|| collateral_err("TCB Info for TDX carries no tdxModule"))?;
    let tdx_module = module_identity(
        "tdxModule".into(),
        &module.mrsigner,
        &module.attributes,
        &module.attributes_mask,
        Vec::new(),
    )?;
    let tdx_module_identities = match raw.tdx_module_identities {
        None => None,
        Some(ids) if ids.is_empty() => {
            return Err(collateral_err("TCB Info tdxModuleIdentities is empty"))
        }
        Some(ids) => Some(
            ids.into_iter()
                .map(|m| {
                    if m.tcb_levels.is_empty() {
                        return Err(collateral_err(format!(
                            "TDX module identity {} has no TCB levels",
                            m.id
                        )));
                    }
                    module_identity(
                        m.id,
                        &m.mrsigner,
                        &m.attributes,
                        &m.attributes_mask,
                        m.tcb_levels,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    };
    if raw.tcb_levels.is_empty() {
        return Err(collateral_err("TCB Info has no TCB levels"));
    }
    let mut levels = raw
        .tcb_levels
        .into_iter()
        .map(|l| {
            rfc3339(&l.tcb_date, "TCB level tcbDate")?;
            let tdx = l
                .tcb
                .tdxtcbcomponents
                .ok_or_else(|| collateral_err("a TDX TCB level carries no tdxtcbcomponents"))?;
            Ok(TdxTcbLevel {
                sgx: sixteen(&l.tcb.sgxtcbcomponents, "sgxtcbcomponents")?,
                pcesvn: l.tcb.pcesvn,
                tdx: sixteen(&tdx, "tdxtcbcomponents")?,
                status: l.tcb_status,
                advisory_ids: l.advisory_ids,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let key = |l: &TdxTcbLevel| (l.sgx, l.pcesvn, l.tdx);
    levels.sort_by_key(|l| std::cmp::Reverse(key(l)));
    if levels.windows(2).any(|w| key(&w[0]) == key(&w[1])) {
        return Err(collateral_err("TCB Info repeats a TCB level"));
    }
    Ok(TdxTcbInfo {
        fmspc: fixed_hex(&raw.fmspc, "TCB Info fmspc")?,
        pce_id: fixed_hex(&raw.pce_id, "TCB Info pceId")?,
        next_update,
        tcb_evaluation_data_number: raw.tcb_evaluation_data_number,
        tdx_module,
        tdx_module_identities,
        levels,
    })
}

/// The PCK leaf's 16 TCB component SVNs (OID 1.2.840.113741.1.13.1.2.1 to .16)
/// and PCESVN (.2.17).
fn extract_pck_tcb_components_from_der(der_certs: &[Vec<u8>]) -> Result<([u8; 16], u16)> {
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found".into(),
        ));
    }

    let (_, cert) = X509Certificate::from_der(&der_certs[0])
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf x509 parse: {e}")))?;

    let sgx_ext_oid = x509_parser::oid_registry::Oid::from(SGX_EXTENSIONS_OID).map_err(|e| {
        AttestationError::CertChainError(format!("invalid SGX_EXTENSIONS_OID: {e:?}"))
    })?;
    let tcb_oid = x509_parser::oid_registry::Oid::from(&[1, 2, 840, 113741, 1, 13, 1, 2][..])
        .map_err(|e| AttestationError::CertChainError(format!("invalid TCB OID: {e:?}")))?;

    for ext in cert.extensions() {
        if ext.oid == sgx_ext_oid {
            let (_, seq) = parse_der_sequence(ext.value).map_err(|e| {
                AttestationError::CertChainError(format!("SGX extension parse: {e}"))
            })?;

            for item in seq.ref_iter() {
                if let BerObjectContent::Sequence(ref inner) = item.content {
                    if inner.len() >= 2 {
                        if let BerObjectContent::OID(ref oid) = inner[0].content {
                            if *oid == tcb_oid {
                                return parse_tcb_sequence(&inner[1]);
                            }
                        }
                    }
                }
            }
        }
    }

    Err(AttestationError::CertChainError(
        "TCB OID not found in SGX extension".into(),
    ))
}

/// Parse TCB SEQUENCE containing 16 component SVNs and PCESVN.
fn parse_tcb_sequence(obj: &x509_parser::der_parser::ber::BerObject) -> Result<([u8; 16], u16)> {
    let items = match &obj.content {
        BerObjectContent::Sequence(items) => items,
        _ => {
            return Err(AttestationError::CertChainError(
                "TCB value is not a SEQUENCE".into(),
            ))
        }
    };

    let mut compsvn = [0u8; 16];
    let mut pcesvn: u16 = 0;

    for item in items {
        if let BerObjectContent::Sequence(ref inner) = item.content {
            if inner.len() >= 2 {
                if let BerObjectContent::OID(ref oid) = inner[0].content {
                    let oid_str = oid.to_id_string();
                    // Component SVNs: 1.2.840.113741.1.13.1.2.{1..16}
                    // PCESVN: 1.2.840.113741.1.13.1.2.17
                    if let Some(suffix) = oid_str.strip_prefix("1.2.840.113741.1.13.1.2.") {
                        if let Ok(idx) = suffix.parse::<usize>() {
                            let val = extract_integer_value(&inner[1])?;
                            let range = |what: &str| {
                                AttestationError::CertChainError(format!(
                                    "PCK {what} {val} is out of range"
                                ))
                            };
                            if (1..=16).contains(&idx) {
                                compsvn[idx - 1] =
                                    u8::try_from(val).map_err(|_| range("TCB component"))?;
                            } else if idx == 17 {
                                pcesvn = u16::try_from(val).map_err(|_| range("PCESVN"))?;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((compsvn, pcesvn))
}

/// Extract an integer value from a BER object (handles INTEGER and OCTET STRING).
fn extract_integer_value(obj: &x509_parser::der_parser::ber::BerObject) -> Result<u64> {
    match &obj.content {
        BerObjectContent::Integer(bytes) => {
            let mut val: u64 = 0;
            for &b in *bytes {
                val = (val << 8) | b as u64;
            }
            Ok(val)
        }
        BerObjectContent::OctetString(bytes) => {
            let mut val: u64 = 0;
            for &b in *bytes {
                val = (val << 8) | b as u64;
            }
            Ok(val)
        }
        _ => Err(AttestationError::CertChainError(
            "unexpected ASN.1 type in TCB extension (expected INTEGER or OCTET STRING)".into(),
        )),
    }
}

/// Verify a signed Intel PCS body: the signing chain (with the Root CA CRL)
/// and the ECDSA-P256 signature over the exact bytes of `member`, which
/// `RawValue` preserves without re-serialization.
fn verify_pcs_signature<'a>(
    raw: &'a serde_json::value::RawValue,
    signature_hex: &str,
    signing_certs_pem: &[u8],
    root_ca_crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
    what: &str,
) -> Result<&'a str> {
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| collateral_err(format!("{what} signature hex decode: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| collateral_err(format!("{what} signature parse: {e}")))?;
    let signing_key = verify_signing_cert_chain_at(signing_certs_pem, root_ca_crl_der, now)?;
    signing_key
        .verify(raw.get().as_bytes(), &signature)
        .map_err(|e| collateral_err(format!("{what} signature verification failed: {e}")))?;
    Ok(raw.get())
}

/// Verify a PCS v4 TDX TCB Info response (`{"tcbInfo": {...}, "signature"}`):
/// the signing chain to the pinned Intel root, the signing certificate's
/// role and revocation, the signature over the exact `tcbInfo` bytes, and the
/// shape rules of [`parse_tdx_tcb_info`].
pub fn verify_tdx_tcb_info_at(
    tcb_info_json: &[u8],
    signing_certs_pem: &[u8],
    root_ca_crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<TdxTcbInfo> {
    let envelope: TcbInfoSignedEnvelope<'_> = serde_json::from_slice(tcb_info_json)
        .map_err(|e| collateral_err(format!("TCB Info envelope parse: {e}")))?;
    let body = verify_pcs_signature(
        envelope.tcb_info,
        &envelope.signature,
        signing_certs_pem,
        root_ca_crl_der,
        now,
        "TCB Info",
    )?;
    parse_tdx_tcb_info(body)
}

/// The PCK leaf's FMSPC, PCE-ID, CPUSVN components and PCESVN.
pub fn pck_tcb_from_pem(pck_pem: &[u8]) -> Result<PckTcb> {
    let der_certs = parse_pem_to_der(pck_pem)?;
    let fmspc = extract_fmspc_from_pck_der(&der_certs)?;
    let fmspc = <[u8; 6]>::try_from(
        hex::decode(&fmspc)
            .map_err(|e| AttestationError::CertChainError(format!("FMSPC: {e}")))?
            .as_slice(),
    )
    .map_err(|_| AttestationError::CertChainError("FMSPC is not 6 bytes".into()))?;
    let (cpusvn, pcesvn) = extract_pck_tcb_components_from_der(&der_certs)?;
    Ok(PckTcb {
        fmspc,
        pce_id: extract_pce_id_from_der(&der_certs)?,
        cpusvn,
        pcesvn,
    })
}

/// QVL's `convergeTcbStatuses`: a component (TDX module or QE) that is
/// `OutOfDate` lowers the platform status, and one that is `Revoked` wins.
pub fn converge_tcb_statuses(platform: TdxTcbStatus, components: &[TdxTcbStatus]) -> TdxTcbStatus {
    use TdxTcbStatus as S;
    let mut status = platform;
    if components.contains(&S::OutOfDate) {
        status = match platform {
            S::UpToDate | S::SWHardeningNeeded => S::OutOfDate,
            S::ConfigurationNeeded | S::ConfigurationAndSWHardeningNeeded => {
                S::OutOfDateConfigurationNeeded
            }
            other => other,
        };
    }
    if components.contains(&S::Revoked) {
        status = S::Revoked;
    }
    status
}

/// A TCB status string restricted to the values a structure may carry.
fn status_in(s: &str, allowed: &[TdxTcbStatus], what: &str) -> Result<TdxTcbStatus> {
    let status = parse_tcb_status(s)
        .map_err(|_| collateral_err(format!("{what} status {s:?} is not recognized")))?;
    if !allowed.contains(&status) {
        return Err(collateral_err(format!(
            "{what} status {s:?} is not allowed there"
        )));
    }
    Ok(status)
}

/// Evaluate a TD quote's TCB against a verified TCB Info and the QE's level,
/// as Intel's QVL does (`QuoteVerifier::verify` 4.1.2.5.10 to 4.1.2.5.12 and
/// `tdxEvaluateTCB`):
///
/// 1. The TCB Info binds to the platform: its FMSPC and PCE-ID are the PCK
///    certificate's.
/// 2. The TDX module identity: `MRSIGNERSEAM` equals the expected signer, and
///    `SEAMATTRIBUTES` is zero and equal to the expected attributes, taken from
///    `tdxModule`, or when `TEE_TCB_SVN[1]` (the module's major version) is not
///    zero, from the `tdxModuleIdentities` entry `TDX_<major as two hex
///    digits>`, whose first level with `isvsvn <= TEE_TCB_SVN[0]` gives the
///    module's status.
/// 3. The platform level: the first, in descending order, whose SGX
///    components the PCK's meet, whose PCESVN the PCK's meets, and whose TDX
///    components `TEE_TCB_SVN` meets, from byte 2 when the major version is
///    not zero.
/// 4. The status converges with the module's and the QE's; the advisories are
///    the platform level's, then the QE level's, then the module level's.
pub fn evaluate_tdx_tcb(
    info: &TdxTcbInfo,
    body: &super::verify::TdxReportBody,
    pck: &PckTcb,
    qe: &QeTcbLevel,
) -> Result<TdxTcbVerdict> {
    use TdxTcbStatus as S;
    if info.fmspc != pck.fmspc {
        return Err(collateral_err(format!(
            "TCB Info is for FMSPC {}, the PCK certificate's is {}",
            hex::encode(info.fmspc),
            hex::encode(pck.fmspc)
        )));
    }
    if info.pce_id != pck.pce_id {
        return Err(collateral_err(format!(
            "TCB Info is for PCE-ID {}, the PCK certificate's is {}",
            hex::encode(info.pce_id),
            hex::encode(pck.pce_id)
        )));
    }

    let svn = &body.tee_tcb_svn;
    let major = svn[1];
    let (expected, module) = if major > 0 {
        let wanted = format!("TDX_{major:02X}");
        let identity = info
            .tdx_module_identities
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|m| m.id.eq_ignore_ascii_case(&wanted))
            .ok_or_else(|| {
                AttestationError::TcbMismatch(format!(
                    "TCB Info has no TDX module identity {wanted}"
                ))
            })?;
        let level = identity
            .levels
            .iter()
            .find(|l| u16::from(svn[0]) >= l.isvsvn)
            .ok_or_else(|| {
                AttestationError::TcbMismatch(format!(
                    "TDX module {wanted} SVN {} meets no TCB level",
                    svn[0]
                ))
            })?;
        let status = status_in(
            &level.status,
            &[S::UpToDate, S::OutOfDate, S::Revoked],
            "TDX module TCB level",
        )?;
        (identity, Some((status, level.advisory_ids.clone())))
    } else {
        (&info.tdx_module, None)
    };
    if body.mrsigner_seam != expected.mrsigner {
        return Err(AttestationError::TcbMismatch(
            "MRSIGNERSEAM is not the TDX module signer the TCB Info names".into(),
        ));
    }
    if body.seam_attributes.iter().any(|b| *b != 0) || body.seam_attributes != expected.attributes {
        return Err(AttestationError::TcbMismatch(
            "SEAMATTRIBUTES is not zero and equal to the TCB Info's TDX module attributes".into(),
        ));
    }

    let start = if major > 0 { 2 } else { 0 };
    let level = info
        .levels
        .iter()
        .find(|l| {
            pck.cpusvn
                .iter()
                .zip(l.sgx.iter())
                .all(|(have, want)| have >= want)
                && pck.pcesvn >= l.pcesvn
                && svn[start..]
                    .iter()
                    .zip(l.tdx[start..].iter())
                    .all(|(have, want)| have >= want)
        })
        .ok_or_else(|| {
            AttestationError::TcbMismatch("the TD quote's TCB matches no TCB level".into())
        })?;
    let platform = status_in(
        &level.status,
        &[
            S::UpToDate,
            S::SWHardeningNeeded,
            S::ConfigurationNeeded,
            S::ConfigurationAndSWHardeningNeeded,
            S::OutOfDate,
            S::OutOfDateConfigurationNeeded,
            S::Revoked,
        ],
        "TCB level",
    )?;

    let mut components = vec![qe.status];
    let mut advisory_ids = level.advisory_ids.clone();
    advisory_ids.extend(qe.advisory_ids.iter().cloned());
    if let Some((status, advisories)) = module {
        components.push(status);
        advisory_ids.extend(advisories);
    }
    Ok(TdxTcbVerdict {
        tcb_status: converge_tcb_statuses(platform, &components),
        advisory_ids,
    })
}

/// The TDX collateral checks of the pre-profile verify paths, over one
/// provider: TCB Info, QE Identity and the evaluation of [`evaluate_tdx_tcb`].
/// `collateral_expired` is true when either document's `nextUpdate` has passed.
pub fn evaluate_tdx_collateral_at(
    body: &super::verify::TdxReportBody,
    qe_report_body: &[u8],
    pck_pem: &[u8],
    tcb_info: (&[u8], &[u8]),
    qe_identity: (&[u8], &[u8]),
    root_ca_crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DcapVerificationStatus> {
    let info = verify_tdx_tcb_info_at(tcb_info.0, tcb_info.1, root_ca_crl_der, now)?;
    let qe = verify_qe_identity_at(
        qe_report_body,
        qe_identity.0,
        qe_identity.1,
        root_ca_crl_der,
        now,
    )?;
    let pck = pck_tcb_from_pem(pck_pem)?;
    let verdict = evaluate_tdx_tcb(&info, body, &pck, &qe)?;
    Ok(DcapVerificationStatus {
        tcb_status: verdict.tcb_status,
        fmspc: hex::encode(pck.fmspc),
        advisory_ids: verdict.advisory_ids,
        collateral_expired: info.next_update <= now || qe.next_update <= now,
    })
}

/// `now` as the type x509-parser compares validity against.
fn asn1_time(now: chrono::DateTime<chrono::Utc>) -> Result<x509_parser::time::ASN1Time> {
    x509_parser::time::ASN1Time::from_timestamp(now.timestamp())
        .map_err(|e| AttestationError::CertChainError(format!("evaluation time: {e}")))
}

/// Parse a TCB status string from Intel PCS into our enum.
fn parse_tcb_status(s: &str) -> Result<TdxTcbStatus> {
    match s {
        "UpToDate" => Ok(TdxTcbStatus::UpToDate),
        "SWHardeningNeeded" => Ok(TdxTcbStatus::SWHardeningNeeded),
        "ConfigurationNeeded" => Ok(TdxTcbStatus::ConfigurationNeeded),
        "ConfigurationAndSWHardeningNeeded" => Ok(TdxTcbStatus::ConfigurationAndSWHardeningNeeded),
        "OutOfDate" => Ok(TdxTcbStatus::OutOfDate),
        "OutOfDateConfigurationNeeded" => Ok(TdxTcbStatus::OutOfDateConfigurationNeeded),
        "Revoked" => Ok(TdxTcbStatus::Revoked),
        _ => Err(AttestationError::TcbMismatch(format!(
            "unknown TCB status: {s}"
        ))),
    }
}

/// Determine the CA type ("platform" or "processor") from the PCK issuer CN.
///
/// Intel PCK certificates are issued either by "Intel SGX PCK Platform CA"
/// or "Intel SGX PCK Processor CA". The CA type is needed to fetch the
/// correct CRL from Intel PCS.
pub fn determine_ca_type(pck_pem: &[u8]) -> Result<String> {
    let der_certs = parse_pem_to_der(pck_pem)?;
    determine_ca_type_from_der(&der_certs)
}

/// Determine the CA type from pre-parsed DER certificate chain.
/// See [`determine_ca_type`] for details.
pub fn determine_ca_type_from_der(der_certs: &[Vec<u8>]) -> Result<String> {
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found".into(),
        ));
    }
    let (_, cert) = X509Certificate::from_der(&der_certs[0])
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf x509 parse: {e}")))?;

    let issuer = format!("{}", cert.issuer());
    if issuer.contains("Platform") {
        Ok("platform".to_string())
    } else if issuer.contains("Processor") {
        Ok("processor".to_string())
    } else {
        Err(AttestationError::CertChainError(format!(
            "unrecognized PCK issuer CA type: {issuer}"
        )))
    }
}

// ---------------------------------------------------------------------------
// QE Identity verification
// ---------------------------------------------------------------------------

/// Intel PCS v4 QE Identity JSON signed envelope.
///
/// Uses `RawValue` for the `enclaveIdentity` field to preserve the exact bytes
/// Intel signed (see [`TcbInfoSignedEnvelope`] for rationale).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityEnvelope<'a> {
    #[serde(borrow)]
    enclave_identity: &'a serde_json::value::RawValue,
    signature: String,
}

/// The TD QE Identity as PCS v4 publishes it (`enclaveIdentity`, version 2,
/// id `TD_QE`). Unknown members are ignored.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnclaveIdentityFields {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    // Required by QVL's EnclaveIdentity parse; not used in the evaluation.
    #[allow(dead_code)]
    tcb_evaluation_data_number: u32,
    mrsigner: String,
    isvprodid: u16,
    miscselect: String,
    miscselect_mask: String,
    attributes: String,
    attributes_mask: String,
    tcb_levels: Vec<QeIdentityTcbLevel>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentityTcbLevel {
    tcb: QeIdentityTcb,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct QeIdentityTcb {
    isvsvn: u16,
}

/// QE report field offsets within the 384-byte SGX report body.
/// See Intel SDM Vol. 3D, Table 38-21 (REPORTBODY structure).
const QE_MISCSELECT_OFFSET: usize = 16;
const QE_ATTRIBUTES_OFFSET: usize = 48;
const QE_MRSIGNER_OFFSET: usize = 128;
const QE_ISVPRODID_OFFSET: usize = 256;
const QE_ISVSVN_OFFSET: usize = 258;

/// Verify the Quoting Enclave against Intel's published TD QE Identity and
/// return the TCB level its ISVSVN selects.
///
/// The identity must be signed through a TCB signing chain to the pinned
/// root (with the Root CA CRL), be version 2 with id `TD_QE`, and carry a
/// `nextUpdate`. The QE report's MRSIGNER and ISVPRODID must equal the
/// identity's, and MISCSELECT and ATTRIBUTES must equal it under the masks.
/// The levels are ordered descending by (ISVSVN, tcbDate), as QVL orders them;
/// the first whose ISVSVN the QE's meets gives the status, which the caller
/// converges with the platform's (QVL `applyQeIdentity`). The signing chain
/// and the Root CA CRL are judged at `now`.
pub fn verify_qe_identity_at(
    qe_report_body: &[u8],
    qe_identity_json: &[u8],
    signing_certs_pem: &[u8],
    root_ca_crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<QeTcbLevel> {
    let envelope: QeIdentityEnvelope<'_> = serde_json::from_slice(qe_identity_json)
        .map_err(|e| collateral_err(format!("QE Identity envelope parse: {e}")))?;
    let raw = verify_pcs_signature(
        envelope.enclave_identity,
        &envelope.signature,
        signing_certs_pem,
        root_ca_crl_der,
        now,
        "QE Identity",
    )?;
    evaluate_qe_identity(qe_report_body, raw)
}

/// Check the QE report against the inner `enclaveIdentity` object of a TD QE
/// Identity whose signature the caller verified; see [`verify_qe_identity_at`].
pub fn evaluate_qe_identity(qe_report_body: &[u8], enclave_identity: &str) -> Result<QeTcbLevel> {
    if qe_report_body.len() < QE_REPORT_BODY_SIZE {
        return Err(AttestationError::QuoteParseFailed(format!(
            "QE report body too short: {} bytes, expected {}",
            qe_report_body.len(),
            QE_REPORT_BODY_SIZE
        )));
    }
    let identity: EnclaveIdentityFields = serde_json::from_str(enclave_identity)
        .map_err(|e| collateral_err(format!("QE Identity fields parse: {e}")))?;
    if identity.version != 2 {
        return Err(collateral_err(format!(
            "QE Identity version {} is not 2",
            identity.version
        )));
    }
    if identity.id != "TD_QE" {
        return Err(collateral_err(format!(
            "QE Identity id {:?} is not TD_QE",
            identity.id
        )));
    }
    rfc3339(&identity.issue_date, "QE Identity issueDate")?;
    let next_update = rfc3339(&identity.next_update, "QE Identity nextUpdate")?;

    // Extract QE report fields at known offsets
    let qe_miscselect = &qe_report_body[QE_MISCSELECT_OFFSET..QE_MISCSELECT_OFFSET + 4];
    let qe_attributes = &qe_report_body[QE_ATTRIBUTES_OFFSET..QE_ATTRIBUTES_OFFSET + 16];
    let qe_mrsigner = &qe_report_body[QE_MRSIGNER_OFFSET..QE_MRSIGNER_OFFSET + 32];
    let qe_isvprodid = u16::from_le_bytes([
        qe_report_body[QE_ISVPRODID_OFFSET],
        qe_report_body[QE_ISVPRODID_OFFSET + 1],
    ]);
    let qe_isvsvn = u16::from_le_bytes([
        qe_report_body[QE_ISVSVN_OFFSET],
        qe_report_body[QE_ISVSVN_OFFSET + 1],
    ]);

    let expected_mrsigner = fixed_hex::<32>(&identity.mrsigner, "QE Identity MRSIGNER")?;
    if !crate::utils::constant_time_eq(qe_mrsigner, &expected_mrsigner) {
        return Err(AttestationError::CertChainError(
            "QE MRSIGNER does not match Intel QE Identity".into(),
        ));
    }
    if qe_isvprodid != identity.isvprodid {
        return Err(AttestationError::CertChainError(format!(
            "QE ISVPRODID {} does not match expected {}",
            qe_isvprodid, identity.isvprodid
        )));
    }
    let expected_miscselect = fixed_hex::<4>(&identity.miscselect, "QE Identity MISCSELECT")?;
    let miscselect_mask = fixed_hex::<4>(&identity.miscselect_mask, "QE Identity MISCSELECT mask")?;
    if (0..4).any(|i| {
        qe_miscselect[i] & miscselect_mask[i] != expected_miscselect[i] & miscselect_mask[i]
    }) {
        return Err(AttestationError::CertChainError(
            "QE MISCSELECT does not match Intel QE Identity (masked)".into(),
        ));
    }
    let expected_attributes = fixed_hex::<16>(&identity.attributes, "QE Identity ATTRIBUTES")?;
    let attributes_mask =
        fixed_hex::<16>(&identity.attributes_mask, "QE Identity ATTRIBUTES mask")?;
    if (0..16).any(|i| {
        qe_attributes[i] & attributes_mask[i] != expected_attributes[i] & attributes_mask[i]
    }) {
        return Err(AttestationError::CertChainError(
            "QE ATTRIBUTES does not match Intel QE Identity (masked)".into(),
        ));
    }

    if identity.tcb_levels.is_empty() {
        return Err(collateral_err("QE Identity has no TCB levels"));
    }
    let mut levels = identity
        .tcb_levels
        .into_iter()
        .map(|l| {
            Ok((
                l.tcb.isvsvn,
                rfc3339(&l.tcb_date, "QE tcbDate")?,
                l.tcb_status,
                l.advisory_ids,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    levels.sort_by_key(|l| std::cmp::Reverse((l.0, l.1)));
    if levels
        .windows(2)
        .any(|w| (w[0].0, w[0].1) == (w[1].0, w[1].1))
    {
        return Err(collateral_err("QE Identity repeats a TCB level"));
    }
    let (_, _, status, advisory_ids) =
        levels
            .into_iter()
            .find(|l| qe_isvsvn >= l.0)
            .ok_or_else(|| {
                AttestationError::TcbMismatch(format!(
                    "QE ISVSVN {qe_isvsvn} does not meet any published TCB level"
                ))
            })?;
    use TdxTcbStatus as S;
    let status = status_in(
        &status,
        &[
            S::UpToDate,
            S::OutOfDate,
            S::ConfigurationNeeded,
            S::Revoked,
            S::OutOfDateConfigurationNeeded,
        ],
        "QE TCB level",
    )?;
    Ok(QeTcbLevel {
        status,
        advisory_ids,
        next_update,
    })
}

/// Normalize CRL data to DER format.
///
/// Intel PCS v4 `pckcrl` endpoint returns PEM-encoded CRLs, while the
/// Root CA CRL endpoint returns raw DER. This function accepts either
/// format and always returns DER bytes.
fn normalize_crl_to_der(data: &[u8]) -> Result<Vec<u8>> {
    if crate::utils::is_pem(data) {
        crate::utils::decode_pem_to_der(data)
            .map_err(|_| AttestationError::CollateralInvalid("CRL PEM decode failed".into()))
    } else {
        Ok(data.to_vec())
    }
}

/// Check whether the Intermediate CA (Platform or Processor CA) has been
/// revoked by the Root CA CRL.
///
/// `pck_pem`: PCK cert chain PEM data (leaf, intermediate, root).
/// `root_ca_crl_der`: DER-encoded Root CA CRL from Intel PCS.
pub fn check_intermediate_ca_revocation(pck_pem: &[u8], root_ca_crl_der: &[u8]) -> Result<()> {
    let der_certs = parse_pem_to_der(pck_pem)?;
    check_intermediate_ca_revocation_from_der(&der_certs, root_ca_crl_der)
}

/// Check intermediate CA revocation from pre-parsed DER certificate chain.
/// See [`check_intermediate_ca_revocation`] for details.
pub fn check_intermediate_ca_revocation_from_der(
    der_certs: &[Vec<u8>],
    root_ca_crl_der: &[u8],
) -> Result<()> {
    check_intermediate_ca_revocation_from_der_at(der_certs, root_ca_crl_der, chrono::Utc::now())
}

/// Check the intermediate PCK CA against the Intel SGX Root CA CRL, which
/// must be signed by the pinned Intel root and be inside its window at `now`.
pub fn check_intermediate_ca_revocation_from_der_at(
    der_certs: &[Vec<u8>],
    root_ca_crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if der_certs.len() < 2 {
        return Err(AttestationError::CertChainError(
            "need at least 2 certs to check intermediate CA revocation".into(),
        ));
    }
    let (_, intermediate_cert) = X509Certificate::from_der(&der_certs[1])
        .map_err(|e| AttestationError::CertChainError(format!("Intermediate CA parse: {e}")))?;
    let intermediate_serial = intermediate_cert.raw_serial();

    let root_crl_der_bytes = normalize_crl_to_der(root_ca_crl_der)?;
    let (_, crl) = CertificateRevocationList::from_der(&root_crl_der_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("Root CA CRL parse: {e}")))?;
    let root_key = VerifyingKey::from_sec1_bytes(INTEL_SGX_ROOT_CA_PUB_DER)
        .map_err(|e| AttestationError::CertChainError(format!("Intel Root CA key parse: {e}")))?;
    verify_intel_crl(&crl, &root_key, now, "Intel SGX Root CA")?;

    for revoked in crl.iter_revoked_certificates() {
        if revoked.raw_serial() == intermediate_serial {
            return Err(AttestationError::Revoked(
                "Intermediate CA certificate has been revoked by Root CA CRL".into(),
            ));
        }
    }
    Ok(())
}

/// Check whether the PCK leaf certificate has been revoked by a CRL.
///
/// `pck_pem`: PCK cert chain PEM data.
/// `crl_der`: DER-encoded CRL (from Intel PCS PCK CRL endpoint).
pub fn check_cert_revocation(pck_pem: &[u8], crl_der: &[u8]) -> Result<()> {
    let der_certs = parse_pem_to_der(pck_pem)?;
    check_cert_revocation_from_der(&der_certs, crl_der)
}

/// Check PCK leaf revocation from pre-parsed DER certificate chain.
/// See [`check_cert_revocation`] for details.
pub fn check_cert_revocation_from_der(der_certs: &[Vec<u8>], crl_der: &[u8]) -> Result<()> {
    check_cert_revocation_from_der_at(der_certs, crl_der, chrono::Utc::now())
}

/// Check the PCK leaf against the PCK CA's CRL, which must be signed by the
/// PCK CA in the (already verified) chain and be inside its window at `now`.
pub fn check_cert_revocation_from_der_at(
    der_certs: &[Vec<u8>],
    crl_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if der_certs.len() < 2 {
        return Err(AttestationError::CertChainError(
            "need the PCK leaf and its CA to check revocation".into(),
        ));
    }
    let (_, leaf_cert) = X509Certificate::from_der(&der_certs[0])
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf parse: {e}")))?;
    let leaf_serial = leaf_cert.raw_serial();

    let crl_der_bytes = normalize_crl_to_der(crl_der)?;
    let (_, crl) = CertificateRevocationList::from_der(&crl_der_bytes)
        .map_err(|e| AttestationError::CollateralInvalid(format!("CRL DER parse: {e}")))?;
    let issuer = parse_x509_cert(&der_certs[1], "PCK CA")?;
    let issuer_key = extract_p256_pub_key(&issuer.pub_key_bytes, "PCK CA")?;
    verify_intel_crl(&crl, &issuer_key, now, "PCK CA")?;

    for revoked in crl.iter_revoked_certificates() {
        if revoked.raw_serial() == leaf_serial {
            return Err(AttestationError::Revoked(
                "PCK certificate has been revoked".into(),
            ));
        }
    }
    Ok(())
}

/// ecdsa-with-SHA256, the only algorithm Intel signs SGX CRLs with.
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

/// An Intel CRL is trusted only with a valid ECDSA P-256 signature by
/// `issuer_key` over its TBSCertList, a `thisUpdate` not in the future and a
/// `nextUpdate` that is present and has not passed at `now`.
fn verify_intel_crl(
    crl: &CertificateRevocationList<'_>,
    issuer_key: &VerifyingKey,
    now: chrono::DateTime<chrono::Utc>,
    label: &str,
) -> Result<()> {
    let alg = crl.signature_algorithm.algorithm.to_string();
    if alg != OID_ECDSA_WITH_SHA256 {
        return Err(AttestationError::CollateralInvalid(format!(
            "{label} CRL signature algorithm {alg} is not ecdsa-with-SHA256"
        )));
    }
    let sig = Signature::from_der(crl.signature_value.as_ref()).map_err(|e| {
        AttestationError::CollateralInvalid(format!("{label} CRL signature parse: {e}"))
    })?;
    issuer_key
        .verify(crl.tbs_cert_list.as_ref(), &sig)
        .map_err(|e| {
            AttestationError::CollateralInvalid(format!(
                "{label} CRL signature verification failed: {e}"
            ))
        })?;
    let now_asn1 = x509_parser::time::ASN1Time::from_timestamp(now.timestamp())
        .map_err(|e| AttestationError::CollateralInvalid(format!("clock out of range: {e}")))?;
    if crl.last_update() > now_asn1 {
        return Err(AttestationError::CollateralInvalid(format!(
            "{label} CRL thisUpdate {} is in the future",
            crl.last_update()
        )));
    }
    match crl.next_update() {
        None => Err(AttestationError::CollateralInvalid(format!(
            "{label} CRL has no nextUpdate; refusing a revocation list with no defined freshness"
        ))),
        Some(next) if next < now_asn1 => Err(AttestationError::CollateralInvalid(format!(
            "{label} CRL is stale: nextUpdate {next} has passed; fetch a current CRL"
        ))),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");
    const V5_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_5.dat");
    const ROOT_CA_CRL_DER: &[u8] = include_bytes!("../../../test_data/collateral/root_ca_crl.der");

    fn body_end_v4() -> usize {
        QUOTE_HEADER_SIZE + REPORT_BODY_SIZE
    }

    fn body_end_v5() -> usize {
        let body_size = V5_QUOTE
            .pread_with::<u32>(QUOTE_HEADER_SIZE + 2, scroll::LE)
            .unwrap() as usize;
        QUOTE_HEADER_SIZE + 6 + body_size
    }

    #[test]
    fn test_parse_auth_data_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).expect("should parse v4 auth data");
        assert_eq!(auth.attestation_pub_key.len(), 64);
        assert_eq!(auth.qe_report_body.len(), QE_REPORT_BODY_SIZE);
        assert_eq!(auth.qe_report_signature.len(), 64);
        assert!(!auth.pck_cert_chain_pem.is_empty());
    }

    #[test]
    fn test_parse_auth_data_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).expect("should parse v5 auth data");
        assert_eq!(auth.attestation_pub_key.len(), 64);
        assert_eq!(auth.qe_report_body.len(), QE_REPORT_BODY_SIZE);
        assert_eq!(auth.qe_report_signature.len(), 64);
        assert!(!auth.pck_cert_chain_pem.is_empty());
    }

    #[test]
    fn test_qe_report_binding_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        assert!(
            verify_qe_report_binding(&auth).is_ok(),
            "v4 QE report binding should pass"
        );
    }

    #[test]
    fn test_qe_report_binding_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).unwrap();
        assert!(
            verify_qe_report_binding(&auth).is_ok(),
            "v5 QE report binding should pass"
        );
    }

    #[test]
    fn test_pck_cert_chain_validation_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let result = verify_pck_cert_chain(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "v4 PCK cert chain should validate: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_qe_report_signature_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let pck_key = verify_pck_cert_chain(auth.pck_cert_chain_pem).unwrap();
        let result = verify_qe_report_signature(&auth, &pck_key);
        assert!(
            result.is_ok(),
            "v4 QE report sig should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_tampered_attestation_key_fails() {
        let mut tampered = V4_QUOTE.to_vec();
        let body_end = body_end_v4();
        // Attestation key starts at body_end + 4 + 64
        let key_offset = body_end + 4 + 64;
        tampered[key_offset] ^= 0xFF; // Flip a byte in the attestation key

        let auth = parse_auth_data(&tampered, body_end).unwrap();
        // QE binding should fail since we changed the key
        assert!(
            verify_qe_report_binding(&auth).is_err(),
            "tampered attestation key should fail QE binding"
        );
    }

    #[test]
    fn test_tampered_qe_signature_fails() {
        let mut tampered = V4_QUOTE.to_vec();
        let body_end = body_end_v4();
        let auth_orig = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let pck_key = verify_pck_cert_chain(auth_orig.pck_cert_chain_pem).unwrap();

        // QE report signature is inside the cert data, after the QE report body
        // Find the cert data start: body_end + 4 + 64 + 64 + 6
        let cert_data_start = body_end + 4 + 64 + 64 + 6;
        // QE sig is at cert_data_start + 384
        let qe_sig_offset = cert_data_start + QE_REPORT_BODY_SIZE;
        tampered[qe_sig_offset] ^= 0xFF;

        let auth = parse_auth_data(&tampered, body_end).unwrap();
        assert!(
            verify_qe_report_signature(&auth, &pck_key).is_err(),
            "tampered QE signature should fail verification"
        );
    }

    #[test]
    fn test_compute_body_end_v4() {
        let end = compute_body_end(V4_QUOTE, QuoteVersion::V4).unwrap();
        assert_eq!(end, QUOTE_HEADER_SIZE + REPORT_BODY_SIZE);
    }

    #[test]
    fn test_compute_body_end_v5() {
        let end = compute_body_end(V5_QUOTE, QuoteVersion::V5Tdx15).unwrap();
        assert_eq!(end, body_end_v5());
    }

    #[test]
    fn test_extract_fmspc_from_pck_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let result = extract_fmspc_from_pck(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "should extract FMSPC from v4 PCK cert: {:?}",
            result.err()
        );
        let fmspc = result.unwrap();
        // FMSPC is 6 bytes = 12 hex chars
        assert_eq!(fmspc.len(), 12, "FMSPC should be 12 hex chars");
    }

    #[test]
    fn test_extract_fmspc_from_pck_v5() {
        let body_end = body_end_v5();
        let auth = parse_auth_data(V5_QUOTE, body_end).unwrap();
        let result = extract_fmspc_from_pck(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "should extract FMSPC from v5 PCK cert: {:?}",
            result.err()
        );
        let fmspc = result.unwrap();
        assert_eq!(fmspc.len(), 12);
    }

    #[test]
    fn test_extract_pck_tcb_components_v4() {
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();
        let pck = pck_tcb_from_pem(auth.pck_cert_chain_pem).expect("PCK TCB");
        assert_eq!(hex::encode(pck.fmspc), "50806f000000");
        assert_eq!(pck.pce_id, [0, 0]);
        // At least some components should be non-zero in a real cert
        assert!(
            pck.cpusvn.iter().any(|&v| v != 0) || pck.pcesvn != 0,
            "TCB components should not all be zero"
        );
    }

    #[test]
    fn test_parse_tcb_status_strings() {
        assert_eq!(
            parse_tcb_status("UpToDate").unwrap(),
            TdxTcbStatus::UpToDate
        );
        assert_eq!(
            parse_tcb_status("SWHardeningNeeded").unwrap(),
            TdxTcbStatus::SWHardeningNeeded
        );
        assert_eq!(
            parse_tcb_status("ConfigurationNeeded").unwrap(),
            TdxTcbStatus::ConfigurationNeeded
        );
        assert_eq!(
            parse_tcb_status("OutOfDate").unwrap(),
            TdxTcbStatus::OutOfDate
        );
        assert_eq!(parse_tcb_status("Revoked").unwrap(), TdxTcbStatus::Revoked);
        assert!(parse_tcb_status("InvalidStatus").is_err());
    }

    #[test]
    fn test_check_intermediate_ca_revocation_needs_two_certs() {
        // A single-cert PEM should fail
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();

        // Extract just the first cert from the PEM chain
        let pem_str = std::str::from_utf8(auth.pck_cert_chain_pem).unwrap();
        let end_marker = "-----END CERTIFICATE-----";
        let first_cert_end = pem_str.find(end_marker).unwrap() + end_marker.len();
        let single_cert_pem = &pem_str[..first_cert_end];

        let bogus_crl = vec![0x30, 0x00];
        let result = check_intermediate_ca_revocation(single_cert_pem.as_bytes(), &bogus_crl);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AttestationError::CertChainError(m)) if m.contains("at least 2 certs")
        ));
    }

    #[test]
    fn test_verify_signing_cert_chain_wrong_key_rejected() {
        // A PEM chain where the root key doesn't match Intel's should be rejected
        let body_end = body_end_v4();
        let auth = parse_auth_data(V4_QUOTE, body_end).unwrap();

        // The PCK chain has 3 certs, not a signing chain, but let's
        // verify that verify_signing_cert_chain rejects it if the root
        // key doesn't match (the PCK chain root IS the Intel root, so
        // it would pass root key check but the chain is 3 certs).
        // With a 2-cert subset that's not a valid signing chain, it should
        // still reject if signatures don't verify.
        let pem_str = std::str::from_utf8(auth.pck_cert_chain_pem).unwrap();
        let end_marker = "-----END CERTIFICATE-----";

        // Extract leaf and intermediate only (2-cert chain)
        let first_end = pem_str.find(end_marker).unwrap() + end_marker.len();
        let second_end =
            pem_str[first_end + 1..].find(end_marker).unwrap() + first_end + 1 + end_marker.len();
        let two_cert_pem = &pem_str[..second_end];

        // This should fail because the 2nd cert (intermediate) is not the Root CA
        let result = verify_signing_cert_chain(two_cert_pem.as_bytes(), ROOT_CA_CRL_DER);
        assert!(
            result.is_err(),
            "intermediate CA should not be accepted as Intel Root CA"
        );
    }

    #[test]
    fn test_normalize_crl_to_der_passthrough() {
        let der = vec![0x30, 0x82, 0x01, 0x00];
        let result = normalize_crl_to_der(&der).unwrap();
        assert_eq!(result, der);
    }

    #[test]
    fn test_normalize_crl_to_der_decodes_pem() {
        let der_bytes = vec![0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let b64 = BASE64.encode(&der_bytes);
        let pem = format!("-----BEGIN X509 CRL-----\n{b64}\n-----END X509 CRL-----\n");
        let result = normalize_crl_to_der(pem.as_bytes()).unwrap();
        assert_eq!(result, der_bytes);
    }

    // -----------------------------------------------------------------------
    // QVL alignment: TCB Info binding, level selection, module identity,
    // convergence, QE Identity, the TCB signing chain and auth data length.
    // -----------------------------------------------------------------------

    use serde_json::{json, Value};

    const TCB_INFO_50806F: &[u8] =
        include_bytes!("../../../test_data/collateral/tcb_info_50806f000000.json");
    const TCB_SIGNING_CHAIN: &[u8] =
        include_bytes!("../../../test_data/collateral/tcb_signing_chain.pem");
    const TD_QE_IDENTITY: &[u8] =
        include_bytes!("../../../test_data/collateral/td_qe_identity.json");
    const QE_IDENTITY_SIGNING_CHAIN: &[u8] =
        include_bytes!("../../../test_data/collateral/qe_identity_signing_chain.pem");
    const PCK_CRL_DER: &[u8] = include_bytes!("../../../test_data/collateral/pck_crl_platform.der");

    fn fixture_now() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 3, 17, 0, 0, 0).unwrap()
    }

    fn v4_body() -> super::super::verify::TdxReportBody {
        super::super::verify::parse_tdx_quote(V4_QUOTE)
            .unwrap()
            .body
    }

    /// FMSPC 50806f000000, PCE-ID 0000, CPUSVN [5,5,13,2,3,1,0,3,0..], PCESVN 11.
    fn v4_pck() -> PckTcb {
        let auth = parse_auth_data(V4_QUOTE, body_end_v4()).unwrap();
        pck_tcb_from_pem(auth.pck_cert_chain_pem).unwrap()
    }

    fn qe_level(status: TdxTcbStatus) -> QeTcbLevel {
        QeTcbLevel {
            status,
            advisory_ids: vec!["INTEL-SA-QE".into()],
            next_update: fixture_now() + chrono::Duration::days(30),
        }
    }

    fn c(prefix: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..prefix.len()].copy_from_slice(prefix);
        out
    }

    fn svns(v: &[u8; 16]) -> Value {
        Value::Array(v.iter().map(|s| json!({ "svn": s })).collect())
    }

    /// A v3 TDX `tcbInfo` for the v4 fixture's platform with these levels
    /// (SGX components, PCESVN, TDX components, status), unsigned.
    fn tcb_info_value(levels: &[([u8; 16], u16, [u8; 16], &str)]) -> Value {
        json!({
            "id": "TDX",
            "version": 3,
            "issueDate": "2026-03-16T00:00:00Z",
            "nextUpdate": "2026-04-15T00:00:00Z",
            "fmspc": "50806f000000",
            "pceId": "0000",
            "tcbType": 0,
            "tcbEvaluationDataNumber": 18,
            "tdxModule": {
                "mrsigner": "00".repeat(48),
                "attributes": "0000000000000000",
                "attributesMask": "FFFFFFFFFFFFFFFF"
            },
            "tcbLevels": levels.iter().map(|(sgx, pcesvn, tdx, status)| json!({
                "tcb": {
                    "sgxtcbcomponents": svns(sgx),
                    "pcesvn": pcesvn,
                    "tdxtcbcomponents": svns(tdx)
                },
                "tcbDate": "2026-01-01T00:00:00Z",
                "tcbStatus": status,
                "advisoryIDs": [format!("INTEL-SA-{status}")]
            })).collect::<Vec<_>>()
        })
    }

    fn module_identity_value(id: &str, levels: &[(u16, &str)]) -> Value {
        json!({
            "id": id,
            "mrsigner": "00".repeat(48),
            "attributes": "0000000000000000",
            "attributesMask": "FFFFFFFFFFFFFFFF",
            "tcbLevels": levels.iter().map(|(isvsvn, status)| json!({
                "tcb": { "isvsvn": isvsvn },
                "tcbDate": "2026-01-01T00:00:00Z",
                "tcbStatus": status,
                "advisoryIDs": [format!("INTEL-SA-MODULE-{status}")]
            })).collect::<Vec<_>>()
        })
    }

    fn parse(v: &Value) -> Result<TdxTcbInfo> {
        parse_tdx_tcb_info(&v.to_string())
    }

    /// The fixture's `tcbInfo` member, unsigned.
    fn fixture_tcb_info() -> Value {
        serde_json::from_slice::<Value>(TCB_INFO_50806F).unwrap()["tcbInfo"].clone()
    }

    fn evaluate(
        info: &TdxTcbInfo,
        body: &super::super::verify::TdxReportBody,
    ) -> Result<TdxTcbVerdict> {
        evaluate_tdx_tcb(info, body, &v4_pck(), &qe_level(TdxTcbStatus::UpToDate))
    }

    fn is_collateral_invalid<T: std::fmt::Debug>(r: &Result<T>) -> bool {
        matches!(r, Err(AttestationError::CollateralInvalid(_)))
    }

    fn is_tcb_mismatch<T: std::fmt::Debug>(r: &Result<T>) -> bool {
        matches!(r, Err(AttestationError::TcbMismatch(_)))
    }

    #[test]
    fn fixture_tcb_info_selects_its_out_of_date_level() {
        let info = verify_tdx_tcb_info_at(
            TCB_INFO_50806F,
            TCB_SIGNING_CHAIN,
            ROOT_CA_CRL_DER,
            fixture_now(),
        )
        .expect("fixture TCB Info verifies");
        let verdict = evaluate(&info, &v4_body()).unwrap();
        assert_eq!(verdict.tcb_status, TdxTcbStatus::OutOfDate);
        assert_eq!(
            verdict.advisory_ids.last().map(String::as_str),
            Some("INTEL-SA-QE")
        );
    }

    #[test]
    fn tcb_info_for_another_fmspc_or_pce_id_is_refused() {
        let mut info = parse(&fixture_tcb_info()).unwrap();
        info.fmspc = [0x90, 0xc0, 0x6f, 0, 0, 0];
        assert!(is_collateral_invalid(&evaluate(&info, &v4_body())));

        let mut info = parse(&fixture_tcb_info()).unwrap();
        info.pce_id = [0x00, 0x01];
        assert!(is_collateral_invalid(&evaluate(&info, &v4_body())));
    }

    #[test]
    fn tcb_info_shape_is_checked_in_the_parser() {
        let refused = |edit: &dyn Fn(&mut Value)| {
            let mut v = fixture_tcb_info();
            edit(&mut v);
            assert!(is_collateral_invalid(&parse(&v)), "accepted {v}");
        };
        refused(&|v| v["version"] = json!(2));
        refused(&|v| v["id"] = json!("SGX"));
        refused(&|v| v["tcbType"] = json!(1));
        refused(&|v| {
            v.as_object_mut().unwrap().remove("nextUpdate");
        });
        refused(&|v| v["nextUpdate"] = json!("soon"));
        refused(&|v| {
            v.as_object_mut().unwrap().remove("tdxModule");
        });
        refused(&|v| v["fmspc"] = json!("50806f"));
        refused(&|v| v["tdxModuleIdentities"] = json!([]));
        refused(&|v| {
            v["tcbLevels"][0]["tcb"]["sgxtcbcomponents"]
                .as_array_mut()
                .unwrap()
                .pop();
        });
        refused(&|v| {
            v["tcbLevels"][0]["tcb"]
                .as_object_mut()
                .unwrap()
                .remove("tdxtcbcomponents");
        });
    }

    #[test]
    fn repeated_tcb_levels_are_refused() {
        let level = (c(&[5, 5]), 11, c(&[3, 0, 5]), "UpToDate");
        let mut v = tcb_info_value(&[level, level]);
        assert!(is_collateral_invalid(&parse(&v)));
        v["tcbLevels"][1]["tcbStatus"] = json!("OutOfDate");
        assert!(
            is_collateral_invalid(&parse(&v)),
            "the status is not part of the key"
        );
    }

    #[test]
    fn level_selection_rechecks_sgx_components_with_tdx_components() {
        // The first level whose TDX components match fails on SGX components;
        // the second matches SGX but not TDX; only the third matches both.
        let info = parse(&tcb_info_value(&[
            (c(&[9, 9]), 0, c(&[0]), "UpToDate"),
            (c(&[5, 5]), 11, c(&[9]), "SWHardeningNeeded"),
            (c(&[5, 5]), 11, c(&[3, 0, 5]), "ConfigurationNeeded"),
        ]))
        .unwrap();
        let verdict = evaluate(&info, &v4_body()).unwrap();
        assert_eq!(verdict.tcb_status, TdxTcbStatus::ConfigurationNeeded);
        assert_eq!(verdict.advisory_ids[0], "INTEL-SA-ConfigurationNeeded");
    }

    #[test]
    fn level_selection_follows_the_sorted_order_whatever_the_json_order() {
        let info = parse(&tcb_info_value(&[
            (c(&[1, 1]), 5, c(&[0]), "OutOfDate"),
            (c(&[5, 5]), 11, c(&[3, 0, 5]), "UpToDate"),
        ]))
        .unwrap();
        assert_eq!(info.levels[0].status, "UpToDate");
        assert_eq!(
            evaluate(&info, &v4_body()).unwrap().tcb_status,
            TdxTcbStatus::UpToDate
        );
    }

    #[test]
    fn a_pcesvn_below_the_level_skips_it() {
        let info = parse(&tcb_info_value(&[
            (c(&[5, 5]), 12, c(&[3, 0, 5]), "UpToDate"),
            (c(&[5, 5]), 11, c(&[3, 0, 5]), "OutOfDate"),
        ]))
        .unwrap();
        assert_eq!(
            evaluate(&info, &v4_body()).unwrap().tcb_status,
            TdxTcbStatus::OutOfDate
        );
    }

    #[test]
    fn an_all_zero_tee_tcb_svn_is_matched_against_tdx_components() {
        let info = parse(&tcb_info_value(&[
            (c(&[5, 5]), 11, c(&[3, 0, 5]), "UpToDate"),
            (c(&[1]), 0, c(&[]), "OutOfDate"),
        ]))
        .unwrap();
        let mut body = v4_body();
        body.tee_tcb_svn = [0; 16];
        assert_eq!(
            evaluate(&info, &body).unwrap().tcb_status,
            TdxTcbStatus::OutOfDate
        );

        let only_high = parse(&tcb_info_value(&[(
            c(&[5, 5]),
            11,
            c(&[3, 0, 5]),
            "UpToDate",
        )]))
        .unwrap();
        assert!(is_tcb_mismatch(&evaluate(&only_high, &body)));
    }

    #[test]
    fn a_module_major_version_compares_tdx_components_from_byte_2() {
        let mut v = tcb_info_value(&[(c(&[5, 5]), 11, c(&[9, 9, 5]), "UpToDate")]);
        v["tdxModuleIdentities"] = json!([module_identity_value("TDX_01", &[(1, "UpToDate")])]);
        let info = parse(&v).unwrap();
        let mut body = v4_body();
        body.tee_tcb_svn = c(&[1, 1, 5]);
        assert_eq!(
            evaluate(&info, &body).unwrap().tcb_status,
            TdxTcbStatus::UpToDate
        );

        body.tee_tcb_svn = c(&[1, 1, 4]);
        assert!(
            is_tcb_mismatch(&evaluate(&info, &body)),
            "byte 2 is still compared"
        );
    }

    #[test]
    fn mrsignerseam_and_seamattributes_must_match_the_tdx_module() {
        let mut v = tcb_info_value(&[(c(&[5, 5]), 11, c(&[3, 0, 5]), "UpToDate")]);
        v["tdxModule"]["mrsigner"] = json!("01".repeat(48));
        assert!(is_tcb_mismatch(&evaluate(&parse(&v).unwrap(), &v4_body())));

        // Nonzero SEAMATTRIBUTES are refused even when the TCB Info names them.
        let mut v = tcb_info_value(&[(c(&[5, 5]), 11, c(&[3, 0, 5]), "UpToDate")]);
        v["tdxModule"]["attributes"] = json!("0100000000000000");
        let info = parse(&v).unwrap();
        let mut body = v4_body();
        body.seam_attributes = [1, 0, 0, 0, 0, 0, 0, 0];
        assert!(is_tcb_mismatch(&evaluate(&info, &body)));
        assert!(
            is_tcb_mismatch(&evaluate(&info, &v4_body())),
            "zero must also equal the TCB Info's"
        );
    }

    #[test]
    fn a_module_major_version_uses_its_identity() {
        let levels = [(c(&[5, 5]), 11, c(&[0, 0, 5]), "UpToDate")];
        let mut body = v4_body();
        body.tee_tcb_svn = c(&[3, 1, 5]);

        // No tdxModuleIdentities, or none for TDX_01.
        assert!(is_tcb_mismatch(&evaluate(
            &parse(&tcb_info_value(&levels)).unwrap(),
            &body
        )));
        let mut v = tcb_info_value(&levels);
        v["tdxModuleIdentities"] = json!([module_identity_value("TDX_03", &[(0, "UpToDate")])]);
        assert!(is_tcb_mismatch(&evaluate(&parse(&v).unwrap(), &body)));

        // The id matches without regard to case; its levels, not tdxModule's
        // signer, judge the module.
        let mut v = tcb_info_value(&levels);
        v["tdxModule"]["mrsigner"] = json!("01".repeat(48));
        v["tdxModuleIdentities"] = json!([module_identity_value(
            "tdx_01",
            &[(2, "OutOfDate"), (4, "UpToDate")]
        )]);
        let verdict = evaluate(&parse(&v).unwrap(), &body).unwrap();
        assert_eq!(verdict.tcb_status, TdxTcbStatus::OutOfDate);
        assert_eq!(
            verdict.advisory_ids,
            [
                "INTEL-SA-UpToDate",
                "INTEL-SA-QE",
                "INTEL-SA-MODULE-OutOfDate"
            ]
        );

        // An identity's signer is checked in place of tdxModule's.
        v["tdxModuleIdentities"][0]["mrsigner"] = json!("02".repeat(48));
        assert!(is_tcb_mismatch(&evaluate(&parse(&v).unwrap(), &body)));

        // A module SVN below every level of its identity.
        let mut v = tcb_info_value(&levels);
        v["tdxModuleIdentities"] = json!([module_identity_value("TDX_01", &[(4, "UpToDate")])]);
        assert!(is_tcb_mismatch(&evaluate(&parse(&v).unwrap(), &body)));

        // A module level may not carry a platform-only status.
        let mut v = tcb_info_value(&levels);
        v["tdxModuleIdentities"] = json!([module_identity_value(
            "TDX_01",
            &[(1, "ConfigurationNeeded")]
        )]);
        assert!(is_collateral_invalid(&evaluate(&parse(&v).unwrap(), &body)));
    }

    #[test]
    fn statuses_converge_as_qvl_converges_them() {
        use TdxTcbStatus as S;
        for (platform, components, want) in [
            (S::UpToDate, vec![S::UpToDate], S::UpToDate),
            (S::UpToDate, vec![S::OutOfDate], S::OutOfDate),
            (S::SWHardeningNeeded, vec![S::OutOfDate], S::OutOfDate),
            (
                S::ConfigurationNeeded,
                vec![S::OutOfDate],
                S::OutOfDateConfigurationNeeded,
            ),
            (
                S::ConfigurationAndSWHardeningNeeded,
                vec![S::UpToDate, S::OutOfDate],
                S::OutOfDateConfigurationNeeded,
            ),
            (
                S::OutOfDateConfigurationNeeded,
                vec![S::OutOfDate],
                S::OutOfDateConfigurationNeeded,
            ),
            (
                S::ConfigurationNeeded,
                vec![S::ConfigurationNeeded],
                S::ConfigurationNeeded,
            ),
            (S::UpToDate, vec![S::OutOfDate, S::Revoked], S::Revoked),
            (S::Revoked, vec![S::UpToDate], S::Revoked),
        ] {
            assert_eq!(
                converge_tcb_statuses(platform, &components),
                want,
                "{platform:?} with {components:?}"
            );
        }

        // The QE's status reaches the verdict.
        let info = parse(&tcb_info_value(&[(
            c(&[5, 5]),
            11,
            c(&[3, 0, 5]),
            "ConfigurationNeeded",
        )]))
        .unwrap();
        let body = v4_body();
        for (qe, want) in [
            (S::OutOfDate, S::OutOfDateConfigurationNeeded),
            (S::Revoked, S::Revoked),
        ] {
            let verdict = evaluate_tdx_tcb(&info, &body, &v4_pck(), &qe_level(qe)).unwrap();
            assert_eq!(verdict.tcb_status, want);
        }
    }

    fn v4_qe_report() -> (Vec<u8>, u16) {
        let auth = parse_auth_data(V4_QUOTE, body_end_v4()).unwrap();
        let isvsvn = u16::from_le_bytes([
            auth.qe_report_body[QE_ISVSVN_OFFSET],
            auth.qe_report_body[QE_ISVSVN_OFFSET + 1],
        ]);
        (auth.qe_report_body.to_vec(), isvsvn)
    }

    /// The fixture's `enclaveIdentity` member, unsigned.
    fn fixture_qe_identity() -> Value {
        serde_json::from_slice::<Value>(TD_QE_IDENTITY).unwrap()["enclaveIdentity"].clone()
    }

    #[test]
    fn fixture_qe_identity_verifies_up_to_date() {
        let (report, _) = v4_qe_report();
        let level = verify_qe_identity_at(
            &report,
            TD_QE_IDENTITY,
            QE_IDENTITY_SIGNING_CHAIN,
            ROOT_CA_CRL_DER,
            fixture_now(),
        )
        .unwrap();
        assert_eq!(level.status, TdxTcbStatus::UpToDate);
        assert_eq!(level.next_update.to_rfc3339(), "2026-04-15T22:16:03+00:00");
    }

    #[test]
    fn qe_identity_id_version_and_next_update_are_required() {
        let (report, _) = v4_qe_report();
        let refused = |edit: &dyn Fn(&mut Value)| {
            let mut v = fixture_qe_identity();
            edit(&mut v);
            let r = evaluate_qe_identity(&report, &v.to_string());
            assert!(is_collateral_invalid(&r), "accepted {v}: {r:?}");
        };
        refused(&|v| v["id"] = json!("QE"));
        refused(&|v| v["id"] = json!("QVE"));
        refused(&|v| v["version"] = json!(1));
        refused(&|v| v["version"] = json!(3));
        refused(&|v| {
            v.as_object_mut().unwrap().remove("nextUpdate");
        });
        refused(&|v| {
            v.as_object_mut().unwrap().remove("issueDate");
        });
        refused(&|v| {
            v.as_object_mut().unwrap().remove("tcbEvaluationDataNumber");
        });
        refused(&|v| v["tcbLevels"] = json!([]));
        refused(&|v| v["tcbLevels"][0]["tcbStatus"] = json!("SWHardeningNeeded"));
    }

    #[test]
    fn qe_identity_levels_are_sorted_and_selected_by_isvsvn() {
        let (report, isvsvn) = v4_qe_report();
        assert!(isvsvn >= 2, "the fixture QE's ISVSVN is {isvsvn}");
        let level = |svn: u16, date: &str, status: &str| json!({"tcb": {"isvsvn": svn}, "tcbDate": date, "tcbStatus": status, "advisoryIDs": [status]});
        let with = |levels: Value| {
            let mut v = fixture_qe_identity();
            v["tcbLevels"] = levels;
            evaluate_qe_identity(&report, &v.to_string())
        };

        // Listed low first: the level the QE meets that is highest still wins.
        let r = with(json!([
            level(1, "2025-01-01T00:00:00Z", "OutOfDate"),
            level(isvsvn, "2026-01-01T00:00:00Z", "UpToDate"),
            level(isvsvn + 1, "2026-02-01T00:00:00Z", "UpToDate"),
        ]))
        .unwrap();
        assert_eq!(r.status, TdxTcbStatus::UpToDate);

        // A revoked level is a status for convergence, not an early error.
        let r = with(json!([level(isvsvn, "2026-01-01T00:00:00Z", "Revoked")])).unwrap();
        assert_eq!(r.status, TdxTcbStatus::Revoked);

        // Two levels with the same ISVSVN and date are one level twice.
        assert!(is_collateral_invalid(&with(json!([
            level(isvsvn, "2026-01-01T00:00:00Z", "UpToDate"),
            level(isvsvn, "2026-01-01T00:00:00Z", "OutOfDate"),
        ]))));

        // A QE below every level.
        assert!(is_tcb_mismatch(&with(json!([level(
            isvsvn + 1,
            "2026-01-01T00:00:00Z",
            "UpToDate"
        )]))));
    }

    #[test]
    fn qe_identity_signer_and_product_are_checked() {
        let (report, _) = v4_qe_report();
        let mut v = fixture_qe_identity();
        v["mrsigner"] = json!("00".repeat(32));
        assert!(matches!(
            evaluate_qe_identity(&report, &v.to_string()),
            Err(AttestationError::CertChainError(_))
        ));
        let mut v = fixture_qe_identity();
        v["isvprodid"] = json!(v["isvprodid"].as_u64().unwrap() + 1);
        assert!(matches!(
            evaluate_qe_identity(&report, &v.to_string()),
            Err(AttestationError::CertChainError(_))
        ));
    }

    /// PEM of the certificates of the v4 quote's PCK chain at these indices.
    fn pck_chain_pem(indices: &[usize]) -> Vec<u8> {
        let auth = parse_auth_data(V4_QUOTE, body_end_v4()).unwrap();
        let certs = parse_pem_to_der(auth.pck_cert_chain_pem).unwrap();
        indices
            .iter()
            .map(|&i| {
                format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    BASE64.encode(&certs[i])
                )
            })
            .collect::<String>()
            .into_bytes()
    }

    #[test]
    fn a_root_signed_certificate_of_another_role_cannot_sign_collateral() {
        // The PCK Platform CA is signed by the same root and verifies as a
        // chain; its role is what refuses it.
        let r =
            verify_signing_cert_chain_at(&pck_chain_pem(&[1, 2]), ROOT_CA_CRL_DER, fixture_now());
        match r {
            Err(AttestationError::CollateralInvalid(m)) => {
                assert!(
                    m.contains("not an Intel SGX TCB Signing certificate"),
                    "{m}"
                )
            }
            Err(e) => panic!("refused for another reason: {e}"),
            Ok(_) => panic!("accepted a PCK CA as the TCB signer"),
        }
        assert!(
            verify_signing_cert_chain_at(TCB_SIGNING_CHAIN, ROOT_CA_CRL_DER, fixture_now()).is_ok()
        );
    }

    #[test]
    fn the_signing_chain_is_exactly_signer_and_root() {
        let mut three = TCB_SIGNING_CHAIN.to_vec();
        three.extend_from_slice(&pck_chain_pem(&[2]));
        assert!(is_collateral_invalid(&verify_signing_cert_chain_at(
            &three,
            ROOT_CA_CRL_DER,
            fixture_now()
        )));
    }

    #[test]
    fn the_signing_chain_needs_a_root_ca_crl_the_root_signed() {
        // The PCK Platform CA's CRL is signed by that CA, not the root.
        let r = verify_signing_cert_chain_at(TCB_SIGNING_CHAIN, PCK_CRL_DER, fixture_now());
        assert!(is_collateral_invalid(&r));
        let mut forged = ROOT_CA_CRL_DER.to_vec();
        let n = forged.len();
        forged[n - 1] ^= 0xff;
        let r = verify_tdx_tcb_info_at(TCB_INFO_50806F, TCB_SIGNING_CHAIN, &forged, fixture_now());
        assert!(r.is_err(), "a forged root CRL passed");
    }

    fn v4_sig_data_len() -> usize {
        V4_QUOTE
            .pread_with::<u32>(body_end_v4(), scroll::LE)
            .unwrap() as usize
    }

    fn with_sig_data_len(len: usize) -> Vec<u8> {
        let mut q = V4_QUOTE.to_vec();
        q[body_end_v4()..body_end_v4() + 4].copy_from_slice(&(len as u32).to_le_bytes());
        q
    }

    #[test]
    fn sig_data_len_must_fit_the_quote_and_hold_the_certification_data() {
        let len = v4_sig_data_len();
        let remaining = V4_QUOTE.len() - body_end_v4() - 4;
        assert!(len <= remaining);
        let too_long = with_sig_data_len(remaining + 1);
        assert!(matches!(
            parse_auth_data(&too_long, body_end_v4()),
            Err(AttestationError::QuoteParseFailed(_))
        ));
        let too_short = with_sig_data_len(len - 1);
        assert!(matches!(
            parse_auth_data(&too_short, body_end_v4()),
            Err(AttestationError::QuoteParseFailed(_))
        ));
        let too_short = with_sig_data_len(128);
        assert!(parse_auth_data(&too_short, body_end_v4()).is_err());
    }

    #[test]
    fn bytes_after_the_auth_data_are_ignored() {
        let mut q = V4_QUOTE.to_vec();
        q.extend_from_slice(&[0xAA; 32]);
        let quote = super::super::verify::parse_tdx_quote(&q).unwrap();
        super::super::verify::verify_quote_signature(&q, &quote).unwrap();
        verify_dcap_chain_at(&q, quote.quote_version, None, fixture_now()).unwrap();
    }
}
