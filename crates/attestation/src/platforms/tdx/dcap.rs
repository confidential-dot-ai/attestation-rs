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
pub fn verify_pck_cert_chain(pem_data: &[u8]) -> Result<VerifyingKey> {
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
        verify_cert_validity_period(der, label)?;
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
/// Validates:
///   - Root CA public key matches hardcoded Intel trust anchor
///   - Root CA self-signs correctly
///   - Signing cert is signed by Root CA
///   - Both certificates are within their validity periods
pub fn verify_signing_cert_chain(pem_data: &[u8]) -> Result<VerifyingKey> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| {
        AttestationError::CertChainError(format!("signing chain PEM not UTF-8: {e}"))
    })?;

    let der_certs = split_pem_to_der(pem_str)?;

    if der_certs.len() < 2 {
        return Err(AttestationError::CertChainError(format!(
            "expected at least 2 certificates in signing chain, got {}",
            der_certs.len()
        )));
    }

    let signing_cert = parse_x509_cert(&der_certs[0], "TCB Signing")?;
    let root_cert = parse_x509_cert(&der_certs[1], "Intel SGX Root CA")?;

    // Verify Root CA public key matches hardcoded Intel key
    let root_pub_key = extract_p256_pub_key(&root_cert.pub_key_bytes, "Root CA")?;
    let intel_root_key = VerifyingKey::from_sec1_bytes(INTEL_SGX_ROOT_CA_PUB_DER)
        .map_err(|e| AttestationError::CertChainError(format!("Intel Root CA key parse: {e}")))?;

    if root_pub_key.to_encoded_point(false) != intel_root_key.to_encoded_point(false) {
        return Err(AttestationError::CertChainError(
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
        verify_cert_validity_period(der, label)?;
    }

    extract_p256_pub_key(&signing_cert.pub_key_bytes, "TCB Signing")
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

/// Verify a certificate's validity period (NotBefore/NotAfter) against the current time.
fn verify_cert_validity_period(der: &[u8], label: &str) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| {
        AttestationError::CertChainError(format!("{label} x509 parse for validity: {e}"))
    })?;

    let validity = cert.validity();
    let now = x509_parser::time::ASN1Time::now();

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
    let body_end = compute_body_end(quote_bytes, quote_version)?;
    let auth = parse_auth_data(quote_bytes, body_end)?;
    let pck_pub_key = verify_pck_cert_chain(auth.pck_cert_chain_pem)?;
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

/// Intel PCS v4 TCB Info JSON structure (subset needed for evaluation).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoWrapper {
    tcb_info: TcbInfoJson,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfoJson {
    tcb_levels: Vec<TcbLevelJson>,
    /// ISO 8601 timestamp indicating when this TCB Info expires.
    #[serde(default)]
    next_update: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelJson {
    tcb: TcbComponentsJson,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbComponentsJson {
    #[serde(default)]
    sgxtcbcomponents: Vec<SvnComponent>,
    pcesvn: u16,
    #[serde(default)]
    tdxtcbcomponents: Option<Vec<SvnComponent>>,
}

#[derive(Debug, serde::Deserialize)]
struct SvnComponent {
    svn: u8,
}

/// Extract SGX TCB component SVNs from the PCK cert's SGX extensions.
///
/// The PCK certificate contains 16 TCB component SVNs under OID
/// 1.2.840.113741.1.13.1.2.{1..16} and a PCESVN under 1.2.840.113741.1.13.1.2.17.
fn extract_pck_tcb_components(pem_data: &[u8]) -> Result<([u8; 16], u16)> {
    let der_certs = parse_pem_to_der(pem_data)?;
    extract_pck_tcb_components_from_der(&der_certs)
}

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
                            if (1..=16).contains(&idx) {
                                compsvn[idx - 1] = val as u8;
                            } else if idx == 17 {
                                pcesvn = val as u16;
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

/// Verify the ECDSA-P256 signature on the Intel PCS TCB Info response.
///
/// Intel PCS v4 returns TCB Info as a signed envelope:
/// ```json
/// { "tcbInfo": { ... }, "signature": "hex-encoded ECDSA-P256 signature" }
/// ```
///
/// The signature covers the raw JSON string of the `tcbInfo` field.
/// `signing_certs_pem`: PEM-encoded signing certificate chain from the
/// `TCB-Info-Issuer-Chain` response header, rooted to Intel SGX Root CA.
pub fn verify_tcb_info_signature(tcb_info_json: &[u8], signing_certs_pem: &[u8]) -> Result<()> {
    let envelope: TcbInfoSignedEnvelope<'_> = serde_json::from_slice(tcb_info_json)
        .map_err(|e| AttestationError::CertChainError(format!("TCB Info envelope parse: {e}")))?;

    let sig_bytes = hex::decode(&envelope.signature).map_err(|e| {
        AttestationError::CertChainError(format!("TCB Info signature hex decode: {e}"))
    })?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("TCB Info signature parse: {e}")))?;

    // Verify the signing cert chain roots to Intel SGX Root CA (2-cert chain)
    let signing_key = verify_signing_cert_chain(signing_certs_pem)?;

    // RawValue preserves the exact bytes Intel signed — no re-serialization.
    signing_key
        .verify(envelope.tcb_info.get().as_bytes(), &signature)
        .map_err(|e| {
            AttestationError::CertChainError(format!("TCB Info signature verification failed: {e}"))
        })?;

    Ok(())
}

/// Evaluate TCB status for a TDX quote against Intel TCB Info collateral.
///
/// Matches the quote's TCB SVNs against the TCB levels from Intel PCS,
/// returning the status and any security advisories.
///
/// `tcb_info_json`: raw JSON response from Intel PCS v4 `/tcb` endpoint.
/// `tee_tcb_svn`: 16-byte TEE TCB SVN from the TDX quote body.
/// `pck_pem`: PCK cert chain PEM (for extracting SGX TCB components).
/// `signing_certs_pem`: optional PEM-encoded TCB signing certificate chain
/// from the `TCB-Info-Issuer-Chain` response header. When provided, the
/// Intel signature on the TCB Info is verified before use.
pub fn evaluate_tcb_status(
    tcb_info_json: &[u8],
    tee_tcb_svn: &[u8; 16],
    pck_pem: &[u8],
    signing_certs_pem: Option<&[u8]>,
) -> Result<DcapVerificationStatus> {
    if let Some(certs_pem) = signing_certs_pem {
        verify_tcb_info_signature(tcb_info_json, certs_pem)?;
    } else {
        log::warn!("TCB Info signing chain not available; skipping signature verification on TCB collateral");
    }

    let wrapper: TcbInfoWrapper = serde_json::from_slice(tcb_info_json)
        .map_err(|e| AttestationError::CertChainError(format!("TCB Info JSON parse: {e}")))?;

    // Check if collateral has expired (nextUpdate is in the past). A missing
    // or unparseable nextUpdate is treated as EXPIRED: freshness evaluation of
    // a security-relevant field fails closed, so malformed or stripped
    // collateral cannot bypass the expiry gate.
    let collateral_expired = wrapper
        .tcb_info
        .next_update
        .as_deref()
        .and_then(|ts| {
            // Intel PCS uses ISO 8601: "2024-03-07T00:00:00Z"
            // Try common formats
            chrono_parse_is_past(ts)
        })
        .unwrap_or(true);
    if collateral_expired {
        log::warn!("TCB Info collateral has expired or nextUpdate is missing/unparseable");
    }

    let (pck_compsvn, pck_pcesvn) = extract_pck_tcb_components(pck_pem)?;
    let fmspc = extract_fmspc_from_pck(pck_pem)?;

    // TCB level matching (follows Intel DCAP QVL algorithm).
    //
    // Pass 1 — SGX match: find the first level where all PCK SGX component
    //   SVNs >= level SVNs and PCESVN >= level PCESVN.
    // Pass 2 — TDX match: starting from the SGX-matched level, find the first
    //   level where all tee_tcb_svn values >= level TDX component SVNs.
    //   When tdxtcbcomponents is absent from a level it is treated as a match
    //   (the level applies to all TDX TCB values).

    // Pass 1: find the first SGX-matching level index.
    let sgx_match_idx = wrapper
        .tcb_info
        .tcb_levels
        .iter()
        .position(|level| {
            let sgx_comps: Vec<u8> = level.tcb.sgxtcbcomponents.iter().map(|c| c.svn).collect();
            sgx_comps.len() >= 16
                && pck_compsvn
                    .iter()
                    .zip(sgx_comps.iter())
                    .all(|(&pck, &lvl)| pck >= lvl)
                && pck_pcesvn >= level.tcb.pcesvn
        })
        .ok_or_else(|| AttestationError::TcbMismatch("no matching SGX TCB level found".into()))?;

    // Pass 2: find the first TDX-matching level at or after the SGX match.
    let tee_tcb_svn_nonzero = tee_tcb_svn.iter().any(|&v| v != 0);
    if !tee_tcb_svn_nonzero {
        // All-zero tee_tcb_svn means the quote carries no TDX module TCB
        // information (e.g. early TDX implementations or SGX-only paths).
        // Skip TDX component matching and use the SGX-matched level directly.
        let level = &wrapper.tcb_info.tcb_levels[sgx_match_idx];
        let tcb_status = parse_tcb_status(&level.tcb_status)?;
        return Ok(DcapVerificationStatus {
            tcb_status,
            fmspc,
            advisory_ids: level.advisory_ids.clone(),
            collateral_expired,
        });
    }

    for level in &wrapper.tcb_info.tcb_levels[sgx_match_idx..] {
        let tdx_ok = match level.tcb.tdxtcbcomponents.as_ref() {
            Some(tdx_comps) => tdx_comps
                .iter()
                .zip(tee_tcb_svn.iter())
                .all(|(comp, &svn)| svn >= comp.svn),
            // When tdxtcbcomponents is absent the level applies universally
            None => true,
        };
        if tdx_ok {
            let tcb_status = parse_tcb_status(&level.tcb_status)?;
            return Ok(DcapVerificationStatus {
                tcb_status,
                fmspc,
                advisory_ids: level.advisory_ids.clone(),
                collateral_expired,
            });
        }
    }

    Err(AttestationError::TcbMismatch(
        "no matching TDX TCB level found".into(),
    ))
}

/// Check if an ISO 8601 timestamp (e.g. "2024-03-07T00:00:00Z") is in the past.
/// Returns `None` if the timestamp cannot be parsed.
fn chrono_parse_is_past(ts: &str) -> Option<bool> {
    let dt = chrono::DateTime::parse_from_rfc3339(ts.trim()).ok()?;
    Some(chrono::Utc::now() > dt)
}

/// Enforce the caller's TCB policy on an evaluated status. Default (both
/// flags false) is Intel's lenient appraisal profile: accept `UpToDate` plus
/// the hardening/configuration-needed statuses (advisories exist but are
/// addressed by software mitigations or platform configuration, not by a TCB
/// recovery), and reject `OutOfDate` / `OutOfDateConfigurationNeeded` (a TCB
/// recovery exists that resolves published advisories, so the platform is
/// simply unpatched) plus expired collateral. `Revoked` is always rejected.
/// Intel's strict profile accepts `UpToDate` only; relying parties that want
/// it can inspect the `tcb_status` surfaced on the verification result and
/// tighten further.
pub fn enforce_tcb_policy(
    status: &DcapVerificationStatus,
    allow_out_of_date_tcb: bool,
    allow_expired_collateral: bool,
) -> Result<()> {
    if status.collateral_expired && !allow_expired_collateral {
        return Err(AttestationError::CollateralExpired(
            "TCB Info nextUpdate is in the past".into(),
        ));
    }
    match status.tcb_status {
        TdxTcbStatus::UpToDate
        | TdxTcbStatus::SWHardeningNeeded
        | TdxTcbStatus::ConfigurationNeeded
        | TdxTcbStatus::ConfigurationAndSWHardeningNeeded => Ok(()),
        TdxTcbStatus::OutOfDate | TdxTcbStatus::OutOfDateConfigurationNeeded
            if allow_out_of_date_tcb =>
        {
            log::warn!("accepting out-of-date TDX TCB (allow_out_of_date_tcb)");
            Ok(())
        }
        other => Err(AttestationError::TcbMismatch(format!(
            "TDX TCB status is {other}"
        ))),
    }
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

/// Parsed QE Identity fields needed for verification.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnclaveIdentityFields {
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
    tcb_status: String,
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

/// Verify the Quoting Enclave identity against Intel's published QE Identity.
///
/// Checks that the QE report fields (MRSIGNER, ISVPRODID, ISVSVN,
/// MISCSELECT, ATTRIBUTES) match the values published by Intel.
///
/// `qe_report_body`: 384-byte QE report body from the quote auth data.
/// `qe_identity_json`: raw JSON response from Intel PCS QE Identity endpoint.
/// `signing_certs_pem`: optional PEM-encoded signing certificate chain from the
/// `SGX-Enclave-Identity-Issuer-Chain` response header. When provided,
/// the Intel signature is verified before use.
pub fn verify_qe_identity(
    qe_report_body: &[u8],
    qe_identity_json: &[u8],
    signing_certs_pem: Option<&[u8]>,
) -> Result<()> {
    if qe_report_body.len() < QE_REPORT_BODY_SIZE {
        return Err(AttestationError::QuoteParseFailed(format!(
            "QE report body too short: {} bytes, expected {}",
            qe_report_body.len(),
            QE_REPORT_BODY_SIZE
        )));
    }

    // Parse the envelope and optionally verify signature
    let envelope: QeIdentityEnvelope<'_> =
        serde_json::from_slice(qe_identity_json).map_err(|e| {
            AttestationError::CertChainError(format!("QE Identity envelope parse: {e}"))
        })?;

    if let Some(certs_pem) = signing_certs_pem {
        // Verify Intel ECDSA P-256 signature on the enclaveIdentity JSON
        let sig_bytes = hex::decode(&envelope.signature).map_err(|e| {
            AttestationError::CertChainError(format!("QE Identity signature hex decode: {e}"))
        })?;
        let signature = Signature::from_slice(&sig_bytes).map_err(|e| {
            AttestationError::CertChainError(format!("QE Identity signature parse: {e}"))
        })?;

        let signing_key = verify_signing_cert_chain(certs_pem)?;

        // RawValue preserves the exact bytes Intel signed — no re-serialization.
        signing_key
            .verify(envelope.enclave_identity.get().as_bytes(), &signature)
            .map_err(|e| {
                AttestationError::CertChainError(format!(
                    "QE Identity signature verification failed: {e}"
                ))
            })?;
    } else {
        log::warn!("QE Identity signing chain not available; skipping signature verification on QE Identity collateral");
    }

    // Parse the identity fields from the raw JSON
    let identity: EnclaveIdentityFields = serde_json::from_str(envelope.enclave_identity.get())
        .map_err(|e| AttestationError::CertChainError(format!("QE Identity fields parse: {e}")))?;

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

    // Check MRSIGNER (exact match)
    let expected_mrsigner = hex::decode(&identity.mrsigner).map_err(|e| {
        AttestationError::CertChainError(format!("QE Identity MRSIGNER hex decode: {e}"))
    })?;
    if !crate::utils::constant_time_eq(qe_mrsigner, &expected_mrsigner) {
        return Err(AttestationError::CertChainError(
            "QE MRSIGNER does not match Intel QE Identity".into(),
        ));
    }

    // Check ISVPRODID (exact match)
    if qe_isvprodid != identity.isvprodid {
        return Err(AttestationError::CertChainError(format!(
            "QE ISVPRODID {} does not match expected {}",
            qe_isvprodid, identity.isvprodid
        )));
    }

    // Check MISCSELECT (masked comparison)
    let expected_miscselect = hex::decode(&identity.miscselect).map_err(|e| {
        AttestationError::CertChainError(format!("QE Identity MISCSELECT hex decode: {e}"))
    })?;
    let miscselect_mask = hex::decode(&identity.miscselect_mask).map_err(|e| {
        AttestationError::CertChainError(format!("QE Identity MISCSELECT_MASK hex decode: {e}"))
    })?;
    if expected_miscselect.len() != 4 || miscselect_mask.len() != 4 {
        return Err(AttestationError::CertChainError(format!(
            "QE Identity MISCSELECT/mask unexpected length: {}/{}",
            expected_miscselect.len(),
            miscselect_mask.len()
        )));
    }
    for i in 0..4 {
        if (qe_miscselect[i] & miscselect_mask[i]) != (expected_miscselect[i] & miscselect_mask[i])
        {
            return Err(AttestationError::CertChainError(
                "QE MISCSELECT does not match Intel QE Identity (masked)".into(),
            ));
        }
    }

    // Check ATTRIBUTES (masked comparison)
    let expected_attributes = hex::decode(&identity.attributes).map_err(|e| {
        AttestationError::CertChainError(format!("QE Identity ATTRIBUTES hex decode: {e}"))
    })?;
    let attributes_mask = hex::decode(&identity.attributes_mask).map_err(|e| {
        AttestationError::CertChainError(format!("QE Identity ATTRIBUTES_MASK hex decode: {e}"))
    })?;
    if expected_attributes.len() != 16 || attributes_mask.len() != 16 {
        return Err(AttestationError::CertChainError(format!(
            "QE Identity ATTRIBUTES/mask unexpected length: {}/{}",
            expected_attributes.len(),
            attributes_mask.len()
        )));
    }
    for i in 0..16 {
        if (qe_attributes[i] & attributes_mask[i]) != (expected_attributes[i] & attributes_mask[i])
        {
            return Err(AttestationError::CertChainError(
                "QE ATTRIBUTES does not match Intel QE Identity (masked)".into(),
            ));
        }
    }

    // Check ISVSVN (>= highest matching TCB level)
    // Find the first TCB level where the QE ISVSVN is >= the level's ISVSVN
    let mut svn_ok = false;
    for level in &identity.tcb_levels {
        if qe_isvsvn >= level.tcb.isvsvn {
            // Reject revoked QE TCB levels
            if level.tcb_status == "Revoked" {
                return Err(AttestationError::CertChainError(
                    "QE TCB status is Revoked".into(),
                ));
            }
            svn_ok = true;
            break;
        }
    }
    if !svn_ok {
        return Err(AttestationError::CertChainError(format!(
            "QE ISVSVN {qe_isvsvn} does not meet any published TCB level"
        )));
    }

    Ok(())
}

/// Normalize CRL data to DER format.
///
/// Intel PCS v4 `pckcrl` endpoint returns PEM-encoded CRLs, while the
/// Root CA CRL endpoint returns raw DER. This function accepts either
/// format and always returns DER bytes.
fn normalize_crl_to_der(data: &[u8]) -> Result<Vec<u8>> {
    if crate::utils::is_pem(data) {
        crate::utils::decode_pem_to_der(data)
            .map_err(|_| AttestationError::CertChainError("CRL PEM decode failed".into()))
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
    if der_certs.len() < 2 {
        return Err(AttestationError::CertChainError(
            "need at least 2 certs to check intermediate CA revocation".into(),
        ));
    }

    // The intermediate CA is the 2nd cert in the chain
    let (_, intermediate_cert) = X509Certificate::from_der(&der_certs[1])
        .map_err(|e| AttestationError::CertChainError(format!("Intermediate CA parse: {e}")))?;
    let intermediate_serial = intermediate_cert.raw_serial();

    // Parse the Root CA CRL (handle both PEM and DER formats)
    let root_crl_der_bytes = normalize_crl_to_der(root_ca_crl_der)?;
    let (_, crl) = CertificateRevocationList::from_der(&root_crl_der_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("Root CA CRL parse: {e}")))?;

    // Check if intermediate serial is in the revoked list
    for revoked in crl.iter_revoked_certificates() {
        if revoked.raw_serial() == intermediate_serial {
            return Err(AttestationError::CertChainError(
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
    if der_certs.is_empty() {
        return Err(AttestationError::CertChainError(
            "no certificates found".into(),
        ));
    }

    // Parse the leaf cert to get its serial number
    let (_, leaf_cert) = X509Certificate::from_der(&der_certs[0])
        .map_err(|e| AttestationError::CertChainError(format!("PCK leaf parse: {e}")))?;
    let leaf_serial = leaf_cert.raw_serial();

    // Parse the CRL (handle both PEM and DER formats)
    let crl_der_bytes = normalize_crl_to_der(crl_der)?;
    let (_, crl) = CertificateRevocationList::from_der(&crl_der_bytes)
        .map_err(|e| AttestationError::CertChainError(format!("CRL DER parse: {e}")))?;

    // Check if leaf serial is in the revoked list
    for revoked in crl.iter_revoked_certificates() {
        if revoked.raw_serial() == leaf_serial {
            return Err(AttestationError::CertChainError(
                "PCK certificate has been revoked".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");
    const V5_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_5.dat");

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
    fn test_enforce_tcb_policy_truth_table() {
        use crate::types::TdxTcbStatus::*;

        let status = |tcb_status: TdxTcbStatus, collateral_expired: bool| DcapVerificationStatus {
            tcb_status,
            fmspc: "000000000000".to_string(),
            advisory_ids: vec![],
            collateral_expired,
        };

        // Fresh collateral, default policy (Intel's lenient appraisal
        // profile): UpToDate + hardening/config-needed statuses accepted.
        for s in [
            UpToDate,
            SWHardeningNeeded,
            ConfigurationNeeded,
            ConfigurationAndSWHardeningNeeded,
        ] {
            assert!(
                enforce_tcb_policy(&status(s, false), false, false).is_ok(),
                "{s} must be accepted by default"
            );
        }
        // OutOfDate* and Revoked rejected by default.
        for s in [OutOfDate, OutOfDateConfigurationNeeded, Revoked] {
            assert!(
                enforce_tcb_policy(&status(s, false), false, false).is_err(),
                "{s} must be rejected by default"
            );
        }
        // allow_out_of_date_tcb accepts OutOfDate* but never Revoked.
        assert!(enforce_tcb_policy(&status(OutOfDate, false), true, false).is_ok());
        assert!(
            enforce_tcb_policy(&status(OutOfDateConfigurationNeeded, false), true, false).is_ok()
        );
        assert!(
            enforce_tcb_policy(&status(Revoked, false), true, false).is_err(),
            "Revoked must always be rejected regardless of opt-ins"
        );
        // Expired collateral gates everything unless opted in — including
        // UpToDate, and including when out-of-date is separately allowed.
        assert!(enforce_tcb_policy(&status(UpToDate, true), false, false).is_err());
        assert!(enforce_tcb_policy(&status(OutOfDate, true), true, false).is_err());
        assert!(enforce_tcb_policy(&status(UpToDate, true), false, true).is_ok());
        assert!(enforce_tcb_policy(&status(OutOfDate, true), true, true).is_ok());
        assert!(
            enforce_tcb_policy(&status(Revoked, true), true, true).is_err(),
            "Revoked must always be rejected regardless of opt-ins"
        );
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
        let result = extract_pck_tcb_components(auth.pck_cert_chain_pem);
        assert!(
            result.is_ok(),
            "should extract PCK TCB components: {:?}",
            result.err()
        );
        let (compsvn, pcesvn) = result.unwrap();
        // At least some components should be non-zero in a real cert
        assert!(
            compsvn.iter().any(|&v| v != 0) || pcesvn != 0,
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
        let err = format!("{:?}", result.unwrap_err());
        assert!(err.contains("at least 2 certs"), "error: {err}");
    }

    #[test]
    fn test_chrono_parse_is_past() {
        // A date in the far past should return true (expired)
        assert_eq!(chrono_parse_is_past("2020-01-01T00:00:00Z"), Some(true));
        // A date in the far future should return false (not expired)
        assert_eq!(chrono_parse_is_past("2099-12-31T23:59:59Z"), Some(false));
        // Invalid format should return None
        assert_eq!(chrono_parse_is_past("invalid"), None);
        assert_eq!(chrono_parse_is_past(""), None);
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
        let result = verify_signing_cert_chain(two_cert_pem.as_bytes());
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
}
