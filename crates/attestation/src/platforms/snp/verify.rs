use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::{Decode, Reader};
use signature::Verifier as _;
use spki::DecodePublicKey;
use x509_parser::prelude::{CertificateRevocationList, FromDer as X509FromDer, X509Certificate};

use sev::certs::snp::{Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::types::{PlatformType, ProcessorGeneration, SnpTcb, VerificationResult, VerifyParams};

// x509-parser's verify_signature does not support RSASSA-PSS with parameters,
// which every AMD ARK uses to sign its CRL, so the `rsa` crate verifies it.
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";

use super::claims::extract_claims;
use super::evidence::SnpEvidence;

/// SNP Attestation Report version (must be >= 3 for cpuid fields).
pub const MIN_REPORT_VERSION: u32 = 3;

/// Maximum supported SNP report version: 6, SNP ABI 1.59, whose ETCB fields
/// are defined for Venice only.
pub const MAX_REPORT_VERSION: u32 = 6;

/// Verify SNP attestation evidence.
pub async fn verify_evidence(
    evidence: &SnpEvidence,
    params: &VerifyParams,
    cert_provider: &dyn CertProvider,
) -> Result<VerificationResult> {
    // 0. Input size validation
    crate::utils::check_field_size("attestation_report", evidence.attestation_report.len())?;

    // 1. Decode the attestation report
    let report_bytes = BASE64
        .decode(&evidence.attestation_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("base64 decode: {e}")))?;

    // 2. Parse, and read the fields the ABI fixes before the signature
    let report = parse_report(&report_bytes)?;
    let signing_key = report_signing_key(&report_bytes)?;

    // 3. Version check
    if report.version < MIN_REPORT_VERSION || report.version > MAX_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: MIN_REPORT_VERSION,
            max: MAX_REPORT_VERSION,
        });
    }

    // 4. Determine processor generation
    // v3+ reports are required to have CPUID fields; treat None as a spec violation.
    let cpuid_fam = match report.cpuid_fam_id {
        Some(v) => v,
        None if report.version >= 3 => {
            return Err(AttestationError::QuoteParseFailed(
                "v3+ SNP report missing cpuid_fam_id field".to_string(),
            ));
        }
        None => 0,
    };
    let cpuid_mod = match report.cpuid_mod_id {
        Some(v) => v,
        None if report.version >= 3 => {
            return Err(AttestationError::QuoteParseFailed(
                "v3+ SNP report missing cpuid_mod_id field".to_string(),
            ));
        }
        None => 0,
    };
    let processor_gen = ProcessorGeneration::from_cpuid(cpuid_fam, cpuid_mod).ok_or_else(|| {
        AttestationError::QuoteParseFailed(format!(
            "unknown processor: family=0x{cpuid_fam:02X}, model=0x{cpuid_mod:02X}"
        ))
    })?;

    // 5. Resolve VEK cert (VCEK or VLEK)
    let vcek_der = resolve_vcek(evidence, &report, processor_gen, cert_provider).await?;

    // 6. The chain SIGNING_KEY names, each certificate inside its window
    let now = chrono::Utc::now();
    let intermediate_der = verify_vek_chain_at(processor_gen, signing_key, &vcek_der, now)?;

    // 6c. CRL revocation check of the ASK/ASVK (if provider supplies CRL data)
    let crl_verified = if let Some(crl_der) = cert_provider.get_snp_crl(processor_gen).await? {
        check_chain_not_revoked_at(
            intermediate_der,
            &crl_der,
            super::certs::get_ark(processor_gen),
            now,
        )?;
        true
    } else {
        log::warn!("snp: CRL data not available from cert provider; skipping revocation check");
        false
    };

    // 7. Verify report signature against VEK, over the received bytes
    verify_report_signature(&report_bytes, &vcek_der)?;

    // 8. VMPL check
    if report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(report.vmpl));
    }

    // 8b. Debug policy enforcement
    if report.policy.debug_allowed() && !params.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }

    // 8c. VCEK OID cross-validation (chip_id + TCB SPLs)
    verify_vcek_tcb(&report, &vcek_der, processor_gen)?;

    // 8d. Minimum TCB enforcement
    if let Some(ref min_tcb) = params.min_tcb {
        enforce_min_tcb(&report.reported_tcb, min_tcb)?;
    }

    // 9. Check report_data binding
    let report_data_match = if let Some(expected) = &params.expected_report_data {
        let padded = crate::utils::pad_report_data(expected, 64)?;
        if !crate::utils::constant_time_eq(&report.report_data[..], &padded) {
            return Err(AttestationError::ReportDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // 10. Check init_data binding (host_data, 32 bytes)
    let init_data_match = if let Some(expected) = &params.expected_init_data_hash {
        let padded = crate::utils::pad_report_data(expected, 32)?;
        if !crate::utils::constant_time_eq(&report.host_data[..], &padded) {
            return Err(AttestationError::InitDataMismatch);
        }
        Some(true)
    } else {
        None
    };

    // Optional launch-digest compare. Mismatch surfaces in the result and
    // does not fail verification.
    let launch_digest_match = params
        .expected_launch_digest
        .as_ref()
        .map(|expected| crate::utils::constant_time_eq(&report.measurement[..], expected));

    // 11. Extract claims
    let claims = extract_claims(&report);

    Ok(VerificationResult {
        signature_valid: true,
        platform: PlatformType::Snp,
        claims,
        report_data_match,
        init_data_match,
        collateral_verified: crl_verified,
        tcb_status: None,
        mrtd_match: None,
        rtmr0_match: None,
        rtmr1_match: None,
        rtmr2_match: None,
        rtmr3_match: None,
        launch_digest_match,
    })
}

/// Enforce minimum TCB version requirements.
///
/// Shared between bare-metal SNP and Azure SNP verification paths.
pub fn enforce_min_tcb(tcb: &sev::firmware::host::TcbVersion, min_tcb: &SnpTcb) -> Result<()> {
    let fmc_below = match (min_tcb.fmc, tcb.fmc) {
        (Some(min_fmc), Some(report_fmc)) => report_fmc < min_fmc,
        (Some(_), None) => true, // min requires FMC but report doesn't have it
        _ => false,
    };
    if tcb.bootloader < min_tcb.bootloader
        || tcb.tee < min_tcb.tee
        || tcb.snp < min_tcb.snp
        || tcb.microcode < min_tcb.microcode
        || fmc_below
    {
        return Err(AttestationError::TcbMismatch(format!(
            "reported TCB ({}.{}.{}.{}) below minimum ({}.{}.{}.{})",
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode,
            min_tcb.bootloader,
            min_tcb.tee,
            min_tcb.snp,
            min_tcb.microcode,
        )));
    }
    Ok(())
}

/// Resolve the VCEK certificate - either from evidence or from cert provider.
async fn resolve_vcek(
    evidence: &SnpEvidence,
    report: &AttestationReport,
    processor_gen: ProcessorGeneration,
    cert_provider: &dyn CertProvider,
) -> Result<Vec<u8>> {
    if let Some(chain) = &evidence.cert_chain {
        // VCEK provided in evidence
        let vcek = BASE64
            .decode(&chain.vcek)
            .map_err(|e| AttestationError::CertChainError(format!("VCEK base64: {e}")))?;
        Ok(vcek)
    } else {
        // Guard: all-zeros chip_id means MASK_CHIP_ID was set, can't fetch from KDS
        if report.chip_id.iter().all(|&b| b == 0) {
            return Err(AttestationError::CertFetchError(
                "chip_id is all zeros in attestation report. \
                 Confirm that MASK_CHIP_ID is set to 0 to request VCEK from KDS."
                    .to_string(),
            ));
        }
        // Fetch from cert provider using report's TCB
        let tcb = SnpTcb {
            bootloader: report.reported_tcb.bootloader,
            tee: report.reported_tcb.tee,
            snp: report.reported_tcb.snp,
            microcode: report.reported_tcb.microcode,
            fmc: if processor_gen == ProcessorGeneration::Turin {
                Some(report.reported_tcb.fmc.ok_or_else(|| {
                    AttestationError::QuoteParseFailed(
                        "Turin report missing FMC TCB field".to_string(),
                    )
                })?)
            } else {
                None
            },
        };
        let mut chip_id = [0u8; 64];
        chip_id.copy_from_slice(&report.chip_id[..]);
        cert_provider
            .get_snp_vcek(processor_gen, &chip_id, &tcb)
            .await
    }
}

/// Verify the AMD certificate chain: ARK (self-signed) -> ASK -> VCEK.
/// Delegates to the sev crate's Verifiable trait.
pub fn verify_cert_chain(ark_der: &[u8], ask_der: &[u8], vcek_der: &[u8]) -> Result<()> {
    let chain = Chain::from_der(ark_der, ask_der, vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("chain parse: {e}")))?;
    chain
        .verify()
        .map_err(|e| AttestationError::CertChainError(format!("chain verify: {e}")))?;
    Ok(())
}

/// Verify a report's signature with a VEK over bytes 0x000 to 0x29F exactly
/// as received (standard section 9.1.4 step 3). The sev crate verifies over
/// a re-encoding of its parsed report, which writes the reserved bytes of the
/// TCB fields back as zero and so leaves them unauthenticated.
///
/// `SIGNATURE_ALGO` must be 1, and `R` and `S` are little-endian in the low
/// 48 bytes of their 72-byte fields, whose upper 24 bytes must be zero.
pub fn verify_report_signature(report_bytes: &[u8], vek_der: &[u8]) -> Result<()> {
    if report_bytes.len() != REPORT_LEN {
        return Err(AttestationError::QuoteParseFailed(format!(
            "SNP report is {} bytes, expected {REPORT_LEN}",
            report_bytes.len()
        )));
    }
    let algo = u32_at(report_bytes, SIGNATURE_ALGO_OFFSET);
    if algo != SIGNATURE_ALGO_ECDSA_P384_SHA384 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "SIGNATURE_ALGO {algo} is not 1 (ECDSA P-384 with SHA-384)"
        )));
    }
    let scalar = |offset: usize, name: &str| -> Result<p384::FieldBytes> {
        let field = &report_bytes[offset..offset + 72];
        if field[48..].iter().any(|b| *b != 0) {
            return Err(AttestationError::SignatureVerificationFailed(format!(
                "signature {name} has non-zero bytes above its low 48"
            )));
        }
        let mut be = [0u8; 48];
        for (dst, src) in be.iter_mut().zip(field[..48].iter().rev()) {
            *dst = *src;
        }
        Ok(be.into())
    };
    let signature = p384::ecdsa::Signature::from_scalars(
        scalar(SIG_R_OFFSET, "R")?,
        scalar(SIG_S_OFFSET, "S")?,
    )
    .map_err(|e| AttestationError::SignatureVerificationFailed(format!("report signature: {e}")))?;
    let (_, cert) = X509Certificate::from_der(vek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK x509 parse: {e}")))?;
    let key =
        p384::ecdsa::VerifyingKey::from_sec1_bytes(&cert.public_key().subject_public_key.data)
            .map_err(|e| {
                AttestationError::CertChainError(format!("VEK is not a P-384 key: {e}"))
            })?;
    key.verify(&report_bytes[..SIGNED_LEN], &signature)
        .map_err(|e| {
            AttestationError::SignatureVerificationFailed(format!(
                "the VEK does not sign the report: {e}"
            ))
        })
}

/// Verify a VEK (VCEK/VLEK) certificate's validity period at `now`.
pub fn verify_vek_validity_period_at(
    vek_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(vek_der).map_err(|e| {
        AttestationError::CertChainError(format!("VEK x509 parse for validity: {e}"))
    })?;
    let validity = cert.validity();
    let now = snp_asn1_time(now)?;
    if now < validity.not_before {
        return Err(AttestationError::CertChainError(format!(
            "VEK certificate is not yet valid (notBefore: {})",
            validity.not_before
        )));
    }
    if now > validity.not_after {
        return Err(AttestationError::CertChainError(format!(
            "VEK certificate has expired (notAfter: {})",
            validity.not_after
        )));
    }
    Ok(())
}

/// Verify the endorsement-key policy for an inline VEK against the bundled
/// AMD roots: the chain `SIGNING_KEY` names, every certificate's window, and
/// the VEK's chip-id/TCB cross-check against the report. Returns the ASK or
/// ASVK for [`check_chain_not_revoked`]. For callers that resolve the VEK
/// themselves (the wasm crate's pre-profile `verify_snp` export).
#[cfg_attr(not(feature = "unstable-internals"), allow(dead_code))]
pub fn verify_vek_endorsement(
    report_bytes: &[u8],
    report: &AttestationReport,
    vek_der: &[u8],
    processor_gen: ProcessorGeneration,
) -> Result<&'static [u8]> {
    let signing_key = report_signing_key(report_bytes)?;
    let intermediate =
        verify_vek_chain_at(processor_gen, signing_key, vek_der, chrono::Utc::now())?;
    verify_vcek_tcb(report, vek_der, processor_gen)?;
    Ok(intermediate)
}

/// Check if a VEK certificate is a VLEK (versioned loaded endorsement key)
/// by examining its Common Name.
pub(crate) fn is_vlek_cert(vek_der: &[u8]) -> Result<bool> {
    let (_, cert) = X509Certificate::from_der(vek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK x509 parse: {e}")))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| {
            AttestationError::CertChainError("VEK certificate has no Common Name".to_string())
        })?
        .as_str()
        .map_err(|e| {
            AttestationError::CertChainError(format!("VEK Common Name is not valid UTF-8: {e}"))
        })?;
    Ok(cn.contains("VLEK"))
}

// --- VCEK OID cross-validation ---
// OID constants from AMD SEV-SNP ABI specification
const HW_ID_OID: &str = "1.3.6.1.4.1.3704.1.4";
const UCODE_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.8";
const SNP_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.3";
const TEE_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.2";
const LOADER_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.1";
const FMC_SPL_OID: &str = "1.3.6.1.4.1.3704.1.3.9";

/// Extract a u8 integer value from a DER-encoded extension value.
/// AMD VCEK TCB extensions encode SPL values as DER INTEGERs.
fn get_oid_int(ext_value: &[u8]) -> Option<u8> {
    <u8 as Decode>::from_der(ext_value).ok()
}

/// The hardware ID a VCEK's HW_ID extension carries: the extension value is
/// exactly the `len`-byte ID (the form Azure's VCEKs carry), or a DER OCTET
/// STRING whose content is exactly `len` bytes (AMD 57230). The two forms
/// differ in length, so the length decides; an ID whose first bytes happen to
/// read as an OCTET STRING header is still taken whole.
fn hardware_id(ext_value: &[u8], len: usize) -> Option<&[u8]> {
    if ext_value.len() == len {
        return Some(ext_value);
    }
    match der::asn1::OctetStringRef::from_der(ext_value) {
        Ok(octets) if octets.as_bytes().len() == len => Some(octets.as_bytes()),
        _ => None,
    }
}

/// Verify VCEK certificate TCB extensions match the SNP attestation report.
///
/// - For "VCEK" certificates: validates chip_id and TCB SPL exact equality.
/// - For "VLEK" certificates: skips chip_id check, only validates TCB SPLs.
///
/// `processor_gen` sets the hardware ID's length: 8 bytes on Turin, which
/// must equal the first 8 bytes of a chip_id whose rest is zero, and the full
/// 64-byte chip_id on Milan and Genoa.
pub fn verify_vcek_tcb(
    report: &AttestationReport,
    vcek_der: &[u8],
    processor_gen: ProcessorGeneration,
) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK x509 parse: {e}")))?;

    // Check common name to determine if this is VCEK or VLEK
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| {
            AttestationError::CertChainError("VCEK certificate has no Common Name".to_string())
        })?
        .as_str()
        .map_err(|e| {
            AttestationError::CertChainError(format!("VCEK Common Name is not valid UTF-8: {e}"))
        })?;

    let is_vcek = !cn.contains("VLEK");

    // Validate chip_id only for VCEK (not VLEK)
    if is_vcek {
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_string() == HW_ID_OID)
            .ok_or_else(|| {
                AttestationError::TcbMismatch(
                    "VCEK missing required HW_ID OID extension".to_string(),
                )
            })?;
        // Turin's hardware ID is the first 8 bytes of CHIP_ID, whose other 56
        // bytes are zero; Milan and Genoa carry all 64.
        let hwid_len = if processor_gen == ProcessorGeneration::Turin {
            8
        } else {
            report.chip_id.len()
        };
        let hwid = hardware_id(ext.value, hwid_len).ok_or_else(|| {
            AttestationError::TcbMismatch(format!(
                "VCEK HW_ID is neither {hwid_len} bytes nor an OCTET STRING of {hwid_len} bytes"
            ))
        })?;
        let ok = crate::utils::constant_time_eq(hwid, &report.chip_id[..hwid_len])
            && report.chip_id[hwid_len..].iter().all(|b| *b == 0);
        if !ok {
            return Err(AttestationError::TcbMismatch(
                "VCEK chip_id does not match report chip_id".to_string(),
            ));
        }
    }

    // Validate TCB SPL values (exact equality)
    let checks: &[(&str, u8, &str)] = &[
        (LOADER_SPL_OID, report.reported_tcb.bootloader, "bootloader"),
        (TEE_SPL_OID, report.reported_tcb.tee, "tee"),
        (SNP_SPL_OID, report.reported_tcb.snp, "snp"),
        (UCODE_SPL_OID, report.reported_tcb.microcode, "microcode"),
    ];

    for &(oid_str, expected, name) in checks {
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_string() == oid_str)
            .ok_or_else(|| {
                AttestationError::TcbMismatch(format!(
                    "VCEK missing required OID extension: {name}"
                ))
            })?;
        let cert_val = get_oid_int(ext.value).ok_or_else(|| {
            AttestationError::TcbMismatch(format!("VCEK {name} OID has unparseable value"))
        })?;
        if cert_val != expected {
            return Err(AttestationError::TcbMismatch(format!(
                "VCEK {name} SPL {cert_val} does not match report {expected}"
            )));
        }
    }

    // Turin processors have an additional FMC SPL OID
    if let Some(fmc_expected) = report.reported_tcb.fmc {
        if let Some(ext) = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_string() == FMC_SPL_OID)
        {
            let cert_val = get_oid_int(ext.value).ok_or_else(|| {
                AttestationError::TcbMismatch("VCEK FMC OID has unparseable value".to_string())
            })?;
            if cert_val != fmc_expected {
                return Err(AttestationError::TcbMismatch(format!(
                    "VCEK fmc SPL {cert_val} does not match report {fmc_expected}"
                )));
            }
        } else if fmc_expected != 0 {
            // Non-zero FMC in the report but VCEK lacks the OID — the cert cannot
            // attest to the platform's FMC level, so reject.
            return Err(AttestationError::TcbMismatch(format!(
                "report FMC SPL is {fmc_expected} but VCEK certificate lacks FMC OID extension"
            )));
        }
    }

    Ok(())
}

/// Check a chain's ASK or ASVK against the generation's AMD CRL (standard
/// section 9.1.4 step 5). The CRL is signed by the ARK and must be inside its
/// window. VCEK serial numbers are zero (AMD 57230, Table 9), so the CRL
/// revokes intermediates and never an individual VCEK.
///
/// `intermediate_der`: the ASK or ASVK the chain used.
/// `crl_der`: DER-encoded CRL from AMD KDS.
/// `ark_der`: the generation's ARK, which signs the CRL.
#[cfg_attr(
    not(any(feature = "az-snp", feature = "unstable-internals")),
    allow(dead_code)
)]
pub fn check_chain_not_revoked(
    intermediate_der: &[u8],
    crl_der: &[u8],
    ark_der: &[u8],
) -> Result<()> {
    check_chain_not_revoked_at(intermediate_der, crl_der, ark_der, chrono::Utc::now())
}

/// `now` as the type x509-parser compares against.
fn snp_asn1_time(now: chrono::DateTime<chrono::Utc>) -> Result<x509_parser::time::ASN1Time> {
    x509_parser::time::ASN1Time::from_timestamp(now.timestamp())
        .map_err(|e| AttestationError::CertChainError(format!("evaluation time: {e}")))
}

/// [`check_chain_not_revoked`] with the CRL window judged at `now`.
pub fn check_chain_not_revoked_at(
    intermediate_der: &[u8],
    crl_der: &[u8],
    ark_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let (_, ark) = X509Certificate::from_der(ark_der)
        .map_err(|e| AttestationError::CertChainError(format!("ARK x509 parse: {e}")))?;
    let (_, crl) = CertificateRevocationList::from_der(crl_der)
        .map_err(|e| AttestationError::CollateralInvalid(format!("AMD CRL parse: {e}")))?;
    verify_crl_signature(&crl, crl_der, &ark)?;

    // 3b. Freshness: a genuine but stale CRL must not vouch for a VEK that a
    // newer list may have revoked. AMD CRLs always carry nextUpdate; one
    // without it has no defined shelf life, so it is rejected rather than
    // trusted forever.
    let now = snp_asn1_time(now)?;
    if crl.last_update() > now {
        return Err(AttestationError::CollateralInvalid(format!(
            "AMD CRL thisUpdate {} is in the future",
            crl.last_update()
        )));
    }
    match crl.next_update() {
        None => {
            return Err(AttestationError::CollateralInvalid(
                "AMD CRL has no nextUpdate; refusing a revocation list with no defined freshness"
                    .into(),
            ));
        }
        Some(next_update) if next_update < now => {
            return Err(AttestationError::CollateralInvalid(format!(
                "AMD CRL is stale: nextUpdate {next_update} has passed; fetch a current CRL"
            )));
        }
        Some(_) => {}
    }

    let (_, intermediate) = X509Certificate::from_der(intermediate_der).map_err(|e| {
        AttestationError::CertChainError(format!("ASK/ASVK x509 parse for CRL: {e}"))
    })?;
    let serial = intermediate.raw_serial();
    if crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == serial)
    {
        return Err(AttestationError::Revoked(format!(
            "AMD's CRL revokes {} (serial {})",
            intermediate.subject(),
            hex::encode(serial)
        )));
    }
    Ok(())
}

/// Extract the TBSCertList raw DER bytes from a CRL DER blob.
///
/// A CRL in DER is: SEQUENCE { TBSCertList, signatureAlgorithm, signatureValue }
/// The signed data is the raw DER encoding of the first element (TBSCertList).
///
/// Uses the `der` crate for ASN.1 parsing instead of hand-rolling DER decoding.
/// x509-parser's `TbsCertList` does not expose raw bytes publicly.
fn extract_tbs_from_crl_der(crl_der: &[u8]) -> Result<&[u8]> {
    let mut reader = der::SliceReader::new(crl_der)
        .map_err(|e| AttestationError::CollateralInvalid(format!("CRL DER: {e}")))?;
    // Skip past the outer SEQUENCE tag+length to reach its content
    let header = der::Header::decode(&mut reader)
        .map_err(|e| AttestationError::CollateralInvalid(format!("CRL DER header: {e}")))?;
    header
        .tag
        .assert_eq(der::Tag::Sequence)
        .map_err(|e| AttestationError::CollateralInvalid(format!("CRL: expected SEQUENCE: {e}")))?;
    // First element inside the SEQUENCE is TBSCertList
    reader
        .tlv_bytes()
        .map_err(|e| AttestationError::CollateralInvalid(format!("CRL TBS extract: {e}")))
}

/// Verify an AMD CRL's signature with the ARK: RSASSA-PSS with SHA-384 as the
/// hash and the MGF1 hash and a 48-byte salt, for every generation (AMD
/// 57230, Table 7: every ARK is an RSA-4096 key).
fn verify_crl_signature(
    crl: &CertificateRevocationList,
    crl_der: &[u8],
    ark: &X509Certificate,
) -> Result<()> {
    let sig_alg_oid = crl.signature_algorithm.algorithm.to_string();
    if sig_alg_oid != OID_RSA_PSS {
        return Err(AttestationError::CollateralInvalid(format!(
            "AMD CRL signature algorithm {sig_alg_oid} is not RSASSA-PSS"
        )));
    }
    let tbs_der = extract_tbs_from_crl_der(crl_der)?;
    let rsa_pub = rsa::RsaPublicKey::from_public_key_der(ark.public_key().raw)
        .map_err(|e| AttestationError::CollateralInvalid(format!("ARK RSA key parse: {e}")))?;
    let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha384>::new(rsa_pub);
    let sig = rsa::pss::Signature::try_from(crl.signature_value.as_ref()).map_err(|e| {
        AttestationError::CollateralInvalid(format!("CRL RSA-PSS signature parse: {e}"))
    })?;
    verifying_key.verify(tbs_der, &sig).map_err(|e| {
        AttestationError::CollateralInvalid(format!(
            "CRL RSA-PSS signature verification failed: {e}"
        ))
    })
}

/// Length of an SEV-SNP `ATTESTATION_REPORT` (SNP ABI 56860, Table 27).
pub const REPORT_LEN: usize = 1184;
/// The report signature covers bytes 0x000 to 0x29F.
const SIGNED_LEN: usize = 0x2A0;
const SIGNATURE_ALGO_OFFSET: usize = 0x34;
const KEY_INFO_OFFSET: usize = 0x48;
const SIG_R_OFFSET: usize = 0x2A0;
const SIG_S_OFFSET: usize = 0x2E8;
/// ECDSA P-384 with SHA-384 (SNP ABI Appendix B, the only encoding defined).
const SIGNATURE_ALGO_ECDSA_P384_SHA384: u32 = 1;
/// Version 6 extended TCB fields (CURRENT, LAUNCH, COMMITTED ETCB), defined
/// for Venice only and not interpreted for Milan, Genoa and Turin.
const ETCB_RANGE: std::ops::Range<usize> = 0x220..0x280;
const CPUID_FAM_OFFSET: usize = 0x188;
const CPUID_MOD_OFFSET: usize = 0x189;

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Parse an SNP attestation report from raw bytes into the sev crate's view.
///
/// sev 7.1 refuses two layouts the SNP ABI and AMD 57230 allow: a version 6
/// report with non-zero ETCB fields (it parses version 6 as version 5, whose
/// bytes 0x208 to 0x29F must be zero), and a Turin model above 0x11 (57230
/// section 1.5 gives Turin models 0x00 to 0x1F). It parses a copy with the
/// ETCB fields zeroed and such a model clamped, then restores the model. The
/// signature is always verified over the received bytes
/// ([`verify_report_signature`]), so the copy only feeds field extraction.
pub fn parse_report(report_bytes: &[u8]) -> Result<AttestationReport> {
    if report_bytes.len() != REPORT_LEN {
        return Err(AttestationError::QuoteParseFailed(format!(
            "SNP report is {} bytes, expected {REPORT_LEN}",
            report_bytes.len()
        )));
    }
    let version = u32_at(report_bytes, 0);
    let family = report_bytes[CPUID_FAM_OFFSET];
    let model = report_bytes[CPUID_MOD_OFFSET];
    let turin_model_above_sev = version >= 3 && family == 0x1A && (0x12..=0x1F).contains(&model);
    let parsed = if version == 6 || turin_model_above_sev {
        let mut copy = report_bytes.to_vec();
        if version == 6 {
            copy[ETCB_RANGE].fill(0);
        }
        if turin_model_above_sev {
            copy[CPUID_MOD_OFFSET] = 0x11;
        }
        AttestationReport::from_bytes(&copy)
    } else {
        AttestationReport::from_bytes(report_bytes)
    };
    let mut report =
        parsed.map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {e}")))?;
    if report.cpuid_mod_id.is_some() {
        report.cpuid_mod_id = Some(model);
    }
    Ok(report)
}

/// The key a report names in `KEY_INFO.SIGNING_KEY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKey {
    Vcek,
    Vlek,
}

/// The fields the SNP ABI fixes before a report's signature can mean
/// anything (standard section 9.1.2): `SIGNATURE_ALGO` is 1, `KEY_INFO` bits
/// 31:6 are zero, `MASK_CHIP_KEY` is 0 (the firmware signed the report), and
/// `SIGNING_KEY` is a VCEK (0) or a VLEK (1). ABI 1.59's chip-secret VCEK (2)
/// is refused in version 1, as are the reserved values and "none" (7).
pub fn report_signing_key(report_bytes: &[u8]) -> Result<SigningKey> {
    if report_bytes.len() != REPORT_LEN {
        return Err(AttestationError::QuoteParseFailed(format!(
            "SNP report is {} bytes, expected {REPORT_LEN}",
            report_bytes.len()
        )));
    }
    let algo = u32_at(report_bytes, SIGNATURE_ALGO_OFFSET);
    if algo != SIGNATURE_ALGO_ECDSA_P384_SHA384 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "SIGNATURE_ALGO {algo} is not 1 (ECDSA P-384 with SHA-384)"
        )));
    }
    let key_info = u32_at(report_bytes, KEY_INFO_OFFSET);
    if key_info >> 6 != 0 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "KEY_INFO {key_info:#x} sets reserved bits 31:6"
        )));
    }
    if key_info & 0b10 != 0 {
        return Err(AttestationError::QuoteParseFailed(
            "MASK_CHIP_KEY is set: the firmware did not sign this report".into(),
        ));
    }
    match (key_info >> 2) & 0b111 {
        0 => Ok(SigningKey::Vcek),
        1 => Ok(SigningKey::Vlek),
        2 => Err(AttestationError::QuoteParseFailed(
            "SIGNING_KEY 2 (chip-secret VCEK) is not accepted in version 1".into(),
        )),
        7 => Err(AttestationError::QuoteParseFailed(
            "SIGNING_KEY 7: the report names no signing key".into(),
        )),
        other => Err(AttestationError::QuoteParseFailed(format!(
            "SIGNING_KEY {other} is reserved"
        ))),
    }
}

/// Authenticate a VEK for a report whose `KEY_INFO` names `signing_key`
/// (standard section 9.1.4 steps 1 and 2): ARK to ASK for a VCEK or to ASVK
/// for a VLEK, the VEK's own certificate agreeing with the report, and the
/// ARK, the intermediate and the VEK each inside its window at `now`.
/// Returns the intermediate, whose serial the CRL is checked against.
pub fn verify_vek_chain_at(
    generation: ProcessorGeneration,
    signing_key: SigningKey,
    vek_der: &[u8],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<&'static [u8]> {
    let cert_is_vlek = is_vlek_cert(vek_der)?;
    // Fixed text: the key kind is never formatted into an error that callers log.
    if cert_is_vlek != (signing_key == SigningKey::Vlek) {
        return Err(AttestationError::CertChainError(
            if cert_is_vlek {
                "the report's SIGNING_KEY names a VCEK and the endorsement certificate is a VLEK"
            } else {
                "the report's SIGNING_KEY names a VLEK and the endorsement certificate is a VCEK"
            }
            .into(),
        ));
    }
    let ark_der = super::certs::get_ark(generation);
    let intermediate_der = match signing_key {
        SigningKey::Vcek => super::certs::get_ask(generation),
        SigningKey::Vlek => super::certs::get_asvk(generation),
    };
    verify_cert_chain(ark_der, intermediate_der, vek_der)?;
    cert_in_window_at(ark_der, "ARK", now)?;
    cert_in_window_at(intermediate_der, "ASK/ASVK", now)?;
    cert_in_window_at(vek_der, "VEK", now)?;
    Ok(intermediate_der)
}

fn cert_in_window_at(der: &[u8], label: &str, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| AttestationError::CertChainError(format!("{label} x509 parse: {e}")))?;
    let validity = cert.validity();
    let now = snp_asn1_time(now)?;
    if now < validity.not_before {
        return Err(AttestationError::CertChainError(format!(
            "{label} certificate is not yet valid (notBefore: {})",
            validity.not_before
        )));
    }
    if now > validity.not_after {
        return Err(AttestationError::CertChainError(format!(
            "{label} certificate has expired (notAfter: {})",
            validity.not_after
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use sev::certs::snp::Certificate;

    // Load real test fixtures at compile time
    const TEST_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-report.bin");
    const TEST_VCEK: &[u8] = include_bytes!("../../../test_data/snp/test-vcek.der");

    // Live Genoa v5 fixtures captured from this machine
    const LIVE_REPORT_V5: &[u8] = include_bytes!("../../../test_data/snp/live-report-v5-genoa.bin");
    const LIVE_VCEK_GENOA: &[u8] = include_bytes!("../../../test_data/snp/live-vcek-genoa.der");
    const TEST_VLEK_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-vlek-report.bin");
    const TEST_VCEK_INVALID_LEGACY: &[u8] =
        include_bytes!("../../../test_data/snp/test-vcek-invalid-legacy.der");
    const TEST_VCEK_INVALID_NEW: &[u8] =
        include_bytes!("../../../test_data/snp/test-vcek-invalid-new.der");

    // Azure IMDS real certificates (Milan)
    const IMDS_VCEK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-vcek.der");
    const IMDS_ASK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-chain-0.der");
    const IMDS_ARK: &[u8] = include_bytes!("../../../test_data/az_snp/imds-chain-1.der");

    #[test]
    fn test_parse_report_fields() {
        let report = parse_report(TEST_REPORT).expect("failed to parse report");
        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 4);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.sig_algo, 1);

        // Policy
        assert_eq!(report.policy.abi_minor(), 31);
        assert_eq!(report.policy.abi_major(), 0);
        assert!(report.policy.smt_allowed());
        assert!(!report.policy.migrate_ma_allowed());
        assert!(!report.policy.debug_allowed());
        assert!(!report.policy.single_socket_required());

        // Platform info
        assert!(report.plat_info.smt_enabled());
        assert!(!report.plat_info.tsme_enabled());

        // TCB
        assert_eq!(report.reported_tcb.bootloader, 3);
        assert_eq!(report.reported_tcb.tee, 0);
        assert_eq!(report.reported_tcb.snp, 8);
        assert_eq!(report.reported_tcb.microcode, 115);

        // Version 2 has no CPUID fields
        assert!(report.cpuid_fam_id.is_none() || report.cpuid_fam_id == Some(0));
        assert!(report.cpuid_mod_id.is_none() || report.cpuid_mod_id == Some(0));
    }

    #[test]
    fn test_parse_vlek_report() {
        let report = parse_report(TEST_VLEK_REPORT).expect("failed to parse VLEK report");
        assert_eq!(report.version, 3);
        assert_eq!(report.guest_svn, 0);
        assert_eq!(report.vmpl, 1);
        assert_eq!(report.sig_algo, 1);
        assert!(report.measurement.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_parse_report_too_short() {
        let data = vec![0u8; 100];
        assert!(parse_report(&data).is_err());
    }

    // ---------------------------------------------------------------
    // Certificate chain tests
    // ---------------------------------------------------------------

    #[test]
    fn test_cert_chain_validation_milan() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK);
        assert!(
            result.is_ok(),
            "Milan cert chain should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_cert_chain_wrong_generation_fails() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK);
        assert!(result.is_err(), "wrong generation certs should fail");
    }

    #[test]
    fn test_cert_chain_invalid_vcek_legacy() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK_INVALID_LEGACY);
        assert!(result.is_err(), "invalid legacy VCEK should fail");
    }

    #[test]
    fn test_cert_chain_invalid_vcek_new() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, TEST_VCEK_INVALID_NEW);
        assert!(result.is_err(), "invalid new VCEK should fail");
    }

    // ---------------------------------------------------------------
    // Report signature tests
    // ---------------------------------------------------------------

    #[test]
    fn test_report_signature_valid() {
        let result = verify_report_signature(TEST_REPORT, TEST_VCEK);
        assert!(
            result.is_ok(),
            "report signature should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_report_tamper_detection() {
        let mut tampered = TEST_REPORT.to_vec();
        tampered[0x90] ^= 0xFF; // Flip byte in measurement
        let result = verify_report_signature(&tampered, TEST_VCEK);
        assert!(result.is_err(), "tampered report should fail sig check");
    }

    #[test]
    fn test_signature_tamper_detection() {
        let mut tampered = TEST_REPORT.to_vec();
        tampered[0x2A0] ^= 0xFF; // Flip byte in signature R
        let result = verify_report_signature(&tampered, TEST_VCEK);
        assert!(result.is_err(), "tampered signature should fail");
    }

    // ---------------------------------------------------------------
    // Azure IMDS real certificate tests
    // ---------------------------------------------------------------

    #[test]
    fn test_imds_full_cert_chain() {
        let result = verify_cert_chain(IMDS_ARK, IMDS_ASK, IMDS_VCEK);
        assert!(
            result.is_ok(),
            "IMDS cert chain should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_imds_bundled_certs_verify() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Milan);
        let result = verify_cert_chain(ark_der, ask_der, IMDS_VCEK);
        assert!(
            result.is_ok(),
            "IMDS VCEK against bundled certs: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------
    // Live Genoa v5 tests
    // ---------------------------------------------------------------

    #[test]
    fn test_live_v5_report_parses() {
        assert_eq!(LIVE_REPORT_V5.len(), 1184);
        let report = parse_report(LIVE_REPORT_V5).expect("live v5 parse");
        assert_eq!(report.version, 5);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.sig_algo, 1);
        assert_eq!(report.cpuid_fam_id, Some(0x19));
        assert_eq!(report.cpuid_mod_id, Some(0xA0));
        let gen = ProcessorGeneration::from_cpuid(
            report.cpuid_fam_id.unwrap(),
            report.cpuid_mod_id.unwrap(),
        );
        assert_eq!(gen, Some(ProcessorGeneration::Genoa));
    }

    #[test]
    fn test_live_v5_genoa_cert_chain() {
        let (ark_der, ask_der) = super::super::certs::get_bundled_certs(ProcessorGeneration::Genoa);
        let result = verify_cert_chain(ark_der, ask_der, LIVE_VCEK_GENOA);
        assert!(
            result.is_ok(),
            "Genoa cert chain should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_live_v5_report_signature() {
        let result = verify_report_signature(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        assert!(
            result.is_ok(),
            "live v5 sig should verify: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------
    // DER OID parsing helper tests
    // ---------------------------------------------------------------

    #[test]
    fn test_get_oid_int_single_byte() {
        // DER INTEGER: tag=0x02, len=0x01, value
        assert_eq!(get_oid_int(&[0x02, 0x01, 0x73]), Some(115));
        assert_eq!(get_oid_int(&[0x02, 0x01, 0x00]), Some(0));
        assert_eq!(get_oid_int(&[0x02, 0x01, 0x7F]), Some(127));
        // 0xFF unpadded is -1 in DER signed integer — must use 2-byte padded form
        assert_eq!(get_oid_int(&[0x02, 0x01, 0xFF]), None);
    }

    #[test]
    fn test_get_oid_int_two_byte_padded() {
        // Values > 127 need a leading 0x00 pad in DER to stay positive.
        // DER INTEGER: tag=0x02, len=0x02, value=0x00DB (219)
        assert_eq!(get_oid_int(&[0x02, 0x02, 0x00, 0xDB]), Some(219));
        assert_eq!(get_oid_int(&[0x02, 0x02, 0x00, 0x80]), Some(128));
        assert_eq!(get_oid_int(&[0x02, 0x02, 0x00, 0xFF]), Some(255));
    }

    #[test]
    fn test_get_oid_int_invalid() {
        assert_eq!(get_oid_int(&[]), None);
        assert_eq!(get_oid_int(&[0x04, 0x01, 0x00]), None); // wrong tag
        assert_eq!(get_oid_int(&[0x02]), None); // truncated
        assert_eq!(get_oid_int(&[0x02, 0x00]), None); // zero-length is invalid DER
                                                      // 3-byte value doesn't fit in u8
        assert_eq!(get_oid_int(&[0x02, 0x03, 0x01, 0x00, 0x00]), None);
    }

    #[test]
    fn hardware_id_is_the_raw_value_or_an_octet_string_of_its_length() {
        for len in [64usize, 8] {
            let raw: Vec<u8> = (0..len as u8).map(|b| b ^ 0x5a).collect();
            assert_eq!(hardware_id(&raw, len), Some(raw.as_slice()), "raw {len}");
            let wrapped = [&[0x04, len as u8][..], &raw].concat();
            assert_eq!(
                hardware_id(&wrapped, len),
                Some(raw.as_slice()),
                "DER {len}"
            );
            // Any other length is neither form.
            assert_eq!(hardware_id(&raw[1..], len), None);
            assert_eq!(hardware_id(&[&raw[..], &[0]].concat(), len), None);
            let short = [&[0x04, len as u8 - 1][..], &raw[1..]].concat();
            assert_eq!(hardware_id(&short, len), None);
        }
        assert_eq!(hardware_id(&[], 64), None);
    }

    #[test]
    fn a_raw_hardware_id_that_reads_as_an_octet_string_header_is_taken_whole() {
        // 04 3E then 62 bytes is also a well-formed OCTET STRING of 62 bytes.
        let mut genoa = [0x11u8; 64];
        genoa[..2].copy_from_slice(&[0x04, 0x3E]);
        assert_eq!(hardware_id(&genoa, 64), Some(&genoa[..]));
        // Turin's 8-byte ID beginning 04 06 reads as an OCTET STRING of 6.
        let turin = [0x04, 0x06, 1, 2, 3, 4, 5, 6];
        assert_eq!(hardware_id(&turin, 8), Some(&turin[..]));
    }

    // ---------------------------------------------------------------
    // TCB cross-validation tests
    // ---------------------------------------------------------------

    #[test]
    fn test_verify_vcek_tcb_milan() {
        let report = parse_report(TEST_REPORT).expect("parse report");
        let result = verify_vcek_tcb(&report, TEST_VCEK, ProcessorGeneration::Milan);
        assert!(
            result.is_ok(),
            "Milan VCEK TCB should verify: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_verify_vcek_tcb_genoa() {
        let report = parse_report(LIVE_REPORT_V5).expect("parse report");
        let result = verify_vcek_tcb(&report, LIVE_VCEK_GENOA, ProcessorGeneration::Genoa);
        assert!(
            result.is_ok(),
            "Genoa VCEK TCB should verify: {:?}",
            result.err()
        );
    }

    // ---------------------------------------------------------------
    // VLEK / ASVK tests
    // ---------------------------------------------------------------

    #[test]
    fn test_is_vlek_vcek_detection() {
        // Regular VCEK should not be detected as VLEK
        assert!(!is_vlek_cert(TEST_VCEK).unwrap(), "VCEK should not be VLEK");
        assert!(
            !is_vlek_cert(LIVE_VCEK_GENOA).unwrap(),
            "Genoa VCEK should not be VLEK"
        );
        assert!(
            !is_vlek_cert(IMDS_VCEK).unwrap(),
            "IMDS VCEK should not be VLEK"
        );
    }

    #[test]
    fn test_asvk_certs_parse() {
        // Verify ASVK certs for all generations can be parsed
        for gen in [
            ProcessorGeneration::Milan,
            ProcessorGeneration::Genoa,
            ProcessorGeneration::Turin,
        ] {
            let asvk_der = super::super::certs::get_asvk(gen);
            let cert = x509_cert::Certificate::from_der(asvk_der)
                .unwrap_or_else(|e| panic!("{gen:?} ASVK parse failed: {e}"));
            let subject = format!("{}", cert.tbs_certificate.subject);
            assert!(
                subject.contains("VLEK"),
                "{gen:?} ASVK subject should contain VLEK"
            );
        }
    }

    #[test]
    fn test_asvk_chain_validates() {
        // ARK → ASVK chain should verify for all generations
        // (We can't do full chain verify without a real VLEK cert, but we can
        // verify the ARK → ASVK link)
        for gen in [
            ProcessorGeneration::Milan,
            ProcessorGeneration::Genoa,
            ProcessorGeneration::Turin,
        ] {
            let ark_der = super::super::certs::get_ark(gen);
            let asvk_der = super::super::certs::get_asvk(gen);
            // Parse via sev crate to verify the crypto
            let ark = Certificate::from_der(ark_der)
                .unwrap_or_else(|e| panic!("{gen:?} ARK sev parse: {e}"));
            let asvk = Certificate::from_der(asvk_der)
                .unwrap_or_else(|e| panic!("{gen:?} ASVK sev parse: {e}"));
            // ARK should verify ASVK
            (&ark, &asvk)
                .verify()
                .unwrap_or_else(|e| panic!("{gen:?} ARK->ASVK verify failed: {e}"));
        }
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_crl_signature_verification_milan() {
        let client = reqwest::Client::new();
        let url = crate::collateral::snp_crl_url(ProcessorGeneration::Milan);
        let resp = client.get(&url).send().await.unwrap();
        let crl_der = resp.bytes().await.unwrap().to_vec();

        // AMD CRLs are signed by the ARK (root), not the ASK
        let ark_der = super::super::certs::get_ark(ProcessorGeneration::Milan);
        let (_, ark_cert) = X509Certificate::from_der(ark_der).unwrap();
        let (_, crl) = CertificateRevocationList::from_der(&crl_der).unwrap();

        eprintln!("CRL sig algo OID: {}", crl.signature_algorithm.algorithm);
        eprintln!("CRL issuer: {}", crl.issuer());

        let result = verify_crl_signature(&crl, &crl_der, &ark_cert);
        assert!(
            result.is_ok(),
            "Milan CRL sig verify failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_crl_signature_verification_genoa() {
        let client = reqwest::Client::new();
        let url = crate::collateral::snp_crl_url(ProcessorGeneration::Genoa);
        let resp = client.get(&url).send().await.unwrap();
        let crl_der = resp.bytes().await.unwrap().to_vec();

        // AMD CRLs are signed by the ARK (root), not the ASK
        let ark_der = super::super::certs::get_ark(ProcessorGeneration::Genoa);
        let (_, ark_cert) = X509Certificate::from_der(ark_der).unwrap();
        let (_, crl) = CertificateRevocationList::from_der(&crl_der).unwrap();

        eprintln!("CRL sig algo OID: {}", crl.signature_algorithm.algorithm);

        let result = verify_crl_signature(&crl, &crl_der, &ark_cert);
        assert!(
            result.is_ok(),
            "Genoa CRL sig verify failed: {:?}",
            result.err()
        );
    }

    // expected_launch_digest tests against the live Genoa v5 fixture.

    /// Cert provider that returns the bundled live Genoa VCEK from the
    /// fixture. No network access, no CRL (so collateral_verified=false).
    struct StubCertProvider;

    #[async_trait::async_trait]
    impl crate::collateral::CertProvider for StubCertProvider {
        async fn get_snp_vcek(
            &self,
            _processor_gen: ProcessorGeneration,
            _chip_id: &[u8; 64],
            _reported_tcb: &SnpTcb,
        ) -> Result<Vec<u8>> {
            Ok(LIVE_VCEK_GENOA.to_vec())
        }

        async fn get_snp_cert_chain(
            &self,
            _processor_gen: ProcessorGeneration,
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            // Not used — the bare-metal SNP path uses bundled ARK/ASK directly.
            Err(AttestationError::CertFetchError(
                "stub provider does not serve full chain".to_string(),
            ))
        }
    }

    fn make_snp_evidence_with_vcek(report: &[u8], vcek_der: &[u8]) -> SnpEvidence {
        use crate::platforms::snp::evidence::SnpCertChain;
        SnpEvidence {
            attestation_report: BASE64.encode(report),
            cert_chain: Some(SnpCertChain {
                vcek: BASE64.encode(vcek_der),
                ask: None,
                ark: None,
            }),
        }
    }

    #[tokio::test]
    async fn test_verify_evidence_no_expected_launch_digest_yields_none() {
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let provider = StubCertProvider;
        let r = verify_evidence(&evidence, &VerifyParams::default(), &provider)
            .await
            .expect("live v5 fixture should verify");
        assert!(r.launch_digest_match.is_none(), "no expected_* → None");
        assert!(r.mrtd_match.is_none(), "SNP never sets mrtd_match");
        assert!(r.rtmr0_match.is_none(), "SNP never sets rtmrN_match");
        assert!(r.rtmr1_match.is_none());
        assert!(r.rtmr2_match.is_none());
        assert!(r.rtmr3_match.is_none());
    }

    #[tokio::test]
    async fn test_verify_evidence_matching_launch_digest() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut expected = [0u8; 48];
        expected.copy_from_slice(&report.measurement[..]);

        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let provider = StubCertProvider;
        let params = VerifyParams {
            expected_launch_digest: Some(expected),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, &provider)
            .await
            .unwrap();
        assert_eq!(r.launch_digest_match, Some(true));
    }

    // ---------------------------------------------------------------
    // Endorsement policy negative tests: VEK validity, TCB floor, and
    // CRL revocation/freshness, with rcgen-minted certificates and CRLs
    // (an ARK-signed CRL naming a fixture serial cannot be produced, so
    // the CRL contract is proven against a test issuer instead).
    // ---------------------------------------------------------------

    use time::macros::datetime;
    use time::{Duration as TimeDuration, OffsetDateTime};

    fn mint_issuer(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        (params.self_signed(&key).unwrap(), key)
    }

    fn mint_leaf(serial: &[u8], not_before: OffsetDateTime, not_after: OffsetDateTime) -> Vec<u8> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        params.not_before = not_before;
        params.not_after = not_after;
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn mint_crl(
        issuer: &(rcgen::Certificate, rcgen::KeyPair),
        revoked_serial: Option<&[u8]>,
        this_update: OffsetDateTime,
        next_update: OffsetDateTime,
    ) -> Vec<u8> {
        let params = rcgen::CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: rcgen::SerialNumber::from(1234u64),
            issuing_distribution_point: None,
            revoked_certs: revoked_serial
                .map(|serial| {
                    vec![rcgen::RevokedCertParams {
                        serial_number: rcgen::SerialNumber::from_slice(serial),
                        revocation_time: this_update,
                        reason_code: None,
                        invalidity_date: None,
                    }]
                })
                .unwrap_or_default(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        params
            .signed_by(&issuer.0, &issuer.1)
            .unwrap()
            .der()
            .to_vec()
    }

    const LEAF_SERIAL: &[u8] = &[0x01, 0x02, 0x03, 0x04];

    fn valid_window() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (now - TimeDuration::days(1), now + TimeDuration::days(1))
    }

    #[test]
    fn test_vek_expired_rejected() {
        let leaf = mint_leaf(
            LEAF_SERIAL,
            datetime!(2020-01-01 0:00 UTC),
            datetime!(2021-01-01 0:00 UTC),
        );
        let err = verify_vek_validity_period_at(&leaf, chrono::Utc::now())
            .expect_err("expired VEK must be rejected");
        assert!(
            err.to_string().contains("expired"),
            "the expired VEK must be refused as expired"
        );
    }

    #[test]
    fn test_vek_not_yet_valid_rejected() {
        let leaf = mint_leaf(
            LEAF_SERIAL,
            datetime!(2100-01-01 0:00 UTC),
            datetime!(2101-01-01 0:00 UTC),
        );
        let err = verify_vek_validity_period_at(&leaf, chrono::Utc::now())
            .expect_err("future VEK must be rejected");
        assert!(
            err.to_string().contains("not yet valid"),
            "the future VEK must be refused as not yet valid"
        );
    }

    #[test]
    fn test_vek_current_accepted() {
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        verify_vek_validity_period_at(&leaf, chrono::Utc::now()).expect("current VEK must pass");
    }

    /// AMD's ARK-signed Genoa CRL: thisUpdate 2026-08-19, nextUpdate
    /// 2026-10-04, revoking serial 020001 (the original Genoa ASK).
    const GENOA_CRL: &[u8] = include_bytes!("../../../test_data/snp/genoa-crl-2026-08-19.der");

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().unwrap()
    }

    /// The bundled Genoa ASK (serial 020002) with its serial rewritten to the
    /// revoked 020001; the revocation check reads the serial alone.
    fn genoa_ask_with_revoked_serial() -> Vec<u8> {
        let mut der = super::super::certs::get_ask(ProcessorGeneration::Genoa).to_vec();
        let serial = [0x02, 0x03, 0x02, 0x00, 0x02];
        let at = der.windows(5).position(|w| w == serial).unwrap();
        der[at + 4] = 0x01;
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert_eq!(cert.raw_serial(), [0x02, 0x00, 0x01]);
        der
    }

    #[test]
    fn crl_revokes_the_chains_ask() {
        let ark = super::super::certs::get_ark(ProcessorGeneration::Genoa);
        let now = at("2026-09-22T00:00:00Z");
        let err = check_chain_not_revoked_at(&genoa_ask_with_revoked_serial(), GENOA_CRL, ark, now)
            .expect_err("the CRL revokes ASK 020001");
        assert!(matches!(err, AttestationError::Revoked(_)), "got: {err}");
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        check_chain_not_revoked_at(ask, GENOA_CRL, ark, now).expect("ASK 020002 is not revoked");
        // VCEK serial numbers are zero; the CRL is not searched for them.
        let (_, vcek) = X509Certificate::from_der(LIVE_VCEK_GENOA).unwrap();
        assert_eq!(vcek.raw_serial(), [0x00]);
    }

    #[test]
    fn crl_outside_its_window_is_refused() {
        let ark = super::super::certs::get_ark(ProcessorGeneration::Genoa);
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        let stale = check_chain_not_revoked_at(ask, GENOA_CRL, ark, at("2026-10-05T00:00:00Z"))
            .expect_err("stale CRL");
        assert!(stale.to_string().contains("stale"), "got: {stale}");
        let early = check_chain_not_revoked_at(ask, GENOA_CRL, ark, at("2026-08-18T00:00:00Z"))
            .expect_err("CRL from the future");
        assert!(early.to_string().contains("future"), "got: {early}");
    }

    #[test]
    fn crl_signed_by_another_ark_is_refused() {
        // The forged-empty-CRL bypass: a CRL whose signature the ARK does not verify.
        let milan_ark = super::super::certs::get_ark(ProcessorGeneration::Milan);
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        let err = check_chain_not_revoked_at(ask, GENOA_CRL, milan_ark, at("2026-09-22T00:00:00Z"))
            .expect_err("CRL signed by another ARK");
        assert!(
            matches!(err, AttestationError::CollateralInvalid(_)),
            "got: {err}"
        );
    }

    #[test]
    fn crl_signed_with_ecdsa_is_refused() {
        // Every ARK is an RSA-4096 key; a CRL under any other algorithm is refused.
        let issuer = mint_issuer("TEST-ARK");
        let (not_before, not_after) = valid_window();
        let crl = mint_crl(&issuer, None, not_before, not_after);
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        let err = check_chain_not_revoked(ask, &crl, issuer.0.der()).expect_err("ECDSA CRL");
        assert!(err.to_string().contains("is not RSASSA-PSS"), "got: {err}");
    }

    #[test]
    fn the_hardware_id_must_equal_the_report_chip_id() {
        let mut report = parse_report(LIVE_REPORT_V5).expect("parse report");
        report.chip_id[63] ^= 1;
        let err = verify_vcek_tcb(&report, LIVE_VCEK_GENOA, ProcessorGeneration::Genoa)
            .expect_err("another chip's VCEK");
        assert!(err.to_string().contains("chip_id"), "got: {err}");
        // Read as Turin, the 64-byte ID is neither form of an 8-byte one.
        let report = parse_report(LIVE_REPORT_V5).expect("parse report");
        let err = verify_vcek_tcb(&report, LIVE_VCEK_GENOA, ProcessorGeneration::Turin)
            .expect_err("a 64-byte ID under Turin");
        assert!(err.to_string().contains("neither 8 bytes"), "got: {err}");
    }

    #[test]
    fn test_vcek_tcb_report_mismatch_rejected() {
        let mut report = parse_report(LIVE_REPORT_V5).expect("parse report");
        report.reported_tcb.microcode = report.reported_tcb.microcode.wrapping_add(1);
        let err = verify_vcek_tcb(&report, LIVE_VCEK_GENOA, ProcessorGeneration::Genoa)
            .expect_err("VEK/report TCB disagreement must be rejected");
        assert!(
            matches!(err, AttestationError::TcbMismatch(_)),
            "got: {err}"
        );
    }

    #[test]
    fn test_enforce_min_tcb_at_floor_passes() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let tcb = &report.reported_tcb;
        let floor = SnpTcb {
            bootloader: tcb.bootloader,
            tee: tcb.tee,
            snp: tcb.snp,
            microcode: tcb.microcode,
            fmc: None,
        };
        enforce_min_tcb(tcb, &floor).expect("reported TCB at the floor must pass");
    }

    #[test]
    fn test_enforce_min_tcb_below_floor_rejected() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let tcb = &report.reported_tcb;
        let floor = SnpTcb {
            bootloader: tcb.bootloader,
            tee: tcb.tee,
            snp: tcb.snp,
            microcode: tcb.microcode + 1,
            fmc: None,
        };
        let err = enforce_min_tcb(tcb, &floor).expect_err("below-floor TCB must be rejected");
        assert!(err.to_string().contains("below minimum"), "got: {err}");
    }

    #[test]
    fn test_enforce_min_tcb_fmc_required_but_absent_rejected() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let tcb = &report.reported_tcb;
        assert!(tcb.fmc.is_none(), "Genoa reports carry no FMC");
        let floor = SnpTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
            fmc: Some(1),
        };
        enforce_min_tcb(tcb, &floor)
            .expect_err("a floor requiring FMC must reject a report without it");
    }

    #[tokio::test]
    async fn test_verify_evidence_wrong_launch_digest_is_some_false() {
        // Wrong digest must record Some(false) without failing verification.
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let provider = StubCertProvider;
        let params = VerifyParams {
            expected_launch_digest: Some([0xAA; 48]),
            ..Default::default()
        };
        let r = verify_evidence(&evidence, &params, &provider)
            .await
            .unwrap();
        assert_eq!(r.launch_digest_match, Some(false));
        assert!(r.signature_valid, "wrong digest should NOT fail signature");
    }

    // ---------------------------------------------------------------
    // Standard section 9.1: the signature over the received bytes, the
    // fields the ABI fixes, the chain SIGNING_KEY names and its windows,
    // version 6 and the Turin models.
    // ---------------------------------------------------------------

    fn genoa_vcek_now() -> chrono::DateTime<chrono::Utc> {
        at("2026-09-22T00:00:00Z")
    }

    fn with_u32(report: &[u8], offset: usize, value: u32) -> Vec<u8> {
        let mut r = report.to_vec();
        r[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        r
    }

    #[test]
    fn the_signature_covers_the_reserved_bytes_of_a_tcb_field() {
        // Byte 2 of REPORTED_TCB is reserved on Genoa. The sev crate drops it
        // when parsing and verifies a re-encoding that writes it back as zero,
        // so it accepts the altered report; the received bytes do not verify.
        let mut altered = LIVE_REPORT_V5.to_vec();
        altered[0x180 + 2] = 1;
        let parsed = parse_report(&altered).unwrap();
        let vek = Certificate::from_der(LIVE_VCEK_GENOA).unwrap();
        assert!((&vek, &parsed).verify().is_ok(), "sev re-encodes the field");
        let err = verify_report_signature(&altered, LIVE_VCEK_GENOA).unwrap_err();
        assert!(
            matches!(err, AttestationError::SignatureVerificationFailed(_)),
            "got: {err}"
        );
        verify_report_signature(LIVE_REPORT_V5, LIVE_VCEK_GENOA).expect("the genuine report");
    }

    #[test]
    fn signature_scalars_have_zero_upper_bytes() {
        for offset in [SIG_R_OFFSET + 48, SIG_S_OFFSET + 71] {
            let mut altered = LIVE_REPORT_V5.to_vec();
            altered[offset] = 1;
            let err = verify_report_signature(&altered, LIVE_VCEK_GENOA).unwrap_err();
            assert!(err.to_string().contains("above its low 48"), "got: {err}");
        }
    }

    #[test]
    fn signature_algo_must_be_ecdsa_p384() {
        for algo in [0, 2] {
            let altered = with_u32(LIVE_REPORT_V5, SIGNATURE_ALGO_OFFSET, algo);
            assert!(matches!(
                report_signing_key(&altered),
                Err(AttestationError::QuoteParseFailed(_))
            ));
            assert!(matches!(
                verify_report_signature(&altered, LIVE_VCEK_GENOA),
                Err(AttestationError::QuoteParseFailed(_))
            ));
        }
    }

    #[test]
    fn key_info_names_a_vcek_or_a_vlek() {
        assert_eq!(
            report_signing_key(LIVE_REPORT_V5).unwrap(),
            SigningKey::Vcek
        );
        assert_eq!(
            report_signing_key(TEST_VLEK_REPORT).unwrap(),
            SigningKey::Vlek
        );
        // SIGNING_KEY 2 (chip-secret VCEK), 3 (reserved), 7 (none); MASK_CHIP_KEY; bit 6.
        for key_info in [2 << 2, 3 << 2, 7 << 2, 0b10, 1 << 6, 1 << 31] {
            let altered = with_u32(LIVE_REPORT_V5, KEY_INFO_OFFSET, key_info);
            assert!(
                matches!(
                    report_signing_key(&altered),
                    Err(AttestationError::QuoteParseFailed(_))
                ),
                "KEY_INFO {key_info:#x} accepted"
            );
        }
        // Bit 5 is reserved without must-be-zero in ABI 1.59; AUTHOR_KEY_EN is bit 0.
        for key_info in [1 << 5, 1] {
            let altered = with_u32(LIVE_REPORT_V5, KEY_INFO_OFFSET, key_info);
            assert_eq!(report_signing_key(&altered).unwrap(), SigningKey::Vcek);
        }
    }

    #[test]
    fn the_vek_must_be_the_key_signing_key_names() {
        let err = verify_vek_chain_at(
            ProcessorGeneration::Genoa,
            SigningKey::Vlek,
            LIVE_VCEK_GENOA,
            genoa_vcek_now(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, AttestationError::CertChainError(m) if m.contains("names a VLEK and the endorsement certificate is a VCEK")),
            "a VCEK under SIGNING_KEY 1 must be refused as a chain error"
        );
        let vlek = include_bytes!("../../../test_data/snp/test-vlek.der");
        let err = verify_vek_chain_at(
            ProcessorGeneration::Milan,
            SigningKey::Vcek,
            vlek,
            at("2025-06-01T00:00:00Z"),
        )
        .unwrap_err();
        assert!(
            matches!(&err, AttestationError::CertChainError(m) if m.contains("names a VCEK and the endorsement certificate is a VLEK")),
            "a VLEK under SIGNING_KEY 0 must be refused as a chain error"
        );
        let intermediate = verify_vek_chain_at(
            ProcessorGeneration::Genoa,
            SigningKey::Vcek,
            LIVE_VCEK_GENOA,
            genoa_vcek_now(),
        )
        .unwrap();
        assert_eq!(
            intermediate,
            super::super::certs::get_ask(ProcessorGeneration::Genoa)
        );
        let intermediate = verify_vek_chain_at(
            ProcessorGeneration::Milan,
            SigningKey::Vlek,
            vlek,
            at("2025-06-01T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(
            intermediate,
            super::super::certs::get_asvk(ProcessorGeneration::Milan)
        );
    }

    #[test]
    fn the_ark_and_the_ask_are_judged_at_the_evaluation_time() {
        // The Genoa ARK expires 2047-01-26 and its ASK 2047-10-31.
        let err = verify_vek_chain_at(
            ProcessorGeneration::Genoa,
            SigningKey::Vcek,
            LIVE_VCEK_GENOA,
            at("2047-06-01T00:00:00Z"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("ARK certificate has expired"),
            "the expired Genoa ARK must be refused"
        );
        // The Turin ASK is valid from 2023-05-15.
        let turin_ask = super::super::certs::get_ask(ProcessorGeneration::Turin);
        let err = cert_in_window_at(turin_ask, "ASK/ASVK", at("2023-01-01T00:00:00Z")).unwrap_err();
        assert!(err.to_string().contains("not yet valid"), "got: {err}");
        cert_in_window_at(turin_ask, "ASK/ASVK", genoa_vcek_now()).unwrap();
    }

    #[test]
    fn version_6_reports_parse_with_their_etcb_fields() {
        assert_eq!(MAX_REPORT_VERSION, 6);
        let mut v6 = with_u32(LIVE_REPORT_V5, 0, 6);
        v6[0x220] = 0x11;
        v6[0x27F] = 0x22;
        assert!(
            AttestationReport::from_bytes(&v6).is_err(),
            "sev 7.1 refuses non-zero ETCB bytes"
        );
        let report = parse_report(&v6).unwrap();
        assert_eq!(report.version, 6);
        assert_eq!(
            report.measurement,
            parse_report(LIVE_REPORT_V5).unwrap().measurement
        );
        // The reserved bytes around the ETCB fields must still be zero.
        for offset in [0x208, 0x21F, 0x280, 0x29F] {
            let mut bad = v6.clone();
            bad[offset] = 1;
            assert!(parse_report(&bad).is_err(), "byte {offset:#x} accepted");
        }
        // In version 5 the same bytes are must-be-zero.
        let mut v5 = LIVE_REPORT_V5.to_vec();
        v5[0x220] = 0x11;
        assert!(parse_report(&v5).is_err());
    }

    #[test]
    fn turin_models_above_0x11_parse() {
        let mut turin = with_u32(LIVE_REPORT_V5, 0, 5);
        turin[CPUID_FAM_OFFSET] = 0x1A;
        turin[CPUID_MOD_OFFSET] = 0x15;
        assert!(
            AttestationReport::from_bytes(&turin).is_err(),
            "sev 7.1 caps Turin at 0x11"
        );
        let report = parse_report(&turin).unwrap();
        assert_eq!(report.cpuid_fam_id, Some(0x1A));
        assert_eq!(report.cpuid_mod_id, Some(0x15));
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x15),
            Some(ProcessorGeneration::Turin)
        );
        turin[CPUID_MOD_OFFSET] = 0x20;
        assert!(parse_report(&turin).is_err());
    }

    #[test]
    fn reports_of_another_length_are_refused() {
        for len in [REPORT_LEN - 1, REPORT_LEN + 1] {
            let mut r = LIVE_REPORT_V5.to_vec();
            r.resize(len, 0);
            assert!(parse_report(&r).is_err());
            assert!(report_signing_key(&r).is_err());
            assert!(verify_report_signature(&r, LIVE_VCEK_GENOA).is_err());
        }
    }
}
