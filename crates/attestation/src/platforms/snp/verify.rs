use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::{Decode, Reader};
use signature::Verifier as _;
use spki::DecodePublicKey;
use x509_parser::prelude::{CertificateRevocationList, FromDer as X509FromDer, X509Certificate};

use sev::certs::snp::{Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

use serde::{Deserialize, Serialize};

use crate::collateral::CertProvider;
use crate::context::Context;
use crate::error::{AttestationError, Result};
use crate::platform::Platform;
use crate::types::{Claims, PlatformType, ProcessorGeneration, SnpTcb};

// OID constants for CRL signature algorithm identification.
// x509-parser's verify_signature does not support OID_RSA_PSS (rsaPSS with parameters),
// which Milan ARK uses for CRL signing. We dispatch on OID and verify with the `rsa`
// and `p384` crates directly.
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";

use super::claims::extract_claims;
use super::evidence::SnpEvidence;

/// SNP Attestation Report version (must be >= 3 for cpuid fields).
const MIN_REPORT_VERSION: u32 = 3;

/// Maximum supported SNP report version.
/// Matches Trustee's upper bound — future versions may change field layout.
pub const MAX_REPORT_VERSION: u32 = 5;

/// What a caller can ask of SEV-SNP evidence.
#[derive(Debug, Clone, Default)]
pub struct SnpParams {
    /// Expected `report_data` (at most 64 bytes, zero-padded). Result in
    /// [`SnpResult::report_data_match`]. On Azure (vTPM) this is checked
    /// against the vTPM quote nonce instead.
    pub report_data: Option<Vec<u8>>,
    /// Expected HOST_DATA (at most 32 bytes, zero-padded). On Azure (vTPM) a
    /// 32-byte init-data hash checked against PCR[8].
    pub host_data: Option<Vec<u8>>,
    /// Allowed launch digests (`report.measurement`): the measurement must
    /// equal one of them. Must not be empty.
    pub launch_digest: Option<Vec<[u8; 48]>>,
    /// Accept a guest whose policy allows debug. Default: false.
    pub allow_debug: bool,
    /// Minimum reported TCB; each component must be at least this.
    pub min_tcb: Option<SnpTcb>,
    /// Highest VMPL accepted. Default: 0.
    pub max_vmpl: u32,
}

impl SnpParams {
    /// Reject params that cannot be applied. Runs before any collateral is
    /// fetched, so caller misuse is never reported as a retryable error.
    pub fn validate(&self) -> Result<()> {
        if self.report_data.as_ref().is_some_and(|d| d.len() > 64) {
            return Err(AttestationError::ReportDataTooLarge { max: 64 });
        }
        if self.host_data.as_ref().is_some_and(|d| d.len() > 32) {
            return Err(AttestationError::InvalidParams(
                "host_data exceeds 32 bytes".into(),
            ));
        }
        crate::utils::check_allowed_set("launch_digest", self.launch_digest.as_deref())
    }
}

/// The answer for genuine SEV-SNP evidence. Every `*_match` is `None` when
/// the params did not ask, `Some(false)` on a mismatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[must_use]
pub struct SnpResult {
    pub claims: Claims,
    pub report_data_match: Option<bool>,
    pub host_data_match: Option<bool>,
    pub launch_digest_match: Option<bool>,
    /// The guest policy allows debug.
    pub debug: bool,
    /// The params allowed a debug guest.
    pub allow_debug: bool,
    /// VMPL the report was requested from.
    pub vmpl: u32,
    /// The highest VMPL the params accept.
    pub max_vmpl: u32,
    /// TCB the report was signed under.
    pub reported_tcb: SnpTcb,
    /// `reported_tcb` is at or above `min_tcb` (`None` if no minimum given).
    pub min_tcb_met: Option<bool>,
    /// The AMD CRL does not revoke the VEK's issuing ASK/ASVK (`None` when no
    /// CRL was checked: offline, or a provider without CRLs).
    pub crl_ok: Option<bool>,
}

impl SnpResult {
    /// True when the evidence satisfied every rule in the params.
    pub fn passed(&self) -> bool {
        crate::platform::all_held(&[
            self.report_data_match,
            self.host_data_match,
            self.launch_digest_match,
            self.min_tcb_met,
            self.crl_ok,
        ]) && (!self.debug || self.allow_debug)
            && self.vmpl <= self.max_vmpl
    }
}

/// Evaluate the params' report rules (launch digest, debug, VMPL, minimum
/// TCB) on a report whose signature has already been verified.
/// `report_data_match` and `host_data_match` are left `None`: where those
/// values live depends on the platform (report or vTPM).
pub fn evaluate_report(
    report: &AttestationReport,
    params: &SnpParams,
    crl_ok: Option<bool>,
) -> SnpResult {
    let reported_tcb = snp_tcb(&report.reported_tcb);
    SnpResult {
        claims: extract_claims(report),
        report_data_match: None,
        host_data_match: None,
        launch_digest_match: crate::utils::match_any(
            &report.measurement[..],
            params.launch_digest.as_deref(),
        ),
        debug: report.policy.debug_allowed(),
        allow_debug: params.allow_debug,
        vmpl: report.vmpl,
        max_vmpl: params.max_vmpl,
        min_tcb_met: params
            .min_tcb
            .as_ref()
            .map(|min| min_tcb_met(&reported_tcb, min)),
        reported_tcb,
        crl_ok,
    }
}

fn snp_tcb(tcb: &sev::firmware::host::TcbVersion) -> SnpTcb {
    SnpTcb {
        bootloader: tcb.bootloader,
        tee: tcb.tee,
        snp: tcb.snp,
        microcode: tcb.microcode,
        fmc: tcb.fmc,
    }
}

/// Bare-metal AMD SEV-SNP.
pub struct Snp;

impl Platform for Snp {
    const KIND: PlatformType = PlatformType::Snp;
    type Evidence = SnpEvidence;
    type Params = SnpParams;
    type Result = SnpResult;

    async fn verify(
        evidence: &SnpEvidence,
        params: &SnpParams,
        ctx: &Context,
    ) -> Result<SnpResult> {
        params.validate()?;
        let now = ctx.now();
        let cert_provider = ctx.cert_provider();

        // 0. Input size validation
        crate::utils::check_field_size("attestation_report", evidence.attestation_report.len())?;

        // 1. Decode the attestation report
        let report_bytes = BASE64
            .decode(&evidence.attestation_report)
            .map_err(|e| AttestationError::EvidenceDeserialize(format!("base64 decode: {e}")))?;

        // 2. Parse with sev crate
        let report = AttestationReport::from_bytes(&report_bytes)
            .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {e}")))?;

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
        let processor_gen =
            ProcessorGeneration::from_cpuid(cpuid_fam, cpuid_mod).ok_or_else(|| {
                AttestationError::QuoteParseFailed(format!(
                    "unknown processor: family=0x{cpuid_fam:02X}, model=0x{cpuid_mod:02X}"
                ))
            })?;

        // 5. Resolve VEK cert (VCEK or VLEK)
        let vcek_der = resolve_vcek(evidence, &report, processor_gen, cert_provider).await?;

        // 6. VEK endorsement: chain to the bundled AMD roots (VLEK
        // auto-detected), validity period, chip-id/TCB OIDs against the report
        verify_vek_endorsement(&report, &vcek_der, processor_gen, now)?;

        // 7. Verify report signature against VEK
        let vek = Certificate::from_der(&vcek_der).map_err(|e| {
            AttestationError::CertChainError(format!("VEK to sev Certificate: {e}"))
        })?;
        (&vek, &report)
            .verify()
            .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{e}")))?;

        // 8. CRL revocation check (if the provider supplies a CRL), only once
        // the evidence is known to be genuine, so a forged report is never
        // reported as retryable. A CRL the provider could not fetch is
        // CollateralUnavailable.
        let crl_ok = match cert_provider.get_snp_crl(processor_gen).await? {
            Some(crl_der) => Some(check_vek_against_crl(
                &vcek_der,
                &crl_der,
                processor_gen,
                now,
            )?),
            None => {
                log::warn!(
                    "snp: CRL data not available from cert provider; skipping revocation check"
                );
                None
            }
        };

        // 9. The params' rules: VMPL, debug, minimum TCB, launch digest
        let mut result = evaluate_report(&report, params, crl_ok);

        // 10. report_data and HOST_DATA bindings
        check_report_bindings(&mut result, &report, params)?;

        Ok(result)
    }
}

/// Compare the report's `report_data` and HOST_DATA with the params (each
/// zero-padded, constant-time) into `result`.
pub fn check_report_bindings(
    result: &mut SnpResult,
    report: &AttestationReport,
    params: &SnpParams,
) -> Result<()> {
    let matches = |expected: Option<&[u8]>, actual: &[u8]| {
        expected
            .map(|e| {
                let padded = crate::utils::pad_report_data(e, actual.len())?;
                Ok::<_, AttestationError>(crate::utils::constant_time_eq(actual, &padded))
            })
            .transpose()
    };
    result.report_data_match = matches(params.report_data.as_deref(), &report.report_data[..])?;
    result.host_data_match = matches(params.host_data.as_deref(), &report.host_data[..])?;
    Ok(())
}

/// True when every component of `tcb` is at or above `min_tcb` (including FMC
/// when the minimum names one).
///
/// Shared between bare-metal SNP and Azure SNP verification paths.
pub fn min_tcb_met(tcb: &SnpTcb, min_tcb: &SnpTcb) -> bool {
    let fmc_below = match (min_tcb.fmc, tcb.fmc) {
        (Some(min_fmc), Some(report_fmc)) => report_fmc < min_fmc,
        (Some(_), None) => true, // min requires FMC but report doesn't have it
        _ => false,
    };
    !(tcb.bootloader < min_tcb.bootloader
        || tcb.tee < min_tcb.tee
        || tcb.snp < min_tcb.snp
        || tcb.microcode < min_tcb.microcode
        || fmc_below)
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
            return Err(AttestationError::CertChainError(
                "evidence carries no VEK and chip_id is all zeros in attestation report. \
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

/// Verify a report signature against a VCEK certificate.
/// Delegates to the sev crate's Verifiable trait.
pub fn verify_report_signature(report_bytes: &[u8], vcek_der: &[u8]) -> Result<()> {
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {e}")))?;
    let vek = Certificate::from_der(vcek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VCEK parse: {e}")))?;
    (&vek, &report)
        .verify()
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{e}")))?;
    Ok(())
}

/// Verify a VEK (VCEK/VLEK) certificate's validity period (notBefore/notAfter)
/// at `now` (Unix seconds).
pub fn verify_vek_validity_period(vek_der: &[u8], now: i64) -> Result<()> {
    let (_, cert) = X509Certificate::from_der(vek_der).map_err(|e| {
        AttestationError::CertChainError(format!("VEK x509 parse for validity: {e}"))
    })?;
    let validity = cert.validity();
    let now = crate::utils::asn1_time(now)?;
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

/// Verify the full endorsement-key policy for an inline VEK against the
/// bundled AMD roots: the ARK → ASK/ASVK → VEK chain (VLEK auto-detected from
/// the certificate CN), the VEK validity period, and the VEK's chip-id/TCB OID
/// cross-validation against the report. This is step 6 of
/// [`Snp::verify`] as one unit, for callers that resolve the VEK
/// themselves (notably the WASM `verify_snp` entry point). Revocation is out
/// of scope — pair with [`check_vek_against_crl`] when CRL data is available.
pub fn verify_vek_endorsement(
    report: &AttestationReport,
    vek_der: &[u8],
    processor_gen: ProcessorGeneration,
    now: i64,
) -> Result<()> {
    verify_cert_chain(
        super::certs::get_ark(processor_gen),
        vek_issuer(vek_der, processor_gen)?,
        vek_der,
    )?;
    verify_vek_validity_period(vek_der, now)?;
    verify_vcek_tcb(report, vek_der, processor_gen)?;
    Ok(())
}

/// The bundled AMD intermediate that issues `vek_der`: the ASVK for a VLEK
/// (ARK → ASVK → VLEK), the ASK for a VCEK (ARK → ASK → VCEK).
fn vek_issuer(vek_der: &[u8], processor_gen: ProcessorGeneration) -> Result<&'static [u8]> {
    Ok(if is_vlek_cert(vek_der)? {
        super::certs::get_asvk(processor_gen)
    } else {
        super::certs::get_ask(processor_gen)
    })
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

/// Extract the chip_id bytes from the VCEK HW_ID extension value.
///
/// Some VCEK certificates encode the chip_id as a DER OCTET STRING,
/// while others (notably Azure VCEK certs from THIM/IMDS) encode it
/// as raw bytes without an inner DER wrapper. This matches the approach
/// used by the Trustee reference implementation.
fn get_oid_octets(ext_value: &[u8]) -> Option<&[u8]> {
    // Try proper DER OCTET STRING decode first.
    if let Ok(octet_string) = der::asn1::OctetStringRef::from_der(ext_value) {
        return Some(octet_string.as_bytes());
    }
    // Raw bytes (no inner DER wrapper) — return as-is if non-empty.
    if !ext_value.is_empty() {
        return Some(ext_value);
    }
    None
}

/// Verify VCEK certificate TCB extensions match the SNP attestation report.
///
/// - For "VCEK" certificates: validates chip_id and TCB SPL exact equality.
/// - For "VLEK" certificates: skips chip_id check, only validates TCB SPLs.
///
/// `processor_gen` gates the chip_id comparison: only Turin uses a short
/// (8-byte + zero-pad) HW_ID, so the short-prefix path is taken there alone.
/// Milan/Genoa must match the full 64-byte chip_id exactly.
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
        let chip_id_bytes = get_oid_octets(ext.value).ok_or_else(|| {
            AttestationError::TcbMismatch("VCEK HW_ID OID has unparseable value".to_string())
        })?;
        // report.chip_id is always a fixed [u8; 64].
        let report_chip_id = &report.chip_id[..];
        let prefix_len = chip_id_bytes.len();

        let ok = if processor_gen == ProcessorGeneration::Turin {
            // Turin's VCEK HW_ID is shorter than the report's 64-byte chip_id
            // field (8 meaningful bytes + 56 zero pad). Compare the meaningful
            // prefix in constant time and confirm the remainder is zero.
            // Minimum 8 bytes: the smallest known AMD HW_ID (Turin).
            const MIN_CHIP_ID_LEN: usize = 8;
            prefix_len >= MIN_CHIP_ID_LEN
                && prefix_len <= report_chip_id.len()
                && crate::utils::constant_time_eq(chip_id_bytes, &report_chip_id[..prefix_len])
                && report_chip_id[prefix_len..].iter().all(|b| *b == 0)
        } else {
            // Milan/Genoa: require full 64-byte chip_id equality. No short path.
            prefix_len == report_chip_id.len()
                && crate::utils::constant_time_eq(chip_id_bytes, report_chip_id)
        };
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

/// Check the AMD certificate that issued a VEK against an AMD KDS CRL.
/// Returns `Ok(false)` when the CRL revokes it.
///
/// AMD CRLs are signed by the ARK and list revoked ARK-issued certificates:
/// ASKs and ASVKs. Every VCEK/VLEK carries serial 0 and is issued by the
/// ASK/ASVK, so the entry that can revoke a VEK is its issuer's serial. The
/// issuer (ASK, or ASVK for a VLEK) and the ARK are the bundled ones for
/// `processor_gen`, the same chain [`verify_cert_chain`] validates.
///
/// A CRL that cannot be parsed, is not signed by the ARK, or is outside its
/// thisUpdate/nextUpdate window at `now` (Unix seconds) was not usefully
/// obtained: [`AttestationError::CollateralUnavailable`]. Only "the issuer is
/// listed" is a value.
pub fn check_vek_against_crl(
    vek_der: &[u8],
    crl_der: &[u8],
    processor_gen: ProcessorGeneration,
    now: i64,
) -> Result<bool> {
    let ark_der = super::certs::get_ark(processor_gen);
    let issuer_der = vek_issuer(vek_der, processor_gen)?;
    let listed = crl_lists(issuer_der, crl_der, ark_der, now).map_err(|e| match e {
        AttestationError::CollateralUnavailable(_) => e,
        other => AttestationError::CollateralUnavailable(format!("AMD CRL: {other}")),
    })?;
    Ok(!listed)
}

/// Whether a CRL from `issuer_der` lists `cert_der`.
///
/// Verifies the CRL's own signature against the issuer and its
/// thisUpdate/nextUpdate window before trusting the revocation list. Without
/// this an attacker could supply a forged or stale empty CRL to bypass
/// revocation checks.
// INVARIANT CLASS: Correctness
// INVARIANT: CRL signature verified against issuing CA before trusting revocation data.
fn crl_lists(cert_der: &[u8], crl_der: &[u8], issuer_der: &[u8], now: i64) -> Result<bool> {
    // 1. Parse the issuing CA cert to extract its public key
    let (_, issuer_cert) = X509Certificate::from_der(issuer_der)
        .map_err(|e| AttestationError::CertChainError(format!("CRL issuer x509 parse: {e}")))?;

    // 2. Parse the CRL
    let (_, crl) = CertificateRevocationList::from_der(crl_der)
        .map_err(|e| AttestationError::CertChainError(format!("AMD CRL parse: {e}")))?;

    // 3. Verify CRL signature against the issuing CA's public key.
    // We use our own implementation because x509-parser's verify_signature
    // doesn't support RSA-PSS (used by Milan ASK for CRL signing).
    verify_crl_signature(&crl, crl_der, &issuer_cert)?;

    // 3b. Freshness: a genuine but stale CRL must not vouch for a certificate
    // that a newer list may have revoked. AMD CRLs always carry nextUpdate;
    // one without it has no defined shelf life, so it is rejected rather than
    // trusted forever.
    let now = crate::utils::asn1_time(now)?;
    if crl.last_update() > now {
        return Err(AttestationError::CollateralUnavailable(format!(
            "AMD CRL thisUpdate {} is in the future",
            crl.last_update()
        )));
    }
    match crl.next_update() {
        None => {
            return Err(AttestationError::CertChainError(
                "AMD CRL has no nextUpdate; refusing a revocation list with no defined freshness"
                    .into(),
            ));
        }
        Some(next_update) if next_update < now => {
            return Err(AttestationError::CollateralUnavailable(format!(
                "AMD CRL is stale: nextUpdate {next_update} has passed; fetch a current CRL"
            )));
        }
        Some(_) => {}
    }

    // 4. Check serial number against revocation list
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| AttestationError::CertChainError(format!("x509 parse for CRL: {e}")))?;
    let cert_serial = cert.raw_serial();
    let revoked = crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == cert_serial);
    if revoked {
        log::warn!(
            "{} (serial {}) is listed in the AMD CRL",
            cert.subject(),
            cert.raw_serial_as_string()
        );
    }
    Ok(revoked)
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
        .map_err(|e| AttestationError::CertChainError(format!("CRL DER: {e}")))?;
    // Skip past the outer SEQUENCE tag+length to reach its content
    let header = der::Header::decode(&mut reader)
        .map_err(|e| AttestationError::CertChainError(format!("CRL DER header: {e}")))?;
    header
        .tag
        .assert_eq(der::Tag::Sequence)
        .map_err(|e| AttestationError::CertChainError(format!("CRL: expected SEQUENCE: {e}")))?;
    // First element inside the SEQUENCE is TBSCertList
    reader
        .tlv_bytes()
        .map_err(|e| AttestationError::CertChainError(format!("CRL TBS extract: {e}")))
}

/// Verify a CRL signature against the issuing CA certificate.
///
/// Supports:
/// - RSA-PSS SHA-384 (Milan ASK, RSA 4096)
/// - ECDSA P-384 SHA-384 (Genoa/Turin ASK)
// INVARIANT CLASS: Correctness
// INVARIANT: CRL must be signed by the issuing CA. No shortcuts.
fn verify_crl_signature(
    crl: &CertificateRevocationList,
    crl_der: &[u8],
    issuer_cert: &X509Certificate,
) -> Result<()> {
    let sig_alg_oid = crl.signature_algorithm.algorithm.to_string();
    let tbs_der = extract_tbs_from_crl_der(crl_der)?;
    let sig_value = crl.signature_value.as_ref();

    match sig_alg_oid.as_str() {
        OID_RSA_PSS => {
            // Milan ASK uses RSA 4096 with PSS SHA-384
            let spki_der = issuer_cert.public_key().raw;
            let rsa_pub = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| {
                AttestationError::CertChainError(format!("CRL issuer RSA key parse: {e}"))
            })?;
            // ALGORITHM: RSA-PSS SHA-384 verification. The AMD Milan ARK signs
            // CRLs with RSASSA-PSS using SHA-384 as both hash and MGF1 hash,
            // salt length = hash length (48 bytes).
            let verifying_key = rsa::pss::VerifyingKey::<sha2::Sha384>::new(rsa_pub);
            let sig = rsa::pss::Signature::try_from(sig_value).map_err(|e| {
                AttestationError::CertChainError(format!("CRL RSA-PSS signature parse: {e}"))
            })?;
            verifying_key.verify(tbs_der, &sig).map_err(|e| {
                AttestationError::CertChainError(format!(
                    "CRL RSA-PSS signature verification failed: {e}"
                ))
            })?;
        }
        OID_ECDSA_WITH_SHA384 => {
            // Genoa/Turin ASK uses ECDSA P-384
            let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(
                &issuer_cert.public_key().subject_public_key.data,
            )
            .or_else(|_| {
                p384::ecdsa::VerifyingKey::from_public_key_der(issuer_cert.public_key().raw)
            })
            .map_err(|e| {
                AttestationError::CertChainError(format!("CRL issuer ECDSA key parse: {e}"))
            })?;
            let sig = p384::ecdsa::DerSignature::from_bytes(sig_value).map_err(|e| {
                AttestationError::CertChainError(format!("CRL ECDSA signature parse: {e}"))
            })?;
            verifying_key.verify(tbs_der, &sig).map_err(|e| {
                AttestationError::CertChainError(format!(
                    "CRL ECDSA signature verification failed: {e}"
                ))
            })?;
        }
        _ => {
            return Err(AttestationError::CertChainError(format!(
                "unsupported CRL signature algorithm OID: {sig_alg_oid}"
            )));
        }
    }

    Ok(())
}

/// Parse an SNP attestation report from raw bytes using the sev crate.
pub fn parse_report(report_bytes: &[u8]) -> Result<AttestationReport> {
    AttestationReport::from_bytes(report_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("SNP report parse: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;

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
    fn test_get_oid_octets_raw_bytes() {
        // Raw chip_id bytes (no inner DER wrapper) — the common case for AMD VCEKs
        let raw = [0x06u8; 64]; // first byte is NOT 0x04
        assert_eq!(get_oid_octets(&raw), Some(raw.as_slice()));
    }

    #[test]
    fn test_get_oid_octets_der_wrapped() {
        // DER OCTET STRING: tag=0x04, len=0x03, data=[0xAA, 0xBB, 0xCC]
        let wrapped = [0x04, 0x03, 0xAA, 0xBB, 0xCC];
        assert_eq!(get_oid_octets(&wrapped), Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn test_get_oid_octets_empty() {
        assert_eq!(get_oid_octets(&[]), None);
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
                "{gen:?} ASVK subject should contain VLEK: {subject}"
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
    /// fixture. No network access, no CRL.
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
            Err(AttestationError::CollateralUnavailable(
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

    /// A provider whose AMD CRL fetch fails.
    struct CrlUnreachable;

    #[async_trait::async_trait]
    impl crate::collateral::CertProvider for CrlUnreachable {
        async fn get_snp_vcek(
            &self,
            _: ProcessorGeneration,
            _: &[u8; 64],
            _: &SnpTcb,
        ) -> Result<Vec<u8>> {
            Ok(LIVE_VCEK_GENOA.to_vec())
        }

        async fn get_snp_cert_chain(&self, _: ProcessorGeneration) -> Result<(Vec<u8>, Vec<u8>)> {
            unreachable!("the bare-metal SNP path uses the bundled chain")
        }

        async fn get_snp_crl(&self, _: ProcessorGeneration) -> Result<Option<Vec<u8>>> {
            Err(AttestationError::CollateralUnavailable(
                "unreachable".into(),
            ))
        }
    }

    #[tokio::test]
    async fn test_crl_fetch_failure_is_collateral_unavailable() {
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let ctx = Context::offline().with_cert_provider(CrlUnreachable);
        let err = Snp::verify(&evidence, &SnpParams::default(), &ctx)
            .await
            .expect_err("the CRL was needed and could not be fetched");
        assert!(err.is_retryable());
    }

    async fn verify(params: &SnpParams) -> Result<SnpResult> {
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let ctx = Context::offline().with_cert_provider(StubCertProvider);
        Snp::verify(&evidence, params, &ctx).await
    }

    #[tokio::test]
    async fn test_verify_evidence_no_expected_launch_digest_yields_none() {
        let r = verify(&SnpParams::default())
            .await
            .expect("live v5 fixture should verify");
        assert!(r.launch_digest_match.is_none(), "no pin → None");
        assert!(r.min_tcb_met.is_none(), "no minimum → None");
        assert!(r.passed());
    }

    #[tokio::test]
    async fn test_verify_evidence_matching_launch_digest() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut expected = [0u8; 48];
        expected.copy_from_slice(&report.measurement[..]);

        let params = SnpParams {
            launch_digest: Some(vec![[0xAA; 48], expected]),
            ..Default::default()
        };
        let r = verify(&params).await.unwrap();
        assert_eq!(r.launch_digest_match, Some(true));
    }

    #[tokio::test]
    async fn test_report_and_host_data_mismatch_are_values() {
        let params = SnpParams {
            report_data: Some(vec![0xFF; 64]),
            host_data: Some(vec![0xFF; 32]),
            ..Default::default()
        };
        let r = verify(&params)
            .await
            .expect("binding mismatches are values, not errors");
        assert_eq!(r.report_data_match, Some(false));
        assert_eq!(r.host_data_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn test_min_tcb_below_floor_is_a_value() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut floor = snp_tcb(&report.reported_tcb);
        let r = verify(&SnpParams {
            min_tcb: Some(floor),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(r.min_tcb_met, Some(true));
        assert_eq!(r.reported_tcb, floor);
        assert!(r.passed());

        floor.microcode += 1;
        let r = verify(&SnpParams {
            min_tcb: Some(floor),
            ..Default::default()
        })
        .await
        .expect("a TCB below the minimum is a value, not an error");
        assert_eq!(r.min_tcb_met, Some(false));
        assert!(!r.passed());
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

    fn now_secs() -> i64 {
        chrono::Utc::now().timestamp()
    }

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
        let in_window = datetime!(2020-06-01 0:00 UTC).unix_timestamp();
        verify_vek_validity_period(&leaf, in_window).expect("valid inside its window");
        let err = verify_vek_validity_period(&leaf, now_secs())
            .expect_err("expired VEK must be rejected");
        assert!(
            matches!(err, AttestationError::CertChainError(_)),
            "{err:?}"
        );
    }

    #[test]
    fn test_vek_not_yet_valid_rejected() {
        let leaf = mint_leaf(
            LEAF_SERIAL,
            datetime!(2100-01-01 0:00 UTC),
            datetime!(2101-01-01 0:00 UTC),
        );
        let in_window = datetime!(2100-06-01 0:00 UTC).unix_timestamp();
        verify_vek_validity_period(&leaf, in_window).expect("valid inside its window");
        let err =
            verify_vek_validity_period(&leaf, now_secs()).expect_err("future VEK must be rejected");
        assert!(
            matches!(err, AttestationError::CertChainError(_)),
            "{err:?}"
        );
    }

    #[test]
    fn test_vek_current_accepted() {
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        verify_vek_validity_period(&leaf, now_secs()).expect("current VEK must pass");
    }

    #[test]
    fn test_crl_revoked_serial_is_listed() {
        let issuer = mint_issuer("TEST-ARK");
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        let crl = mint_crl(&issuer, Some(LEAF_SERIAL), not_before, not_after);
        assert!(
            crl_lists(&leaf, &crl, issuer.0.der(), now_secs()).unwrap(),
            "a revoked serial is reported, not an error"
        );
    }

    #[test]
    fn test_crl_revoking_bundled_ask_is_listed() {
        // AMD CRLs list ASK/ASVK serials; a VEK is revoked through its issuer.
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        let (_, ask_cert) = X509Certificate::from_der(ask).unwrap();
        let issuer = mint_issuer("TEST-ARK");
        let (this_update, next_update) = valid_window();
        let crl = mint_crl(
            &issuer,
            Some(ask_cert.raw_serial()),
            this_update,
            next_update,
        );
        assert!(crl_lists(ask, &crl, issuer.0.der(), now_secs()).unwrap());
    }

    #[test]
    fn test_revoked_issuer_fails_passed() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let params = SnpParams::default();
        assert!(evaluate_report(&report, &params, Some(true)).passed());
        assert!(evaluate_report(&report, &params, None).passed());
        assert!(!evaluate_report(&report, &params, Some(false)).passed());
    }

    #[test]
    fn test_crl_fresh_nonrevoked_accepted() {
        let issuer = mint_issuer("TEST-ARK");
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        let crl = mint_crl(&issuer, Some(&[0xEE; 4]), not_before, not_after);
        assert!(!crl_lists(&leaf, &crl, issuer.0.der(), now_secs())
            .expect("fresh CRL not naming the serial must pass"));
    }

    #[test]
    fn test_crl_stale_rejected() {
        let issuer = mint_issuer("TEST-ARK");
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        let now = OffsetDateTime::now_utc();
        // nextUpdate already passed: a genuine but stale list must not vouch.
        let crl = mint_crl(
            &issuer,
            None,
            now - TimeDuration::days(30),
            now - TimeDuration::days(1),
        );
        let err = crl_lists(&leaf, &crl, issuer.0.der(), now_secs())
            .expect_err("stale CRL must be rejected");
        assert!(err.is_retryable(), "a stale CRL needs a fresh fetch: {err}");
    }

    #[test]
    fn test_crl_from_future_rejected() {
        let issuer = mint_issuer("TEST-ARK");
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        let now = OffsetDateTime::now_utc();
        let crl = mint_crl(
            &issuer,
            None,
            now + TimeDuration::days(1),
            now + TimeDuration::days(30),
        );
        let err = crl_lists(&leaf, &crl, issuer.0.der(), now_secs())
            .expect_err("future-dated CRL must be rejected");
        assert!(err.to_string().contains("future"), "got: {err}");
    }

    #[test]
    fn test_crl_wrong_issuer_rejected() {
        let signer = mint_issuer("TEST-ARK");
        let impostor = mint_issuer("OTHER-ARK");
        let (not_before, not_after) = valid_window();
        let leaf = mint_leaf(LEAF_SERIAL, not_before, not_after);
        // An empty CRL signed by a key the verifier does not trust must not
        // clear the check — this is exactly the forged-empty-CRL bypass.
        let crl = mint_crl(&signer, None, not_before, not_after);
        let err = crl_lists(&leaf, &crl, impostor.0.der(), now_secs())
            .expect_err("CRL signed by the wrong issuer must be rejected");
        assert!(
            err.to_string().contains("signature verification failed"),
            "got: {err}"
        );
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
    fn test_min_tcb_fmc_required_but_absent_not_met() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let tcb = &snp_tcb(&report.reported_tcb);
        assert!(tcb.fmc.is_none(), "Genoa reports carry no FMC");
        let floor = SnpTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
            fmc: Some(1),
        };
        assert!(
            !min_tcb_met(tcb, &floor),
            "a floor requiring FMC must reject a report without it"
        );
    }

    #[tokio::test]
    async fn test_verify_evidence_wrong_launch_digest_is_some_false() {
        // Wrong digest must record Some(false) without failing verification.
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let ctx = Context::offline().with_cert_provider(StubCertProvider);
        let params = SnpParams {
            launch_digest: Some(vec![[0xAA; 48]]),
            ..Default::default()
        };
        let r = Snp::verify(&evidence, &params, &ctx).await.unwrap();
        assert_eq!(r.launch_digest_match, Some(false));
        assert!(!r.passed());
    }
}
