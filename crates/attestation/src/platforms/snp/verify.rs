use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::{Decode, Reader};
use signature::Verifier as _;
use spki::DecodePublicKey;
use x509_parser::prelude::{CertificateRevocationList, FromDer as X509FromDer, X509Certificate};

use sev::certs::snp::{Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

use serde::{Deserialize, Serialize};

use crate::collateral::{AmdCrl, AmdKey, CollateralUsed, Store, Vcek};
use crate::error::{AttestationError, Result};
use crate::platform::Platform;
use crate::types::{Claims, PlatformType, ProcessorGeneration, SnpTcb};
use crate::utils::b64;

// OID constants for CRL signature algorithm identification.
// x509-parser's verify_signature does not support OID_RSA_PSS (rsaPSS with parameters),
// which Milan ARK uses for CRL signing. We dispatch on OID and verify with the `rsa`
// and `p384` crates directly.
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";

use super::claims::extract_claims;
use super::evidence::SnpEvidence;
use super::measurement_registers::{self, MeasurementRegisters};

/// SNP Attestation Report version (must be >= 3 for cpuid fields).
const MIN_REPORT_VERSION: u32 = 3;

/// Maximum supported SNP report version.
/// Matches Trustee's upper bound — future versions may change field layout.
pub const MAX_REPORT_VERSION: u32 = 5;

/// What a caller can ask of SEV-SNP evidence. In JSON, byte values are
/// base64 and `launch_digest` is one value or an array.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SnpParams {
    /// Expected `report_data` (at most 64 bytes, zero-padded). Result in
    /// [`SnpResult::report_data_match`]. On Azure (vTPM) this is checked
    /// against the vTPM quote nonce instead. With `measurement_registers`, the
    /// exact 64 bytes the requester passed, which `REPORT_DATA` must commit to.
    #[serde(with = "b64::bytes")]
    pub report_data: Option<Vec<u8>>,
    /// Expected HOST_DATA (at most 32 bytes, zero-padded). On Azure (vTPM) a
    /// 32-byte init-data hash checked against `PCR[8]`.
    #[serde(with = "b64::bytes")]
    pub host_data: Option<Vec<u8>>,
    /// Allowed launch digests (`report.measurement`): the measurement must
    /// equal one of them. Must not be empty.
    #[serde(with = "b64::digests")]
    pub launch_digest: Option<Vec<[u8; 48]>>,
    /// Accept a guest whose policy allows debug. Default: false.
    pub allow_debug: bool,
    /// Minimum TCB: each component of the reported, committed and launch
    /// TCB must be at least this.
    pub min_tcb: Option<SnpTcb>,
    /// Highest VMPL accepted. Default: 0.
    pub max_vmpl: u32,
    /// Bare-metal guest kernel measurement registers: the expected final values
    /// in index order, at most 16; registers past the list must be zero (`[]`:
    /// all zero). Setting it selects the mode: `REPORT_DATA` must commit to
    /// the evidence's event log and `report_data`. It needs a 64-byte
    /// `report_data`, `launch_digest` and VMPL 0. Azure and GCP refuse it
    /// (`InvalidParams`). On a provider image `REPORT_DATA` is always the
    /// commitment, so only this mode binds the requester's bytes there.
    ///
    /// **Every `launch_digest` value must be an image whose kernel has the
    /// measurement-register provider.** On an image without it, guest root
    /// chooses `REPORT_DATA` and can forge any registers; never pin such an
    /// image here, not even next to provider images.
    ///
    /// With debug allowed, the host can read and change guest memory, so
    /// register values are not protected against the host. Likewise with
    /// `min_tcb` unset: a host on firmware with known bugs can forge
    /// registers, so production verifiers should set `min_tcb`.
    #[serde(
        with = "b64::digest_list::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub measurement_registers: Option<Vec<[u8; 48]>>,
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
        if let Some(registers) = &self.measurement_registers {
            if registers.len() > measurement_registers::REGISTER_COUNT
                || self.report_data.as_ref().is_none_or(|d| d.len() != 64)
                || self.launch_digest.is_none()
                || self.max_vmpl != 0
            {
                return Err(AttestationError::InvalidParams(
                    "measurement_registers needs at most 16 values, a 64-byte report_data, \
                     launch_digest and VMPL 0"
                        .into(),
                ));
            }
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
    /// The guest policy allows a migration agent (never accepted).
    #[serde(default)]
    pub migrate_ma: bool,
    /// VMPL the report was requested from.
    pub vmpl: u32,
    /// The highest VMPL the params accept.
    pub max_vmpl: u32,
    /// TCB the report was signed under.
    pub reported_tcb: SnpTcb,
    /// The reported, committed and launch TCB are each at or above `min_tcb`
    /// (`None` if no minimum given).
    pub min_tcb_met: Option<bool>,
    /// The AMD CRL does not revoke the VEK's issuing ASK/ASVK (`None` only on
    /// results not from [`Snp::verify`]).
    pub crl_ok: Option<bool>,
    /// The guest kernel's measurement registers that `REPORT_DATA` commits to;
    /// `None` unless the result [passed](Self::passed).
    pub measurement_registers: Option<MeasurementRegisters>,
    /// `measurement_registers` equal the expected ones (`None` outside
    /// measurement-register mode).
    pub measurement_registers_match: Option<bool>,
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
            self.measurement_registers_match,
        ]) && (!self.debug || self.allow_debug)
            && !self.migrate_ma
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
        migrate_ma: report.policy.migrate_ma_allowed(),
        vmpl: report.vmpl,
        max_vmpl: params.max_vmpl,
        min_tcb_met: params.min_tcb.as_ref().map(|min| {
            [
                &report.reported_tcb,
                &report.committed_tcb,
                &report.launch_tcb,
            ]
            .into_iter()
            .all(|tcb| min_tcb_met(&snp_tcb(tcb), min))
        }),
        reported_tcb,
        crl_ok,
        measurement_registers: None,
        measurement_registers_match: None,
    }
}

pub(crate) fn snp_tcb(tcb: &sev::firmware::host::TcbVersion) -> SnpTcb {
    SnpTcb {
        bootloader: tcb.bootloader,
        tee: tcb.tee,
        snp: tcb.snp,
        microcode: tcb.microcode,
        fmc: tcb.fmc,
    }
}

/// The SEV-SNP collateral set.
pub struct SnpCollateralSet {
    /// The VEK the report is signed with (DER): carried in the evidence (a
    /// VCEK or VLEK), or the VCEK fetched from AMD KDS.
    pub vek: Vec<u8>,
    pub crl: AmdCrl,
}

impl SnpCollateralSet {
    /// The collateral for `report`, which has verified against `inline`
    /// when the evidence carries its VEK; a fetched VCEK is checked against
    /// the report here.
    pub(crate) async fn gather(
        report: &AttestationReport,
        gen: ProcessorGeneration,
        inline: Option<Vec<u8>>,
        store: &Store,
        now: i64,
    ) -> Result<(Self, Vec<CollateralUsed>)> {
        if let Some(vek) = inline {
            let (crl, used) = store
                .get::<AmdCrl>(&(gen, AmdKey::of_vek(&vek)?), now)
                .await?;
            return Ok((Self { vek, crl }, vec![used]));
        }
        if report.chip_id.iter().all(|&b| b == 0) {
            return Err(AttestationError::CertChainError(
                "evidence carries no VEK and the report's CHIP_ID is masked".into(),
            ));
        }
        let tcb = snp_tcb(&report.reported_tcb);
        if gen == ProcessorGeneration::Turin && tcb.fmc.is_none() {
            return Err(AttestationError::QuoteParseFailed(
                "Turin report missing FMC TCB field".into(),
            ));
        }
        let (vcek_id, crl_id) = ((gen, report.chip_id, tcb), (gen, AmdKey::Vcek));
        let (vcek, crl) = futures_util::join!(
            store.get::<Vcek>(&vcek_id, now),
            store.get::<AmdCrl>(&crl_id, now)
        );
        let (vcek, vcek_used) = vcek?;
        check_report(report, &vcek.der, gen, now)?;
        let (crl, crl_used) = crl?;
        let collateral = Self { vek: vcek.der, crl };
        Ok((collateral, vec![vcek_used, crl_used]))
    }
}

/// Bare-metal AMD SEV-SNP.
pub struct Snp;

impl Platform for Snp {
    const KIND: PlatformType = PlatformType::Snp;
    type Evidence = SnpEvidence;
    type Params = SnpParams;
    type Result = SnpResult;
    type CollateralSet = SnpCollateralSet;

    fn validate(params: &SnpParams) -> Result<()> {
        params.validate()
    }

    /// The VEK (unless the evidence carries it) and the AMD CRL for its
    /// issuer. A report that carries its VEK is checked before anything is
    /// fetched; otherwise an unverified CHIP_ID names the VCEK to fetch, and
    /// the report is checked against it before the collateral is returned.
    async fn gather(
        evidence: &SnpEvidence,
        store: &Store,
        now: i64,
    ) -> Result<(SnpCollateralSet, Vec<CollateralUsed>)> {
        let (report, gen, inline) = genuine_report(evidence, now)?;
        SnpCollateralSet::gather(&report, gen, inline, store, now).await
    }

    fn verify(
        evidence: &SnpEvidence,
        params: &SnpParams,
        collateral: &SnpCollateralSet,
        now: i64,
    ) -> Result<SnpResult> {
        params.validate()?;
        let (_, report, gen) = parse_evidence(evidence)?;
        let vek = &collateral.vek;
        check_report(&report, vek, gen, now)?;

        let revoked = vek_revoked(vek, &collateral.crl, gen)?;
        let mut result = evaluate_report(&report, params, Some(!revoked));
        check_report_bindings(&mut result, &report, params)?;
        if let Some(expected) = &params.measurement_registers {
            let caller_data = params
                .report_data
                .as_deref()
                .and_then(|d| d.try_into().ok())
                .expect("validate: measurement_registers needs a 64-byte report_data");
            check_measurement_registers(
                &mut result,
                &report.report_data,
                evidence.event_log.as_deref(),
                caller_data,
                expected,
            )?;
        }
        Ok(result)
    }
}

/// Replay the event log prefix that `report_data` names and replace
/// `report_data_match` with whether `report_data` commits to it and
/// `caller_data`. Registers are compared with `expected` only when the
/// launch digest pin also held (without the provider the commitment means
/// nothing), and exposed only when the whole result passed.
fn check_measurement_registers(
    result: &mut SnpResult,
    report_data: &[u8; 64],
    event_log: Option<&str>,
    caller_data: &[u8; 64],
    expected: &[[u8; 48]],
) -> Result<()> {
    let event_log = event_log.unwrap_or_default();
    crate::utils::check_field_size("event_log", event_log.len())?;
    let log = BASE64
        .decode(event_log)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("event_log base64: {e}")))?;
    let registers = measurement_registers::verify(report_data, &log, caller_data)?
        .filter(|_| result.launch_digest_match == Some(true));
    result.report_data_match = Some(registers.is_some());
    result.measurement_registers_match = Some(registers.as_ref().is_some_and(|r| {
        r.registers
            .iter()
            .enumerate()
            .all(|(i, value)| *value == expected.get(i).copied().unwrap_or([0; 48]))
    }));
    result.measurement_registers = registers.filter(|_| result.passed());
    Ok(())
}

/// Decode and parse the report, check its version, and find its generation.
fn parse_evidence(
    evidence: &SnpEvidence,
) -> Result<(Vec<u8>, AttestationReport, ProcessorGeneration)> {
    crate::utils::check_field_size("attestation_report", evidence.attestation_report.len())?;
    let report_bytes = BASE64
        .decode(&evidence.attestation_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("base64 decode: {e}")))?;
    let report = parse_report(&report_bytes)?;
    if report.version < MIN_REPORT_VERSION || report.version > MAX_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: MIN_REPORT_VERSION,
            max: MAX_REPORT_VERSION,
        });
    }
    // v3+ reports carry the CPUID fields.
    let (Some(family), Some(model)) = (report.cpuid_fam_id, report.cpuid_mod_id) else {
        return Err(AttestationError::QuoteParseFailed(
            "v3+ SNP report missing CPUID fields".to_string(),
        ));
    };
    let gen = ProcessorGeneration::from_cpuid(family, model).ok_or_else(|| {
        AttestationError::QuoteParseFailed(format!(
            "unknown processor: family=0x{family:02X}, model=0x{model:02X}"
        ))
    })?;
    Ok((report_bytes, report, gen))
}

/// The report, its generation and the VEK it carries (if any), once the
/// report has verified against that VEK: the checks that need no collateral.
pub(crate) fn genuine_report(
    evidence: &SnpEvidence,
    now: i64,
) -> Result<(AttestationReport, ProcessorGeneration, Option<Vec<u8>>)> {
    let (_, report, gen) = parse_evidence(evidence)?;
    let inline = inline_vek(evidence)?;
    if let Some(vek) = &inline {
        check_report(&report, vek, gen, now)?;
    }
    Ok((report, gen, inline))
}

/// The VEK chains to the bundled AMD roots (VLEK auto-detected), is valid at
/// `now` and names the report's chip and TCB, and it signed the report.
fn check_report(
    report: &AttestationReport,
    vek: &[u8],
    gen: ProcessorGeneration,
    now: i64,
) -> Result<()> {
    verify_vek_endorsement(report, vek, gen, now)?;
    let cert = Certificate::from_der(vek)
        .map_err(|e| AttestationError::CertChainError(format!("VEK to sev Certificate: {e}")))?;
    (&cert, report)
        .verify()
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{e}")))
}

fn inline_vek(evidence: &SnpEvidence) -> Result<Option<Vec<u8>>> {
    evidence
        .cert_chain
        .as_ref()
        .map(|chain| {
            BASE64
                .decode(&chain.vcek)
                .map_err(|e| AttestationError::CertChainError(format!("VCEK base64: {e}")))
        })
        .transpose()
}

/// Whether `crl` revokes the AMD certificate that issued `vek_der` (its ASK,
/// or ASVK for a VLEK). AMD CRLs are signed by the ARK and list the
/// ARK-issued ASKs and ASVKs; every VEK carries serial 0, so the entry that
/// can revoke a VEK is its issuer's. The CRL's signature was checked when it
/// was stored; here it must be the one for this VEK.
pub(crate) fn vek_revoked(
    vek_der: &[u8],
    crl: &AmdCrl,
    processor_gen: ProcessorGeneration,
) -> Result<bool> {
    let key = AmdKey::of_vek(vek_der)?;
    if (crl.generation, crl.key) != (processor_gen, key) {
        return Err(AttestationError::CertChainError(format!(
            "collateral has the {:?} {:?} CRL, the VEK is a {processor_gen:?} {key:?}",
            crl.generation, crl.key
        )));
    }
    let (_, issuer) = X509Certificate::from_der(vek_issuer(vek_der, processor_gen)?)
        .map_err(|e| AttestationError::CertChainError(format!("VEK issuer x509 parse: {e}")))?;
    let (_, list) = CertificateRevocationList::from_der(&crl.der)
        .map_err(|e| AttestationError::CertChainError(format!("AMD CRL parse: {e}")))?;
    let revoked = list
        .iter_revoked_certificates()
        .any(|r| r.raw_serial() == issuer.raw_serial());
    if revoked {
        log::warn!("{} is listed in the AMD CRL", issuer.subject());
    }
    Ok(revoked)
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
/// themselves. Revocation is out of scope; use [`Snp`] for verification with
/// AMD revocation checks.
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

/// Verify that a VEK certificate was issued for the report's chip and TCB.
pub fn verify_vcek_tcb(
    report: &AttestationReport,
    vcek_der: &[u8],
    processor_gen: ProcessorGeneration,
) -> Result<()> {
    check_vek_binding(
        vcek_der,
        &report.chip_id,
        &snp_tcb(&report.reported_tcb),
        processor_gen,
    )
}

/// Verify that a VEK certificate's TCB extensions name `chip_id` and `tcb`.
///
/// - For "VCEK" certificates: validates chip_id and TCB SPL exact equality.
/// - For "VLEK" certificates: skips chip_id check, only validates TCB SPLs.
///
/// `processor_gen` gates the chip_id comparison: only Turin uses a short
/// (8-byte + zero-pad) HW_ID, so the short-prefix path is taken there alone.
/// Milan/Genoa must match the full 64-byte chip_id exactly.
pub fn check_vek_binding(
    vcek_der: &[u8],
    chip_id: &[u8; 64],
    tcb: &SnpTcb,
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
        let report_chip_id = &chip_id[..];
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
        (LOADER_SPL_OID, tcb.bootloader, "bootloader"),
        (TEE_SPL_OID, tcb.tee, "tee"),
        (SNP_SPL_OID, tcb.snp, "snp"),
        (UCODE_SPL_OID, tcb.microcode, "microcode"),
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
    if let Some(fmc_expected) = tcb.fmc {
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
        } else if fmc_expected != 0 || processor_gen == ProcessorGeneration::Turin {
            return Err(AttestationError::TcbMismatch(format!(
                "report FMC SPL is {fmc_expected} but VCEK certificate lacks FMC OID extension"
            )));
        }
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
pub(crate) fn verify_crl_signature(
    crl: &CertificateRevocationList,
    crl_der: &[u8],
    issuer_cert: &X509Certificate,
) -> Result<()> {
    // The outer algorithm is not signed; it must repeat the signed one.
    if crl.signature_algorithm != crl.tbs_cert_list.signature {
        return Err(AttestationError::CertChainError(
            "CRL signature algorithm differs from the signed one".into(),
        ));
    }
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
    use crate::testing;
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

    // expected_launch_digest tests against the live Genoa v5 fixture.

    fn make_snp_evidence_with_vcek(report: &[u8], vcek_der: &[u8]) -> SnpEvidence {
        use crate::platforms::snp::evidence::SnpCertChain;
        SnpEvidence {
            attestation_report: BASE64.encode(report),
            cert_chain: Some(SnpCertChain {
                vcek: BASE64.encode(vcek_der),
                ask: None,
                ark: None,
            }),
            event_log: None,
        }
    }

    #[tokio::test]
    async fn a_crl_held_nowhere_is_collateral_unavailable() {
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let err = testing::verify::<Snp>(&evidence, &SnpParams::default(), vec![])
            .await
            .expect_err("the CRL was needed and is held nowhere");
        assert!(err.is_retryable());
    }

    async fn verify(params: &SnpParams) -> Result<SnpResult> {
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        testing::verify::<Snp>(
            &evidence,
            params,
            vec![testing::amd_crl(ProcessorGeneration::Genoa)],
        )
        .await
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

    #[test]
    fn a_turin_vcek_must_carry_the_fmc_spl() {
        fn vcek(fmc: Option<u8>) -> Vec<u8> {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "SEV-VCEK");
            let ext = |oid: &str, content: Vec<u8>| {
                let arcs: Vec<u64> = oid.split('.').map(|a| a.parse().unwrap()).collect();
                rcgen::CustomExtension::from_oid_content(&arcs, content)
            };
            params.custom_extensions = vec![ext(HW_ID_OID, vec![0x04, 8, 7, 7, 7, 7, 7, 7, 7, 7])];
            for oid in [LOADER_SPL_OID, TEE_SPL_OID, SNP_SPL_OID, UCODE_SPL_OID] {
                params.custom_extensions.push(ext(oid, vec![0x02, 1, 1]));
            }
            if let Some(fmc) = fmc {
                params
                    .custom_extensions
                    .push(ext(FMC_SPL_OID, vec![0x02, 1, fmc]));
            }
            params.self_signed(&key).unwrap().der().to_vec()
        }
        let mut chip_id = [0u8; 64];
        chip_id[..8].fill(7);
        let tcb = SnpTcb {
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
            fmc: Some(0),
        };
        let turin = ProcessorGeneration::Turin;
        assert!(check_vek_binding(&vcek(Some(0)), &chip_id, &tcb, turin).is_ok());
        assert!(check_vek_binding(&vcek(None), &chip_id, &tcb, turin).is_err());
    }

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

    fn genoa_crl(der: Vec<u8>) -> AmdCrl {
        AmdCrl {
            der,
            generation: ProcessorGeneration::Genoa,
            key: AmdKey::Vcek,
            this_update: 0,
            next_update: 0,
            number: None,
        }
    }

    #[test]
    fn a_crl_listing_the_veks_ask_revokes_it() {
        // AMD CRLs list ASK/ASVK serials; a VEK is revoked through its issuer.
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        let (_, ask_cert) = X509Certificate::from_der(ask).unwrap();
        let issuer = mint_issuer("TEST-ARK");
        let (this_update, next_update) = valid_window();
        let listing = mint_crl(
            &issuer,
            Some(ask_cert.raw_serial()),
            this_update,
            next_update,
        );
        let gen = ProcessorGeneration::Genoa;
        assert!(vek_revoked(LIVE_VCEK_GENOA, &genoa_crl(listing), gen).unwrap());
        let amd = testing::raw("2026-10-14/amd_crl_genoa.der", None).0;
        assert!(!vek_revoked(LIVE_VCEK_GENOA, &genoa_crl(amd), gen).unwrap());
    }

    #[tokio::test]
    async fn a_host_data_mismatch_alone_fails() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut params = SnpParams {
            report_data: Some(report.report_data.to_vec()),
            host_data: Some(report.host_data.to_vec()),
            ..Default::default()
        };
        let r = verify(&params).await.unwrap();
        assert_eq!(r.host_data_match, Some(true));
        assert!(r.passed());
        params.host_data.as_mut().unwrap()[0] ^= 1;
        let r = verify(&params).await.unwrap();
        assert_eq!(r.report_data_match, Some(true));
        assert_eq!(r.host_data_match, Some(false));
        assert!(!r.passed());
    }

    #[test]
    fn snp_verify_fails_a_report_whose_ask_is_revoked() {
        let ask = super::super::certs::get_ask(ProcessorGeneration::Genoa);
        let (_, ask_cert) = X509Certificate::from_der(ask).unwrap();
        let (this_update, next_update) = valid_window();
        let listing = mint_crl(
            &mint_issuer("TEST-ARK"),
            Some(ask_cert.raw_serial()),
            this_update,
            next_update,
        );
        let amd = testing::raw("2026-10-14/amd_crl_genoa.der", None).0;
        let evidence = make_snp_evidence_with_vcek(LIVE_REPORT_V5, LIVE_VCEK_GENOA);
        let verify = |crl: Vec<u8>| {
            let collateral = SnpCollateralSet {
                vek: LIVE_VCEK_GENOA.to_vec(),
                crl: genoa_crl(crl),
            };
            Snp::verify(&evidence, &SnpParams::default(), &collateral, now_secs()).unwrap()
        };
        let r = verify(amd);
        assert_eq!(r.crl_ok, Some(true));
        assert!(r.passed());
        let r = verify(listing);
        assert_eq!(r.crl_ok, Some(false));
        assert!(!r.passed());
    }

    #[test]
    fn a_crl_for_another_generation_or_key_is_refused() {
        let mut crl = genoa_crl(Vec::new());
        crl.generation = ProcessorGeneration::Milan;
        assert!(vek_revoked(LIVE_VCEK_GENOA, &crl, ProcessorGeneration::Genoa).is_err());
        crl.generation = ProcessorGeneration::Genoa;
        crl.key = AmdKey::Vlek;
        assert!(vek_revoked(LIVE_VCEK_GENOA, &crl, ProcessorGeneration::Genoa).is_err());
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

    // ---------------------------------------------------------------
    // Kernel measurement registers and guest policy
    // ---------------------------------------------------------------

    fn measurement_params(report: &AttestationReport) -> SnpParams {
        SnpParams {
            report_data: Some(vec![7; 64]),
            launch_digest: Some(vec![report.measurement]),
            measurement_registers: Some(vec![]),
            ..Default::default()
        }
    }

    #[test]
    fn a_migration_agent_fails() {
        let mut report = parse_report(LIVE_REPORT_V5).unwrap();
        let params = SnpParams::default();
        assert!(evaluate_report(&report, &params, Some(true)).passed());
        report.policy.set_migrate_ma_allowed(true);
        let r = evaluate_report(&report, &params, Some(true));
        assert!(r.migrate_ma && !r.passed());
    }

    #[test]
    fn a_report_above_the_accepted_vmpl_fails() {
        let mut report = parse_report(LIVE_REPORT_V5).unwrap();
        assert_eq!(report.vmpl, 0);
        let vmpl1 = SnpParams {
            max_vmpl: 1,
            ..Default::default()
        };
        assert!(evaluate_report(&report, &SnpParams::default(), Some(true)).passed());
        for (vmpl, passes_at_vmpl1) in [(1, true), (2, false), (0xFFFF_FFFF, false)] {
            report.vmpl = vmpl;
            assert!(!evaluate_report(&report, &SnpParams::default(), Some(true)).passed());
            assert_eq!(
                evaluate_report(&report, &vmpl1, Some(true)).passed(),
                passes_at_vmpl1,
                "VMPL {vmpl:#x}"
            );
        }
    }

    #[test]
    fn a_debug_guest_passes_only_when_allowed() {
        let mut report = parse_report(LIVE_REPORT_V5).unwrap();
        let allow_debug = SnpParams {
            allow_debug: true,
            ..Default::default()
        };
        assert!(evaluate_report(&report, &SnpParams::default(), Some(true)).passed());
        report.policy.set_debug_allowed(true);
        let r = evaluate_report(&report, &SnpParams::default(), Some(true));
        assert!(r.debug && !r.passed());
        assert!(evaluate_report(&report, &allow_debug, Some(true)).passed());
    }

    #[test]
    fn the_tcb_floor_applies_to_the_reported_committed_and_launch_tcb() {
        let mut report = parse_report(LIVE_REPORT_V5).unwrap();
        report.committed_tcb = report.reported_tcb;
        report.launch_tcb = report.reported_tcb;
        let params = SnpParams {
            min_tcb: Some(snp_tcb(&report.reported_tcb)),
            ..Default::default()
        };
        let met =
            |report: &AttestationReport| evaluate_report(report, &params, Some(true)).min_tcb_met;
        assert_eq!(met(&report), Some(true));
        for field in 0..3 {
            let mut below = report;
            let tcb = [
                &mut below.reported_tcb,
                &mut below.committed_tcb,
                &mut below.launch_tcb,
            ]
            .into_iter()
            .nth(field)
            .unwrap();
            tcb.microcode -= 1;
            assert_eq!(met(&below), Some(false), "TCB {field}");
        }
    }

    #[test]
    fn measurement_register_params_need_the_strict_mode() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let ok = measurement_params(&report);
        ok.validate().unwrap();
        // Debug is the caller's choice, as for any SNP report.
        SnpParams {
            allow_debug: true,
            ..ok.clone()
        }
        .validate()
        .unwrap();
        SnpParams {
            measurement_registers: Some(vec![[1; 48]; 16]),
            ..ok.clone()
        }
        .validate()
        .unwrap();
        let bad = [
            SnpParams {
                report_data: Some(vec![7; 63]),
                ..ok.clone()
            },
            SnpParams {
                report_data: None,
                ..ok.clone()
            },
            SnpParams {
                launch_digest: None,
                ..ok.clone()
            },
            SnpParams {
                max_vmpl: 1,
                ..ok.clone()
            },
            SnpParams {
                measurement_registers: Some(vec![[1; 48]; 17]),
                ..ok.clone()
            },
        ];
        for params in bad {
            assert!(params.validate().is_err(), "{params:?}");
        }
    }

    #[test]
    fn measurement_registers_are_an_ordered_list_in_json() {
        let parse = |registers: &str| {
            serde_json::from_str::<SnpParams>(&format!(
                r#"{{"measurement_registers":{registers}}}"#
            ))
            .map(|p| p.measurement_registers)
        };
        let r0 = BASE64.encode([1; 48]);
        assert_eq!(parse("null").unwrap(), None);
        assert_eq!(parse("[]").unwrap(), Some(vec![]));
        assert_eq!(
            parse(&format!(r#"["{r0}","{}"]"#, BASE64.encode([0; 48]))).unwrap(),
            Some(vec![[1; 48], [0; 48]])
        );
        assert!(
            parse(&format!(r#""{r0}""#)).is_err(),
            "one value is not a list"
        );
        let params = SnpParams {
            measurement_registers: Some(vec![]),
            ..Default::default()
        };
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""measurement_registers":[]"#), "{json}");
        // Unset, the field is left out, so parsers that predate it accept the JSON.
        let json = serde_json::to_string(&SnpParams::default()).unwrap();
        assert!(!json.contains("measurement_registers"), "{json}");
    }

    #[tokio::test]
    async fn measurement_register_mode_without_an_event_log_fails_even_on_the_callers_bytes() {
        // An image without the provider passes the caller's bytes through as
        // REPORT_DATA; the evidence carries no event log.
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let plain = SnpParams {
            report_data: Some(report.report_data.to_vec()),
            launch_digest: Some(vec![report.measurement]),
            ..Default::default()
        };
        assert!(verify(&plain).await.unwrap().passed());
        let r = verify(&SnpParams {
            measurement_registers: Some(vec![]),
            ..plain
        })
        .await
        .unwrap();
        assert_eq!(r.report_data_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());
    }

    #[test]
    fn a_result_without_migrate_ma_deserializes() {
        let report = parse_report(LIVE_REPORT_V5).unwrap();
        let mut json =
            serde_json::to_value(evaluate_report(&report, &SnpParams::default(), None)).unwrap();
        json.as_object_mut().unwrap().remove("migrate_ma").unwrap();
        let r: SnpResult = serde_json::from_value(json).unwrap();
        assert!(!r.migrate_ma);
    }

    // ---------------------------------------------------------------
    // Hardware fixture: a Genoa guest kernel with measurement registers
    // ---------------------------------------------------------------

    const KMR_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-report.bin");
    const KMR_EVENT_LOG: &[u8] = include_bytes!("../../../test_data/snp/kmr-event-log.bin");
    const KMR_CALLER_DATA: &[u8] = include_bytes!("../../../test_data/snp/kmr-caller-data.bin");
    const KMR_BOOT_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-boot-report.bin");
    const KMR_BOOT_CALLER_DATA: &[u8] =
        include_bytes!("../../../test_data/snp/kmr-boot-caller-data.bin");
    const KMR_VCEK: &[u8] = include_bytes!("../../../test_data/snp/kmr-vcek.der");

    /// Verify a fixture report from the kernel guest at 2026-10-20 (its VCEK
    /// was issued 2026-10-19), with the same launch digest pin.
    async fn verify_kmr(
        report: &[u8],
        event_log: &[u8],
        caller_data: &[u8],
        expected: Vec<[u8; 48]>,
    ) -> SnpResult {
        let params = SnpParams {
            report_data: Some(caller_data.to_vec()),
            launch_digest: Some(vec![parse_report(report).unwrap().measurement]),
            measurement_registers: Some(expected),
            ..Default::default()
        };
        verify_kmr_with(report, event_log, &params).await
    }

    async fn verify_kmr_with(report: &[u8], event_log: &[u8], params: &SnpParams) -> SnpResult {
        try_verify_kmr(report, event_log, params).await.unwrap()
    }

    async fn try_verify_kmr(
        report: &[u8],
        event_log: &[u8],
        params: &SnpParams,
    ) -> Result<SnpResult> {
        const AT: i64 = 1_792_454_400;
        let mut evidence = make_snp_evidence_with_vcek(report, KMR_VCEK);
        evidence.event_log = Some(BASE64.encode(event_log));
        let ctx = crate::context::Context::held(vec![testing::amd_crl(ProcessorGeneration::Genoa)])
            .at(AT)
            .unwrap();
        let (collateral, _) = Snp::gather(&evidence, ctx.store(), AT).await.unwrap();
        Snp::verify(&evidence, params, &collateral, AT)
    }

    fn kmr_expected() -> Vec<[u8; 48]> {
        let hex48 = |s: &str| -> [u8; 48] { hex::decode(s).unwrap().try_into().unwrap() };
        vec![
            hex48("f3be9859164ede7b01be3c5856639f170754b0b68bdc74b18901ce22a4da7426a9f5baa70616338fd8a296ba92aefa90"),
            [0; 48],
            hex48("fd3bae3f6e3d7b4298af44f7e909cd8c542042f23f9ed693d2515db38aff41dc1eceadfd381fc1b727b9230370cc9edd"),
            [0; 48],
            hex48("7b8ce46e415acf0241046b21b4624e06fad196c737f287a42cf2d842c867b61aa5bee9a83171f033d1873ebd3e37865e"),
        ]
    }

    #[tokio::test]
    async fn a_kernel_report_verifies_with_its_registers() {
        let r = verify_kmr(KMR_REPORT, KMR_EVENT_LOG, KMR_CALLER_DATA, kmr_expected()).await;
        assert_eq!(r.report_data_match, Some(true));
        assert_eq!(r.measurement_registers.as_ref().unwrap().event_count, 3);
        assert_eq!(r.measurement_registers_match, Some(true));
        assert!(r.passed());

        let mut other_caller = KMR_CALLER_DATA.to_vec();
        other_caller[0] ^= 1;
        let r = verify_kmr(KMR_REPORT, KMR_EVENT_LOG, &other_caller, kmr_expected()).await;
        assert!(r.measurement_registers.is_none() && !r.passed());

        let mut other_log = KMR_EVENT_LOG.to_vec();
        other_log[60] ^= 1;
        let r = verify_kmr(KMR_REPORT, &other_log, KMR_CALLER_DATA, kmr_expected()).await;
        assert!(r.measurement_registers.is_none() && !r.passed());

        let mut other_expected = kmr_expected();
        other_expected.truncate(3);
        let r = verify_kmr(KMR_REPORT, KMR_EVENT_LOG, KMR_CALLER_DATA, other_expected).await;
        assert_eq!(r.measurement_registers_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn the_earliest_kernel_report_commits_to_zero_registers() {
        let r = verify_kmr(KMR_BOOT_REPORT, &[], KMR_BOOT_CALLER_DATA, vec![]).await;
        assert_eq!(r.measurement_registers.as_ref().unwrap().event_count, 0);
        assert_eq!(r.measurement_registers_match, Some(true));
        assert!(r.passed());
    }

    // The kernel guest's full log: 4096 events, then extend fails with ENOSPC.
    const KMR_FULL_REPORT: &[u8] = include_bytes!("../../../test_data/snp/kmr-full-report.bin");
    const KMR_FULL_EVENT_LOG: &[u8] =
        include_bytes!("../../../test_data/snp/kmr-full-event-log.bin");
    const KMR_FULL_CALLER_DATA: &[u8] =
        include_bytes!("../../../test_data/snp/kmr-full-caller-data.bin");
    /// The 16 final registers, replayed by an independent hashlib script.
    const KMR_FULL_REGISTERS: &[u8] =
        include_bytes!("../../../test_data/snp/kmr-full-registers.bin");

    fn kmr_full_params() -> SnpParams {
        SnpParams {
            report_data: Some(KMR_FULL_CALLER_DATA.to_vec()),
            launch_digest: Some(vec![parse_report(KMR_FULL_REPORT).unwrap().measurement]),
            measurement_registers: Some(KMR_FULL_REGISTERS.as_chunks::<48>().0.to_vec()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_full_kernel_log_verifies() {
        assert_eq!(
            KMR_FULL_EVENT_LOG.len(),
            4096 * measurement_registers::ENTRY_LEN
        );
        let encoded = BASE64.encode(KMR_FULL_EVENT_LOG).len();
        assert!(
            encoded < crate::utils::MAX_EVIDENCE_FIELD_SIZE / 3,
            "{encoded}"
        );
        let r = verify_kmr_with(KMR_FULL_REPORT, KMR_FULL_EVENT_LOG, &kmr_full_params()).await;
        let registers = r.measurement_registers.as_ref().unwrap();
        assert_eq!(registers.event_count, 4096);
        assert!(registers.registers.iter().all(|r| *r != [0; 48]));
        assert_eq!(r.measurement_registers_match, Some(true));
        assert!(r.passed());

        let mut other = kmr_full_params();
        other.measurement_registers.as_mut().unwrap()[15][47] ^= 1;
        let r = verify_kmr_with(KMR_FULL_REPORT, KMR_FULL_EVENT_LOG, &other).await;
        assert_eq!(r.measurement_registers_match, Some(false));
        assert!(!r.passed());
    }

    #[tokio::test]
    async fn a_full_log_follows_the_error_contract() {
        let params = kmr_full_params();
        let log = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut log = KMR_FULL_EVENT_LOG.to_vec();
            change(&mut log);
            log
        };
        // Bytes that are not whole entries are malformed, whatever the count.
        for junk in [1, 48] {
            let bad = log(&|l| l.extend(vec![0; junk]));
            let err = try_verify_kmr(KMR_FULL_REPORT, &bad, &params).await;
            assert!(
                matches!(err, Err(AttestationError::EvidenceDeserialize(_))),
                "{junk} trailing bytes: {err:?}"
            );
        }
        // A whole entry past the count is not attested and changes nothing.
        let longer = log(&|l| {
            l.push(3);
            l.extend([9; 48]);
        });
        let r = verify_kmr_with(KMR_FULL_REPORT, &longer, &params).await;
        assert_eq!(r.measurement_registers.as_ref().unwrap().event_count, 4096);
        assert!(r.passed());
        // A log shorter than the count is a mismatch, not an error.
        for shorter in [
            log(&|l| l.truncate(4095 * measurement_registers::ENTRY_LEN)),
            Vec::new(),
        ] {
            let r = verify_kmr_with(KMR_FULL_REPORT, &shorter, &params).await;
            assert_eq!(r.report_data_match, Some(false));
            assert!(r.measurement_registers.is_none() && !r.passed());
        }
    }

    #[tokio::test]
    async fn snp_verify_refuses_params_validate_refuses() {
        let ok = kmr_full_params();
        assert!(verify_kmr_with(KMR_FULL_REPORT, KMR_FULL_EVENT_LOG, &ok)
            .await
            .passed());
        let bad = [
            SnpParams {
                max_vmpl: 1,
                ..ok.clone()
            },
            SnpParams {
                measurement_registers: Some(vec![[1; 48]; 17]),
                ..ok.clone()
            },
            SnpParams {
                report_data: Some(vec![7; 63]),
                ..ok.clone()
            },
            SnpParams {
                launch_digest: None,
                ..ok.clone()
            },
        ];
        for params in bad {
            let r = try_verify_kmr(KMR_FULL_REPORT, KMR_FULL_EVENT_LOG, &params).await;
            assert!(
                matches!(r, Err(AttestationError::InvalidParams(_))),
                "{params:?}: {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_event_log_above_the_field_limit_is_refused() {
        // Whole zero entries, just over the 1 MiB base64 limit: without the
        // limit this decodes to a well-formed log that is only a mismatch.
        let log = vec![0; 147 * 5350];
        assert!(BASE64.encode(&log).len() > crate::utils::MAX_EVIDENCE_FIELD_SIZE);
        let r = try_verify_kmr(KMR_FULL_REPORT, &log, &kmr_full_params()).await;
        assert!(
            matches!(&r, Err(AttestationError::EvidenceDeserialize(m)) if m.contains("too large")),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn a_kernel_report_above_vmpl_0_fails() {
        macro_rules! kmr_vmpl {
            ($file:literal) => {
                include_bytes!(concat!("../../../test_data/snp/kmr-vmpl/", $file)).as_slice()
            };
        }
        // The expectation is the log's own replay, so only the VMPL can fail.
        let params = |report: &[u8], log: &[u8], caller_data: &[u8]| {
            let count = u32::from_le_bytes(
                parse_report(report).unwrap().report_data[..4]
                    .try_into()
                    .unwrap(),
            );
            SnpParams {
                report_data: Some(caller_data.to_vec()),
                launch_digest: Some(vec![parse_report(report).unwrap().measurement]),
                measurement_registers: Some(
                    measurement_registers::replay(log, count)
                        .unwrap()
                        .unwrap()
                        .to_vec(),
                ),
                ..Default::default()
            }
        };
        let (report, log, caller) = (
            kmr_vmpl!("vmpl0.report.bin"),
            kmr_vmpl!("vmpl0.event-log.bin"),
            kmr_vmpl!("vmpl0.caller-data.bin"),
        );
        let r = verify_kmr_with(report, log, &params(report, log, caller)).await;
        assert_eq!(r.vmpl, 0);
        assert!(r.passed() && r.measurement_registers.is_some());

        let (log, caller) = (kmr_vmpl!("event-log.bin"), kmr_vmpl!("caller-data.bin"));
        for (report, vmpl) in [
            (kmr_vmpl!("vmpl1.report.bin"), 1),
            (kmr_vmpl!("vmpl2.report.bin"), 2),
            (kmr_vmpl!("vmpl3.report.bin"), 3),
            (kmr_vmpl!("vmpl4.report.bin"), 4),
            (kmr_vmpl!("privlevel1.report.bin"), 1),
            (kmr_vmpl!("privlevel2.report.bin"), 2),
            (kmr_vmpl!("privlevel3.report.bin"), 3),
        ] {
            let r = verify_kmr_with(report, log, &params(report, log, caller)).await;
            assert_eq!(r.vmpl, vmpl);
            assert_eq!(r.report_data_match, Some(true), "VMPL {vmpl}");
            assert_eq!(r.measurement_registers_match, Some(true), "VMPL {vmpl}");
            assert!(!r.passed(), "VMPL {vmpl}");
            assert!(r.measurement_registers.is_none(), "VMPL {vmpl}");
        }
    }

    /// Guest root on an image without the provider passes a forged `H || C`
    /// as its report data. Only the launch digest pin tells it apart.
    #[tokio::test]
    async fn a_forged_commitment_passes_only_where_its_image_is_pinned() {
        let report = include_bytes!("../../../test_data/snp/kmr-forge/report.bin");
        let log = include_bytes!("../../../test_data/snp/kmr-forge/event-log.bin");
        let caller = include_bytes!("../../../test_data/snp/kmr-forge/caller-data.bin");
        let hex48 = |s: &str| -> [u8; 48] { hex::decode(s).unwrap().try_into().unwrap() };
        let forged = vec![
            [0; 48],
            hex48("faef475db093da0bf48d02e58db273cf2efd9cc33fea6f75c86b094c9f2352b73c7021e4629e7f784f97893febebfc0d"),
            [0; 48],
            [0; 48],
            hex48("9447d432169ab5914449fe9c0cc297b1ed8fca7b9a934151a81d174ab72df392fdd6e0305ff7c1587254f511381d9efa"),
        ];
        let image = parse_report(report).unwrap().measurement;
        let provider = hex48("3dc918aabbb74ba2b8e16f5796bbf7c49b56057ed828f0197658b70cb6a02d2f7e933097d21f7cfab17db4232d449523");
        let params = |launch_digest: Vec<[u8; 48]>| SnpParams {
            report_data: Some(caller.to_vec()),
            launch_digest: Some(launch_digest),
            measurement_registers: Some(forged.clone()),
            ..Default::default()
        };

        let r = verify_kmr_with(report, log, &params(vec![provider])).await;
        assert_eq!(r.launch_digest_match, Some(false));
        assert_eq!(r.report_data_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());

        // Pinning the image without the provider, even next to a provider
        // image, accepts the forged registers.
        let r = verify_kmr_with(report, log, &params(vec![provider, image])).await;
        assert_eq!(
            r.measurement_registers.as_ref().unwrap().registers[..5],
            forged[..]
        );
        assert!(r.passed());
    }

    #[test]
    fn a_debug_guest_shows_registers_only_when_debug_is_allowed() {
        let mut report = parse_report(KMR_REPORT).unwrap();
        report.policy.set_debug_allowed(true);
        let check = |allow_debug: bool| {
            let params = SnpParams {
                launch_digest: Some(vec![report.measurement]),
                allow_debug,
                ..Default::default()
            };
            let mut result = evaluate_report(&report, &params, Some(true));
            check_measurement_registers(
                &mut result,
                &report.report_data,
                Some(&BASE64.encode(KMR_EVENT_LOG)),
                KMR_CALLER_DATA.try_into().unwrap(),
                &kmr_expected(),
            )
            .unwrap();
            result
        };
        let r = check(true);
        assert!(r.passed() && r.measurement_registers.is_some());
        let r = check(false);
        assert_eq!(r.measurement_registers_match, Some(true));
        assert!(!r.passed() && r.measurement_registers.is_none());
    }

    #[tokio::test]
    async fn registers_are_not_exposed_when_the_launch_digest_pin_fails() {
        let mut params = SnpParams {
            report_data: Some(KMR_CALLER_DATA.to_vec()),
            launch_digest: Some(vec![parse_report(KMR_REPORT).unwrap().measurement]),
            measurement_registers: Some(kmr_expected()),
            ..Default::default()
        };
        let r = verify_kmr_with(KMR_REPORT, KMR_EVENT_LOG, &params).await;
        assert!(r.measurement_registers.is_some() && r.passed());

        params.launch_digest = Some(vec![[0x77; 48]]);
        let r = verify_kmr_with(KMR_REPORT, KMR_EVENT_LOG, &params).await;
        assert_eq!(r.launch_digest_match, Some(false));
        assert_eq!(r.report_data_match, Some(false));
        assert_eq!(r.measurement_registers_match, Some(false));
        assert!(r.measurement_registers.is_none() && !r.passed());
    }

    #[tokio::test]
    async fn test_verify_evidence_wrong_launch_digest_is_some_false() {
        // Wrong digest must record Some(false) without failing verification.
        let params = SnpParams {
            launch_digest: Some(vec![[0xAA; 48]]),
            ..Default::default()
        };
        let r = verify(&params).await.unwrap();
        assert_eq!(r.launch_digest_match, Some(false));
        assert!(!r.passed());
    }
}
