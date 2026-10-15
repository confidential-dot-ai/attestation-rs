//! Google's signed launch endorsements for GCE Confidential VM firmware.
//!
//! For each firmware (OVMF) build, Google publishes a `VMLaunchEndorsement`
//! protobuf at `gs://gce_tcb_integrity/ovmf_x64_csm/{tdx,sevsnp}/<hex>.binarypb`,
//! named by the TDX MRTD or SEV-SNP launch measurement. It signs a
//! `VMGoldenMeasurement` that lists every MRTD (per RAM size) and SNP
//! measurement (per launch VMSA count) of that build. The checks follow
//! github.com/google/gce-tcb-verifier: `verify.EndorsementProto` for the
//! endorsement itself, and `gcetcbendorsement tdx/sev validate` for matching
//! it to evidence (any endorsed RAM size / VMSA count is accepted).

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use der::oid::db::rfc5912::{ID_MGF_1, ID_RSASSA_PSS, ID_SHA_256};
use der::{Decode, Encode, Tag, Tagged};
use rsa::pkcs1::RsaPssParams;
use rsa::pss::{Signature, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::Sha256;
use signature::Verifier as _;
use spki::DecodePublicKey;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
use x509_cert::{Certificate, TbsCertificate};

use crate::error::{AttestationError, Result};
use crate::types::{AttestationEvidence, PlatformType};

/// GCE-cc-tcb-root_1, from <https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt>
/// (SHA-256 e876bc69...f0b18c). Endorsement signing certs are issued by it directly.
const GCE_TCB_ROOT: &[u8] = include_bytes!("../../certs/google/GCE-cc-tcb-root_1.der");

/// Subject CN of the certificate Google signs launch endorsements with.
const SIGNER_CN: &str = "GCE-uefi-signer";

/// Public HTTPS location of the `gce_tcb_integrity` bucket's endorsements.
pub const GCE_TCB_INTEGRITY_URL: &str =
    "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";

/// Golden measurements signed after this time (2024-08-02T00:00:00Z) must name
/// the source they were built from (`cl_spec` or `commit`).
const PROVENANCE_REQUIRED_AFTER: i64 = 1_722_556_800;

/// The signed contents of a launch endorsement (`VMGoldenMeasurement`), with
/// the fields this crate uses.
#[derive(Debug, Clone, Default)]
pub struct GoldenMeasurement {
    /// Signing time, Unix seconds.
    pub timestamp: i64,
    /// Changelist number the firmware was built from.
    pub cl_spec: u64,
    /// Commit hash the firmware was built from.
    pub commit: Vec<u8>,
    /// DER certificate of the signing key.
    pub cert: Vec<u8>,
    /// SHA-384 of the firmware binary.
    pub digest: Vec<u8>,
    pub sev_snp: Option<SevSnpGolden>,
    pub tdx: Option<TdxGolden>,
}

#[derive(Debug, Clone, Default)]
pub struct SevSnpGolden {
    pub svn: u32,
    /// Launch measurement by number of VMSAs (vCPUs) at launch.
    pub measurements: BTreeMap<u32, Vec<u8>>,
    /// Guest policy the firmware is launched with.
    pub policy: u64,
    /// Launch measurement when started under an SVSM.
    pub svsm_measurement: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct TdxGolden {
    pub svn: u32,
    pub measurements: Vec<TdxGoldenMeasurement>,
}

#[derive(Debug, Clone, Default)]
pub struct TdxGoldenMeasurement {
    pub ram_gib: u32,
    pub early_accept: bool,
    pub mrtd: Vec<u8>,
}

impl SevSnpGolden {
    /// Every endorsed launch measurement: one per launch VMSA count, and the
    /// SVSM one if present.
    pub fn endorsed(&self) -> impl Iterator<Item = &[u8]> {
        let svsm = Some(&self.svsm_measurement[..]).filter(|m| !m.is_empty());
        self.measurements.values().map(Vec::as_slice).chain(svsm)
    }

    /// Whether `measurement` is endorsed for any launch VMSA count.
    pub fn endorses(&self, measurement: &[u8]) -> bool {
        self.endorsed().any(|m| m == measurement)
    }
}

impl TdxGolden {
    /// Every endorsed MRTD, one per RAM size.
    pub fn endorsed(&self) -> impl Iterator<Item = &[u8]> {
        self.measurements.iter().map(|m| m.mrtd.as_slice())
    }

    /// Whether `mrtd` is endorsed for any RAM size.
    pub fn endorses(&self, mrtd: &[u8]) -> bool {
        self.endorsed().any(|m| m == mrtd)
    }
}

/// Verifies a serialized `VMLaunchEndorsement` and returns its golden
/// measurement: the signing certificate must be Google's `GCE-uefi-signer`,
/// issued by the pinned GCE-cc-tcb-root and valid at `now` (Unix seconds), and
/// its key must sign the golden measurement (RSASSA-PSS, SHA-256). The
/// endorsement is a caller param, so one that does not verify is
/// [`AttestationError::InvalidParams`].
pub fn verify_endorsement(endorsement: &[u8], now: i64) -> Result<GoldenMeasurement> {
    let (golden, (not_before, not_after)) = check_endorsement(endorsement).map_err(|reason| {
        AttestationError::InvalidParams(format!("GCE launch endorsement: {reason}"))
    })?;
    if !(not_before..=not_after).contains(&now) {
        return Err(AttestationError::InvalidParams(format!(
            "GCE launch endorsement: signing cert is not valid at {now} (valid {not_before}..{not_after})"
        )));
    }
    Ok(golden)
}

/// Checks an endorsement's signature, signer role and provenance, and returns
/// its golden measurement with the window (Unix seconds) in which both the
/// signing cert and the root are valid.
pub(crate) fn check_endorsement(
    endorsement: &[u8],
) -> std::result::Result<(GoldenMeasurement, (i64, i64)), String> {
    let golden_bytes = last_bytes(endorsement, 1)?.ok_or("no serialized_uefi_golden")?;
    let signature = last_bytes(endorsement, 2)?.ok_or("no signature")?;
    let cert = last_bytes(golden_bytes, 4)?.ok_or("no signing cert")?;
    let signature = Signature::try_from(signature).map_err(|e| format!("signature: {e}"))?;
    let (key, window) = signer_key(cert)?;
    VerifyingKey::<Sha256>::new(key)
        .verify(golden_bytes, &signature)
        .map_err(|_| "signature does not verify")?;

    let golden = parse_golden(golden_bytes)?;
    if golden.timestamp > PROVENANCE_REQUIRED_AFTER
        && golden.cl_spec == 0
        && golden.commit.is_empty()
    {
        return Err("missing provenance (cl_spec or commit)".into());
    }
    Ok((golden, window))
}

/// The last value of length-delimited field `number` in `message`.
fn last_bytes(message: &[u8], number: u64) -> std::result::Result<Option<&[u8]>, String> {
    let mut value = None;
    for (n, field) in fields(message)? {
        if n == number {
            value = Some(field.bytes()?);
        }
    }
    Ok(value)
}

/// Checks the signing certificate against the pinned root and the signer
/// role, and returns its key and the window in which it and the root are
/// valid.
fn signer_key(cert_der: &[u8]) -> std::result::Result<(RsaPublicKey, (i64, i64)), String> {
    let root =
        Certificate::from_der(GCE_TCB_ROOT).map_err(|e| format!("bundled GCE-cc-tcb-root: {e}"))?;
    let cert = Certificate::from_der(cert_der).map_err(|e| format!("cert: {e}"))?;
    if cert.tbs_certificate.issuer != root.tbs_certificate.subject {
        return Err("cert is not issued by GCE-cc-tcb-root".into());
    }
    check_pss_sha256(&cert)?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| format!("cert: {e}"))?;
    let cert_signature = Signature::try_from(cert.signature.raw_bytes())
        .map_err(|e| format!("cert signature: {e}"))?;
    VerifyingKey::<Sha256>::new(rsa_key(&root)?)
        .verify(&tbs, &cert_signature)
        .map_err(|_| "cert is not signed by GCE-cc-tcb-root")?;
    let unix = |t: x509_cert::time::Time| {
        i64::try_from(t.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
    };
    let mut window = (i64::MIN, i64::MAX);
    for c in [&root, &cert] {
        let validity = &c.tbs_certificate.validity;
        window.0 = window.0.max(unix(validity.not_before));
        window.1 = window.1.min(unix(validity.not_after));
    }
    check_signer_role(&cert.tbs_certificate)?;
    Ok((rsa_key(&cert)?, window))
}

/// The cert must be signed with RSASSA-PSS over SHA-256, MGF1-SHA-256 and a
/// 32-byte salt: the parameters the verification above assumes.
fn check_pss_sha256(cert: &Certificate) -> std::result::Result<(), String> {
    let algorithm = &cert.signature_algorithm;
    if algorithm.oid != ID_RSASSA_PSS {
        return Err(format!(
            "cert signature algorithm {} is not RSASSA-PSS",
            algorithm.oid
        ));
    }
    let params: RsaPssParams<'_> = algorithm
        .parameters
        .as_ref()
        .ok_or("cert has no RSASSA-PSS parameters")?
        .decode_as()
        .map_err(|e| format!("cert RSASSA-PSS parameters: {e}"))?;
    let mgf_hash = params.mask_gen.parameters.map(|hash| hash.oid);
    if params.hash.oid != ID_SHA_256
        || params.mask_gen.oid != ID_MGF_1
        || mgf_hash != Some(ID_SHA_256)
        || params.salt_len != 32
    {
        return Err("cert RSASSA-PSS parameters are not SHA-256, MGF1-SHA-256, salt 32".into());
    }
    Ok(())
}

/// The cert must be the endorsement signer: subject CN `GCE-uefi-signer`, a
/// digitalSignature key usage, and not a CA.
fn check_signer_role(tbs: &TbsCertificate) -> std::result::Result<(), String> {
    let common_name = tbs
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid == der::oid::db::rfc4519::CN)
        .filter(|atv| matches!(atv.value.tag(), Tag::Utf8String | Tag::PrintableString))
        .map(|atv| atv.value.value());
    if common_name != Some(SIGNER_CN.as_bytes()) {
        return Err(format!("cert subject {} is not {SIGNER_CN}", tbs.subject));
    }
    let key_usage = tbs
        .get::<KeyUsage>()
        .map_err(|e| format!("cert key usage: {e}"))?;
    if !key_usage.is_some_and(|(_, usage)| usage.digital_signature()) {
        return Err("cert key usage does not allow digitalSignature".into());
    }
    let constraints = tbs
        .get::<BasicConstraints>()
        .map_err(|e| format!("cert basic constraints: {e}"))?;
    if !matches!(constraints, Some((_, BasicConstraints { ca: false, .. }))) {
        return Err("cert is not marked cA=false".into());
    }
    Ok(())
}

fn rsa_key(cert: &Certificate) -> std::result::Result<RsaPublicKey, String> {
    let spki = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("cert key: {e}"))?;
    RsaPublicKey::from_public_key_der(&spki).map_err(|e| format!("cert key: {e}"))
}

/// Whether the endorsement lists `mrtd` (for any RAM size).
#[cfg(feature = "gcp-tdx")]
pub(crate) fn endorses_tdx(golden: &GoldenMeasurement, mrtd: &[u8]) -> bool {
    golden.tdx.as_ref().is_some_and(|tdx| tdx.endorses(mrtd))
}

/// Whether the endorsement lists the launch `measurement` (for any VMSA
/// count) and the guest `policy` is no more permissive than the endorsed one,
/// as `gcetcbendorsement sev validate` checks.
#[cfg(feature = "gcp-snp")]
pub(crate) fn endorses_snp(golden: &GoldenMeasurement, measurement: &[u8], policy: u64) -> bool {
    let Some(snp) = &golden.sev_snp else {
        return false;
    };
    if let Err(reason) = check_snp_policy(policy, snp.policy) {
        log::warn!("gcp-snp: {reason}");
        return false;
    }
    snp.endorses(measurement)
}

/// The report's guest policy must not grant more than the endorsed policy, as
/// go-sev-guest's `validatePolicy` checks it.
#[cfg(feature = "gcp-snp")]
fn check_snp_policy(policy: u64, endorsed: u64) -> std::result::Result<(), String> {
    // SMT, MIGRATE_MA, DEBUG, CXL_ALLOW.
    const GRANTS: u64 = 1 << 16 | 1 << 18 | 1 << 19 | 1 << 21;
    // SINGLE_SOCKET, MEM_AES_256_XTS, RAPL_DIS, CIPHERTEXT_HIDING_DRAM, PAGE_SWAP_DISABLE.
    const RESTRICTIONS: u64 = 1 << 20 | 1 << 22 | 1 << 23 | 1 << 24 | 1 << 25;
    // ABI_MAJOR.ABI_MINOR in the low 16 bits.
    const ABI: u64 = 0xffff;
    if (policy & !endorsed & GRANTS) != 0
        || (endorsed & !policy & RESTRICTIONS) != 0
        || (policy & ABI) < (endorsed & ABI)
    {
        return Err(format!(
            "guest policy {policy:#x} exceeds the endorsed policy {endorsed:#x}"
        ));
    }
    Ok(())
}

#[cfg(feature = "gcp-tdx")]
pub(crate) fn tdx_mrtd(
    evidence: &crate::platforms::tdx::evidence::TdxEvidence,
) -> Result<[u8; 48]> {
    let quote = BASE64
        .decode(&evidence.quote)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("quote base64: {e}")))?;
    Ok(crate::platforms::tdx::verify::parse_tdx_quote(&quote)?
        .body
        .mr_td)
}

#[cfg(feature = "gcp-snp")]
pub(crate) fn snp_report(
    evidence: &crate::platforms::snp::evidence::SnpEvidence,
) -> Result<sev::firmware::guest::AttestationReport> {
    let report = BASE64
        .decode(&evidence.attestation_report)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("base64 decode: {e}")))?;
    crate::platforms::snp::verify::parse_report(&report)
}

/// URL of the endorsement for the firmware that produced `evidence_json` (a
/// gcp-tdx or gcp-snp [`AttestationEvidence`](crate::types::AttestationEvidence)
/// envelope), named by its MRTD or launch measurement.
pub fn endorsement_url(evidence_json: &[u8]) -> Result<String> {
    let envelope: AttestationEvidence = serde_json::from_slice(evidence_json)
        .map_err(|e| AttestationError::EvidenceDeserialize(e.to_string()))?;
    let deserialize = |e: serde_json::Error| AttestationError::EvidenceDeserialize(e.to_string());
    let (dir, measurement) = match envelope.platform {
        #[cfg(feature = "gcp-tdx")]
        PlatformType::GcpTdx => (
            "tdx",
            tdx_mrtd(&serde_json::from_value(envelope.evidence).map_err(deserialize)?)?.to_vec(),
        ),
        #[cfg(feature = "gcp-snp")]
        PlatformType::GcpSnp => (
            "sevsnp",
            snp_report(&serde_json::from_value(envelope.evidence).map_err(deserialize)?)?
                .measurement
                .to_vec(),
        ),
        other => {
            return Err(AttestationError::InvalidParams(format!(
                "Google publishes launch endorsements for gcp-tdx and gcp-snp, not {other}"
            )))
        }
    };
    Ok(format!(
        "{GCE_TCB_INTEGRITY_URL}/{dir}/{}.binarypb",
        hex::encode(measurement)
    ))
}

/// Downloads an endorsement from `url` (see [`endorsement_url`]) and checks
/// that it verifies now. A download that fails or does not verify is
/// [`AttestationError::CollateralUnavailable`]. Pass the bytes as the
/// `endorsement` param.
#[cfg(not(target_arch = "wasm32"))]
pub async fn fetch_endorsement(url: &str) -> Result<Vec<u8>> {
    let timeouts = crate::collateral::HttpTimeouts::default();
    let client = reqwest::Client::builder()
        .timeout(timeouts.request_timeout)
        .connect_timeout(timeouts.connect_timeout)
        .build()
        .map_err(|e| AttestationError::CollateralUnavailable(format!("HTTP client: {e}")))?;
    let response = crate::collateral::send_get(&client, url).await?;
    let endorsement = crate::collateral::read_response_with_limit(response).await?;
    verify_endorsement(&endorsement, chrono::Utc::now().timestamp())
        .map_err(|e| AttestationError::CollateralUnavailable(format!("{url}: {e}")))?;
    Ok(endorsement)
}

// ── Minimal protobuf decoding ──
// The endorsement messages use only varint and length-delimited fields;
// fixed-width fields are skipped, groups are rejected.

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

impl<'a> Field<'a> {
    fn varint(&self) -> std::result::Result<u64, String> {
        match self {
            Field::Varint(v) => Ok(*v),
            _ => Err("protobuf: expected a varint field".to_string()),
        }
    }

    /// A varint that must fit `T` (uint32, int64 >= 0, ...).
    fn int<T: TryFrom<u64>>(&self) -> std::result::Result<T, String> {
        T::try_from(self.varint()?).map_err(|_| "protobuf: integer out of range".to_string())
    }

    fn bytes(&self) -> std::result::Result<&'a [u8], String> {
        match self {
            Field::Bytes(b) => Ok(b),
            _ => Err("protobuf: expected a length-delimited field".to_string()),
        }
    }
}

/// Splits a protobuf message into (field number, value) pairs.
fn fields(mut buf: &[u8]) -> std::result::Result<Vec<(u64, Field<'_>)>, String> {
    fn varint(buf: &mut &[u8]) -> std::result::Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = buf
                .split_first()
                .ok_or_else(|| "protobuf: truncated varint".to_string())?;
            *buf = rest;
            if shift == 63 && byte > 1 {
                return Err("protobuf: varint overflows 64 bits".to_string());
            }
            if shift > 0 && byte == 0 {
                return Err("protobuf: over-long varint".to_string());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("protobuf: varint too long".to_string())
    }
    fn take<'a>(buf: &mut &'a [u8], len: u64) -> std::result::Result<&'a [u8], String> {
        let len = usize::try_from(len)
            .ok()
            .filter(|&l| l <= buf.len())
            .ok_or_else(|| "protobuf: truncated field".to_string())?;
        let (head, rest) = buf.split_at(len);
        *buf = rest;
        Ok(head)
    }

    let mut out = Vec::new();
    while !buf.is_empty() {
        let key = varint(&mut buf)?;
        if key >> 3 == 0 {
            return Err("protobuf: field number 0".to_string());
        }
        let field = match key & 7 {
            0 => Field::Varint(varint(&mut buf)?),
            1 => take(&mut buf, 8).map(|_| Field::Fixed)?,
            2 => {
                let len = varint(&mut buf)?;
                Field::Bytes(take(&mut buf, len)?)
            }
            5 => take(&mut buf, 4).map(|_| Field::Fixed)?,
            wire_type => return Err(format!("protobuf: unsupported wire type {wire_type}")),
        };
        out.push((key >> 3, field));
    }
    Ok(out)
}

fn parse_golden(buf: &[u8]) -> std::result::Result<GoldenMeasurement, String> {
    let mut golden = GoldenMeasurement::default();
    for (number, field) in fields(buf)? {
        match number {
            1 => {
                // google.protobuf.Timestamp { int64 seconds = 1; int32 nanos = 2; }
                for (n, f) in fields(field.bytes()?)? {
                    if n == 1 {
                        golden.timestamp = f.int()?;
                    }
                }
            }
            2 => golden.cl_spec = field.varint()?,
            3 => golden.commit = field.bytes()?.to_vec(),
            4 => golden.cert = field.bytes()?.to_vec(),
            5 => golden.digest = field.bytes()?.to_vec(),
            7 => golden.sev_snp = Some(parse_sev_snp(field.bytes()?)?),
            8 => golden.tdx = Some(parse_tdx(field.bytes()?)?),
            _ => {}
        }
    }
    Ok(golden)
}

/// Runs the reader over `data` as an unverified golden measurement, for the
/// cargo-fuzz target in `crates/attestation/fuzz`.
#[cfg(fuzzing)]
pub fn fuzz_parse_golden(data: &[u8]) {
    let _ = parse_golden(data);
}

fn parse_sev_snp(buf: &[u8]) -> std::result::Result<SevSnpGolden, String> {
    let mut snp = SevSnpGolden::default();
    for (number, field) in fields(buf)? {
        match number {
            1 => snp.svn = field.int()?,
            2 => {
                // map<uint32, bytes> entry { key = 1; value = 2; }
                let (mut key, mut value) = (0, Vec::new());
                for (n, f) in fields(field.bytes()?)? {
                    match n {
                        1 => key = f.int()?,
                        2 => value = f.bytes()?.to_vec(),
                        _ => {}
                    }
                }
                snp.measurements.insert(key, value);
            }
            5 => snp.policy = field.varint()?,
            7 => snp.svsm_measurement = field.bytes()?.to_vec(),
            _ => {}
        }
    }
    Ok(snp)
}

fn parse_tdx(buf: &[u8]) -> std::result::Result<TdxGolden, String> {
    let mut tdx = TdxGolden::default();
    for (number, field) in fields(buf)? {
        match number {
            1 => tdx.svn = field.int()?,
            2 => {
                let mut m = TdxGoldenMeasurement::default();
                for (n, f) in fields(field.bytes()?)? {
                    match n {
                        1 => m.ram_gib = f.int()?,
                        2 => m.early_accept = f.varint()? != 0,
                        3 => m.mrtd = f.bytes()?.to_vec(),
                        _ => {}
                    }
                }
                tdx.measurements.push(m);
            }
            _ => {}
        }
    }
    Ok(tdx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_integers_must_fit_their_type() {
        assert_eq!(Field::Varint(7).int::<u32>(), Ok(7));
        assert!(Field::Varint(u64::from(u32::MAX) + 1).int::<u32>().is_err());
        assert!(Field::Varint(u64::MAX).int::<i64>().is_err());
    }

    // Fetched from gs://gce_tcb_integrity/ovmf_x64_csm/ on 2026-10-12. The TDX
    // one is named by the MRTD of test_data/gcp_tdx/boot-quote.dat, the SNP one
    // by the launch measurement of test_data/gcp_snp/evidence-boot1.json. They
    // are two different firmware builds.
    const TDX_ENDORSEMENT: &[u8] =
        include_bytes!("../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");
    const SNP_ENDORSEMENT: &[u8] =
        include_bytes!("../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");
    const GCP_TDX_MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    const GCP_SNP_MEASUREMENT: &str = "0e017d2fba7c4964575fdd8c770061abf07f0753148d030f94e969a2d1fa5a5747ba0ced9174f2d44b5f6663fa2de00f";

    /// 2026-10-01T00:00:00Z. Both signing certs are valid 2026-05-05..2031-05-05.
    const NOW: i64 = 1_790_812_800;

    fn rejected(result: Result<GoldenMeasurement>) {
        let err = result.expect_err("endorsement must be rejected");
        assert!(matches!(err, AttestationError::InvalidParams(_)), "{err}");
    }

    fn len_field(number: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![number << 3 | 2];
        let mut len = bytes.len();
        while len >= 0x80 {
            out.push(len as u8 | 0x80);
            len >>= 7;
        }
        out.push(len as u8);
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn tdx_endorsement_endorses_the_gcp_tdx_mrtd() {
        let golden = verify_endorsement(TDX_ENDORSEMENT, NOW).unwrap();
        let tdx = golden.tdx.unwrap();
        assert!(tdx.endorses(&hex::decode(GCP_TDX_MRTD).unwrap()));
        assert!(!golden
            .sev_snp
            .unwrap()
            .endorses(&hex::decode(GCP_SNP_MEASUREMENT).unwrap()));
    }

    #[test]
    fn snp_endorsement_endorses_the_gcp_snp_measurement_for_2_vmsas() {
        let golden = verify_endorsement(SNP_ENDORSEMENT, NOW).unwrap();
        let snp = golden.sev_snp.unwrap();
        let measurement = hex::decode(GCP_SNP_MEASUREMENT).unwrap();
        assert!(snp.endorses(&measurement));
        assert_eq!(snp.measurements[&2], measurement);
        assert_eq!(snp.policy, 0x70000);
        assert!(!golden
            .tdx
            .unwrap()
            .endorses(&hex::decode(GCP_TDX_MRTD).unwrap()));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut endorsement = TDX_ENDORSEMENT.to_vec();
        *endorsement.last_mut().unwrap() ^= 1;
        rejected(verify_endorsement(&endorsement, NOW));
    }

    #[test]
    fn tampered_measurement_is_rejected() {
        let mrtd = hex::decode(GCP_TDX_MRTD).unwrap();
        let mut endorsement = TDX_ENDORSEMENT.to_vec();
        let at = endorsement
            .windows(mrtd.len())
            .position(|w| w == mrtd)
            .unwrap();
        endorsement[at] ^= 1;
        rejected(verify_endorsement(&endorsement, NOW));
    }

    #[test]
    fn signing_cert_outside_its_validity_is_rejected() {
        // 2026-05-01 and 2031-06-01.
        for now in [1_777_593_600, 1_938_124_800] {
            rejected(verify_endorsement(TDX_ENDORSEMENT, now));
        }
    }

    #[test]
    fn signing_cert_from_another_issuer_is_rejected() {
        let ark = include_bytes!("../../certs/amd/milan/ark.der");
        let golden = [len_field(3, b"commit"), len_field(4, ark)].concat();
        let endorsement = [len_field(1, &golden), len_field(2, &[0; 512])].concat();
        rejected(verify_endorsement(&endorsement, NOW));
    }

    #[test]
    fn truncated_endorsement_is_rejected() {
        rejected(verify_endorsement(&TDX_ENDORSEMENT[..100], NOW));
    }

    #[test]
    fn bundled_root_parses() {
        Certificate::from_der(GCE_TCB_ROOT).unwrap();
    }

    #[test]
    fn over_long_varints_are_rejected() {
        // Field 1 = 1, as one byte, padded to two, and overflowing in the 10th.
        assert!(fields(&[0x08, 0x01]).is_ok());
        assert!(fields(&[0x08, 0x81, 0x00]).is_err());
        assert!(fields(&[0x88, 0x00, 0x01]).is_err());
        let overflow = [
            0x08, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
        ];
        assert!(fields(&overflow).is_err());
        let max = [
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ];
        assert!(matches!(
            fields(&max).unwrap()[..],
            [(1, Field::Varint(u64::MAX))]
        ));
    }

    #[test]
    fn field_number_0_is_rejected() {
        assert!(fields(&[0x00, 0x01]).is_err());
        rejected(verify_endorsement(
            &[&[0x02, 0x00], TDX_ENDORSEMENT].concat(),
            NOW,
        ));
    }

    fn signer_cert() -> Certificate {
        let golden = last_bytes(TDX_ENDORSEMENT, 1).unwrap().unwrap();
        Certificate::from_der(last_bytes(golden, 4).unwrap().unwrap()).unwrap()
    }

    #[test]
    fn signer_cert_must_use_pss_sha256_salt_32() {
        let cert = signer_cert();
        check_pss_sha256(&cert).unwrap();
        let der = cert.to_der().unwrap();
        let sha256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let salt_32 = [0xa2, 0x03, 0x02, 0x01, 0x20];
        for (from, to) in
            [(&sha256[..], 8, 0x02), (&salt_32[..], 4, 0x40)].map(|(from, at, byte)| {
                let mut to = from.to_vec();
                to[at] = byte;
                (from, to)
            })
        {
            let mut der = der.clone();
            let mut at = 0;
            while let Some(i) = der[at..].windows(from.len()).position(|w| w == from) {
                der[at + i..at + i + from.len()].copy_from_slice(&to);
                at += i + from.len();
            }
            assert!(check_pss_sha256(&Certificate::from_der(&der).unwrap()).is_err());
        }
    }

    #[test]
    fn signer_cert_must_be_the_uefi_signer() {
        use rcgen::{
            BasicConstraints as Bc, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        };
        let cert = |cn: &str, usage: KeyUsagePurpose, is_ca: IsCa| {
            let mut params = CertificateParams::new(vec![]).unwrap();
            params.distinguished_name.push(DnType::CommonName, cn);
            params.key_usages = vec![usage];
            params.is_ca = is_ca;
            let der = params.self_signed(&KeyPair::generate().unwrap()).unwrap();
            Certificate::from_der(der.der()).unwrap().tbs_certificate
        };
        check_signer_role(&signer_cert().tbs_certificate).unwrap();
        let signing = KeyUsagePurpose::DigitalSignature;
        check_signer_role(&cert(SIGNER_CN, signing, IsCa::ExplicitNoCa)).unwrap();
        for tbs in [
            cert("GCE-other-signer", signing, IsCa::ExplicitNoCa),
            cert(SIGNER_CN, KeyUsagePurpose::KeyCertSign, IsCa::ExplicitNoCa),
            cert(SIGNER_CN, signing, IsCa::NoCa),
            cert(SIGNER_CN, signing, IsCa::Ca(Bc::Unconstrained)),
        ] {
            assert!(check_signer_role(&tbs).is_err(), "{}", tbs.subject);
        }
    }

    #[cfg(feature = "gcp-snp")]
    #[test]
    fn snp_policy_must_not_exceed_the_endorsed_policy() {
        // The GCP report (SMT) under the endorsed policy (SMT, MIGRATE_MA).
        check_snp_policy(0x30000, 0x70000).unwrap();
        check_snp_policy(0x70000, 0x70000).unwrap();
        // DEBUG, a higher endorsed ABI, a required SINGLE_SOCKET.
        for (policy, endorsed) in [(0xb0000, 0x70000), (0x30000, 0x70001), (0x30000, 0x170000)] {
            assert!(check_snp_policy(policy, endorsed).is_err(), "{policy:#x}");
        }
    }

    #[cfg(feature = "gcp-tdx")]
    #[test]
    fn endorsement_url_names_the_mrtd() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        let quote = include_bytes!("../../test_data/gcp_tdx/boot-quote.dat");
        let envelope = |platform: &str| {
            serde_json::to_vec(&serde_json::json!({
                "platform": platform,
                "evidence": { "quote": BASE64.encode(quote) },
            }))
            .unwrap()
        };
        assert_eq!(
            endorsement_url(&envelope("gcp-tdx")).unwrap(),
            format!("{GCE_TCB_INTEGRITY_URL}/tdx/{GCP_TDX_MRTD}.binarypb")
        );
        assert!(endorsement_url(&envelope("tdx")).is_err());
    }
}
