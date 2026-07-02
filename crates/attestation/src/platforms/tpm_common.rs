use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use rsa::pkcs1v15::VerifyingKey as RsaVerifyingKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "attest", target_os = "linux"))]
use std::sync::Once;

use crate::error::{AttestationError, Result};
use crate::types::{Claims, PlatformType, VerificationResult};
use crate::utils::strip_trailing_nulls;

/// Decoded TPM quote components: (signature, message, pcr_values).
pub type DecodedTpmQuote = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>);

/// The vTPM device path `az_cvm_vtpm` opens (`TctiNameConf::Device` default).
#[cfg(all(feature = "attest", target_os = "linux"))]
const VTPM_DEVICE_PATH: &str = "/dev/tpm0";

/// Azure sets this fixed value on all its VMs
#[cfg(all(feature = "attest", target_os = "linux"))]
const AZURE_CHASSIS_ASSET_TAG: &str = "7783-7084-3265-9085-8269-3286-77";

/// Whether an Azure vTPM is present and usable for SNP/TDX detection.
///
/// For mysterious reasons, Azure offers TEE attestation via a vTPM,
/// at device `/dev/tmp0`, exactly like a real bare metal machine with
/// a real TPM. To avoid sending Azure TEE messages to the real TPMs and
/// causing ERROR log lines, we see if we are on an Azure VM first.
#[cfg(all(feature = "attest", target_os = "linux"))]
pub fn azure_vtpm_available() -> bool {
    is_azure_cvm() && vtpm_device_accessible()
}

#[cfg(all(feature = "attest", target_os = "linux"))]
fn is_azure_cvm() -> bool {
    std::fs::read_to_string("/sys/class/dmi/id/chassis_asset_tag")
        .map(|tag| tag.trim() == AZURE_CHASSIS_ASSET_TAG)
        .unwrap_or(false)
}

#[cfg(all(feature = "attest", target_os = "linux"))]
static WARN_FOUND: Once = Once::new();

/// Whether the vTPM device exists and is readable/writable.
/// Warns if we can see a device but don't have permissions.
/// Uses a Once guard to avoid one warning each for snp and tdx.
#[cfg(all(feature = "attest", target_os = "linux"))]
fn vtpm_device_accessible() -> bool {
    let access = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(VTPM_DEVICE_PATH);
    let access_ok = access.is_ok();

    if access.is_err() {
        let exists = std::fs::exists(VTPM_DEVICE_PATH).unwrap_or(false);
        if exists {
            WARN_FOUND.call_once(|| {
                let e = access.unwrap_err();
                eprintln!(
                    "WARNING: found TPM device {} with error {}",
                    VTPM_DEVICE_PATH, e
                )
            });
        }
    };

    access_ok
}

// --- TPM algorithm constants ---

/// TPM_ALG_RSA
const TPM_ALG_RSA: u16 = 0x0001;

/// TPM_ALG_NULL (used for symmetric and scheme fields)
const TPM_ALG_NULL: u16 = 0x0010;

/// TPMS_ATTEST magic value: 0xFF544347 ("TCG\xFF")
const TPM_ATTEST_MAGIC: u32 = 0xFF544347;

/// Default RSA public exponent (65537 = 0x010001).
/// A zero exponent in TPM2B_PUBLIC means this default value.
const RSA_DEFAULT_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// Read a big-endian u16 from a byte slice at the given offset.
fn read_be_u16(data: &[u8], offset: usize, field: &str) -> Result<u16> {
    data.get(offset..offset + 2)
        .and_then(|s| s.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| AttestationError::QuoteParseFailed(format!("truncated at {field}")))
}

/// Read a big-endian u32 from a byte slice at the given offset.
fn read_be_u32(data: &[u8], offset: usize, field: &str) -> Result<u32> {
    data.get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| AttestationError::QuoteParseFailed(format!("truncated at {field}")))
}

// --- HCL report parsing ---

/// HCL report header magic: "HCLA".
const HCL_MAGIC: [u8; 4] = *b"HCLA";

/// Offset of the TEE report within the HCL report.
const HCL_TEE_REPORT_OFFSET: usize = 0x20;

/// Size of the TEE report area (both SNP and TDX use 1184 bytes).
const HCL_TEE_REPORT_SIZE: usize = 1184;

/// Size of the var_data header after the TEE report (5 × u32 LE).
const HCL_VARDATA_HEADER_SIZE: usize = 20;

/// HCL report type: AMD SEV-SNP.
pub const HCL_REPORT_TYPE_SNP: u32 = 2;

/// HCL report type: Intel TDX.
pub const HCL_REPORT_TYPE_TDX: u32 = 4;

/// Verify HCL var_data binding: report_data[..32] == SHA-256(var_data).
///
/// Shared between Azure SNP and Azure TDX verification paths.
pub fn verify_hcl_var_data_binding(report_data: &[u8], var_data: &[u8]) -> Result<()> {
    let hash = crate::utils::sha256(var_data);
    let report_data_prefix = report_data.get(..32).ok_or_else(|| {
        AttestationError::QuoteParseFailed("report_data shorter than 32 bytes".to_string())
    })?;
    if !crate::utils::constant_time_eq(report_data_prefix, &hash) {
        return Err(AttestationError::SignatureVerificationFailed(
            "HCL var_data binding failed: report_data[..32] != SHA-256(var_data)".to_string(),
        ));
    }
    Ok(())
}

/// Parsed HCL report data.
pub struct HclReportData {
    /// Raw TEE report bytes (1184 bytes).
    pub tee_report: Vec<u8>,
    /// Report type (2=SNP, 4=TDX).
    pub report_type: u32,
    /// Null-trimmed var_data content (JSON with JWK keys).
    pub var_data: Vec<u8>,
}

/// Parse an HCL report blob into its components.
///
/// The HCL report structure:
/// - Bytes 0x00..0x1F: Header (starts with "HCLA" magic)
/// - Bytes 0x20..0x4BF: TEE report (1184 bytes, SNP or TDX)
/// - Bytes 0x4C0..0x4D3: var_data header (20 bytes, 5 × LE u32)
///   - total_remaining, count, report_type, version, content_length
/// - Bytes 0x4D4..end: var_data content (JSON with JWK keys, null-padded)
pub fn parse_hcl_report(hcl_report: &[u8]) -> Result<HclReportData> {
    let tee_report_end = HCL_TEE_REPORT_OFFSET + HCL_TEE_REPORT_SIZE;
    let content_start = tee_report_end + HCL_VARDATA_HEADER_SIZE;

    if hcl_report.len() < content_start {
        return Err(AttestationError::QuoteParseFailed(format!(
            "HCL report too short: {} < {}",
            hcl_report.len(),
            content_start
        )));
    }

    if hcl_report[..4] != HCL_MAGIC {
        return Err(AttestationError::QuoteParseFailed(format!(
            "invalid HCL magic: {:02X}{:02X}{:02X}{:02X}",
            hcl_report[0], hcl_report[1], hcl_report[2], hcl_report[3]
        )));
    }

    let tee_report = hcl_report[HCL_TEE_REPORT_OFFSET..tee_report_end].to_vec();

    // Parse var_data header (all fields are little-endian u32)
    let header = &hcl_report[tee_report_end..content_start];
    let report_type = u32::from_le_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| AttestationError::QuoteParseFailed("HCL header slice".to_string()))?,
    );
    let content_length =
        u32::from_le_bytes(header[16..20].try_into().map_err(|_| {
            AttestationError::QuoteParseFailed("HCL content_length slice".to_string())
        })?) as usize;

    // Validate content_length against available data
    let available = hcl_report.len() - content_start;
    if content_length > available {
        return Err(AttestationError::QuoteParseFailed(format!(
            "HCL content_length ({content_length}) exceeds available data ({available})"
        )));
    }
    let bounded_len = content_length;

    // Extract content and trim trailing nulls
    let content = &hcl_report[content_start..content_start + bounded_len];
    let trimmed_len = content.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

    if trimmed_len == 0 {
        return Err(AttestationError::QuoteParseFailed(
            "HCL var_data is empty after null trimming".to_string(),
        ));
    }

    Ok(HclReportData {
        tee_report,
        report_type,
        var_data: content[..trimmed_len].to_vec(),
    })
}

/// Extract the AK public key (RSA modulus and exponent) from HCL var_data JSON.
///
/// The var_data contains JSON with a "keys" array. The AK public key
/// has `kid="HCLAkPub"` and `kty="RSA"`, with base64url-encoded `n`
/// (modulus) and `e` (exponent) fields.
pub fn extract_ak_pub_from_jwk_json(json_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let json: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| AttestationError::QuoteParseFailed(format!("HCL var_data JSON: {e}")))?;

    let keys = json["keys"].as_array().ok_or_else(|| {
        AttestationError::QuoteParseFailed("HCL var_data JSON missing 'keys' array".to_string())
    })?;

    for key in keys {
        let kid = key["kid"].as_str().unwrap_or("");
        let kty = key["kty"].as_str().unwrap_or("");

        if kid == "HCLAkPub" && kty == "RSA" {
            let n_b64 = key["n"].as_str().ok_or_else(|| {
                AttestationError::QuoteParseFailed("HCLAkPub missing 'n' field".to_string())
            })?;
            let e_b64 = key["e"].as_str().ok_or_else(|| {
                AttestationError::QuoteParseFailed("HCLAkPub missing 'e' field".to_string())
            })?;

            let modulus = BASE64URL.decode(n_b64).map_err(|e| {
                AttestationError::QuoteParseFailed(format!("HCLAkPub 'n' base64: {e}"))
            })?;
            let exponent = BASE64URL.decode(e_b64).map_err(|e| {
                AttestationError::QuoteParseFailed(format!("HCLAkPub 'e' base64: {e}"))
            })?;

            return Ok((modulus, exponent));
        }
    }

    Err(AttestationError::QuoteParseFailed(
        "HCL var_data JSON does not contain HCLAkPub RSA key".to_string(),
    ))
}

/// TPM quote data, shared between Azure SNP and Azure TDX platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// TPM signature bytes (hex encoded).
    pub signature: String,
    /// TPM Attest message bytes (hex encoded).
    pub message: String,
    /// PCR values (24 entries, each hex encoded SHA-256 digest).
    pub pcrs: Vec<String>,
}

/// Verify TPM quote signature using the AK public key from HCL var_data.
///
/// The Azure vTPM uses RSA 2048 with RSASSA-PKCS1-v1.5 and SHA-256 for
/// its Attestation Key (AK). The AK public key is embedded in the HCL
/// report's variable data, either as JWK JSON (real Azure format) or
/// as a TPM2B_PUBLIC structure (synthetic test data).
pub fn verify_tpm_signature(signature: &[u8], message: &[u8], var_data: &[u8]) -> Result<()> {
    // Extract the RSA public key: try JWK JSON first, fall back to TPM2B_PUBLIC
    let (modulus, exponent) = match extract_ak_pub_from_jwk_json(var_data) {
        Ok(result) => result,
        Err(jwk_err) => {
            log::debug!("JWK AK extraction failed, trying TPM2B_PUBLIC: {jwk_err}");
            extract_ak_pub_from_var_data(var_data)?
        }
    };

    let n = rsa::BigUint::from_bytes_be(&modulus);
    let e = rsa::BigUint::from_bytes_be(&exponent);

    let public_key = RsaPublicKey::new(n, e).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("construct RSA key: {e}"))
    })?;

    let verifying_key = RsaVerifyingKey::<sha2::Sha256>::new(public_key);

    let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("parse RSA sig: {e}"))
    })?;

    verifying_key.verify(message, &sig).map_err(|e| {
        AttestationError::SignatureVerificationFailed(format!("TPM RSA PKCS1v15 SHA-256: {e}"))
    })
}

/// Extract the AK public key (RSA modulus and exponent) from HCL var_data.
///
/// The var_data contains a TPM2B_PUBLIC structure. For Azure vTPM, the
/// key is RSA 2048 with exponent 65537.
///
/// TPM2B_PUBLIC layout:
/// - size: 2 bytes (BE)
/// - TPMT_PUBLIC:
///   - type: 2 bytes (BE) - TPM_ALG_RSA = 0x0001
///   - nameAlg: 2 bytes (BE) - TPM_ALG_SHA256 = 0x000B
///   - objectAttributes: 4 bytes
///   - authPolicy: 2 bytes size + data
///   - parameters (TPMS_RSA_PARMS):
///     - symmetric: 2 bytes (TPM_ALG_NULL = 0x0010)
///     - scheme: 2 bytes
///     - keyBits: 2 bytes (BE)
///     - exponent: 4 bytes (0 means 65537)
///   - unique (TPM2B_PUBLIC_KEY_RSA):
///     - size: 2 bytes
///     - modulus: size bytes
pub fn extract_ak_pub_from_var_data(var_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if var_data.len() < 14 {
        return Err(AttestationError::QuoteParseFailed(
            "var_data too short for TPM2B_PUBLIC".to_string(),
        ));
    }

    let mut offset = 0;

    // TPM2B_PUBLIC.size
    let pub_size = read_be_u16(var_data, offset, "TPM2B_PUBLIC size")? as usize;
    offset += 2;

    if offset + pub_size > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(format!(
            "TPM2B_PUBLIC declared size {} exceeds available data {}",
            pub_size,
            var_data.len() - offset
        )));
    }

    // TPMT_PUBLIC.type
    let alg_type = read_be_u16(var_data, offset, "TPM2B_PUBLIC type")?;
    offset += 2;

    if alg_type != TPM_ALG_RSA {
        return Err(AttestationError::SignatureVerificationFailed(format!(
            "AK key type 0x{alg_type:04x} is not RSA (expected 0x{TPM_ALG_RSA:04x})"
        )));
    }

    // TPMT_PUBLIC.nameAlg
    let _name_alg = read_be_u16(var_data, offset, "nameAlg")?;
    offset += 2;

    // objectAttributes
    offset += 4;

    // authPolicy (TPM2B_DIGEST): 2-byte size + data
    let auth_size = read_be_u16(var_data, offset, "authPolicy size")? as usize;
    offset = offset.checked_add(2 + auth_size).ok_or_else(|| {
        AttestationError::QuoteParseFailed("authPolicy size overflow".to_string())
    })?;

    // TPMS_RSA_PARMS
    if offset + 10 > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(
            "var_data truncated at RSA params".to_string(),
        ));
    }

    // symmetric (TPM_ALG_ID)
    let sym_alg = read_be_u16(var_data, offset, "symmetric alg")?;
    offset += 2;

    // If symmetric is not NULL, skip the symmetric definition
    if sym_alg != TPM_ALG_NULL {
        // Skip symmetric algorithm, key bits, and mode (2 + 2 + 2 = 6 bytes)
        offset += 6;
    }

    // scheme (TPMT_RSA_SCHEME): algorithm (2 bytes) + optional hash (2 bytes)
    let scheme_alg = read_be_u16(var_data, offset, "scheme alg")?;
    offset += 2;
    if scheme_alg != TPM_ALG_NULL {
        offset += 2; // skip hash algorithm
    }

    // keyBits
    if offset + 6 > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(
            "var_data truncated at keyBits".to_string(),
        ));
    }
    let _key_bits = read_be_u16(var_data, offset, "keyBits")?;
    offset += 2;

    // exponent (4 bytes, 0 means default 65537)
    let exp_val = read_be_u32(var_data, offset, "exponent")?;
    offset += 4;

    let exponent = if exp_val == 0 {
        RSA_DEFAULT_EXPONENT.to_vec()
    } else {
        exp_val.to_be_bytes().to_vec()
    };

    // TPM2B_PUBLIC_KEY_RSA (unique): 2-byte size + modulus
    let mod_size = read_be_u16(var_data, offset, "modulus size")? as usize;
    offset += 2;

    if offset + mod_size > var_data.len() {
        return Err(AttestationError::QuoteParseFailed(format!(
            "var_data truncated at modulus: need {} bytes at offset {}, have {}",
            mod_size,
            offset,
            var_data.len()
        )));
    }

    let modulus = var_data[offset..offset + mod_size].to_vec();

    Ok((modulus, exponent))
}

/// Extract the TPM nonce (extraData / qualifyingData) from a TPMS_ATTEST message.
///
/// Parses the TPMS_ATTEST structure to reach the extraData field:
///   magic (4) + type (2) + qualifiedSigner (TPM2B) + extraData (TPM2B) + ...
///
/// On Azure vTPM platforms the user's custom report_data is embedded here.
pub fn extract_tpm_nonce(message: &[u8]) -> Result<Vec<u8>> {
    if message.len() < 10 {
        return Err(AttestationError::QuoteParseFailed(
            "TPM Attest message too short".to_string(),
        ));
    }

    let magic = read_be_u32(message, 0, "TPM magic")?;
    if magic != TPM_ATTEST_MAGIC {
        return Err(AttestationError::QuoteParseFailed(format!(
            "invalid TPM Attest magic: 0x{magic:08X}"
        )));
    }

    // Skip magic(4) + type(2), then skip qualifiedSigner (TPM2B_NAME)
    let mut offset = 6;
    let signer_size = read_be_u16(message, offset, "qualifiedSigner size")? as usize;
    offset += 2 + signer_size;

    // extraData (TPM2B): 2-byte size + nonce bytes
    let nonce_size = read_be_u16(message, offset, "extraData size")? as usize;
    offset += 2;

    if message.len() < offset + nonce_size {
        return Err(AttestationError::QuoteParseFailed(
            "TPM Attest truncated at nonce data".to_string(),
        ));
    }

    Ok(message[offset..offset + nonce_size].to_vec())
}

/// Verify TPM nonce matches expected report_data.
pub fn verify_tpm_nonce(message: &[u8], expected: &[u8]) -> Result<()> {
    let nonce = extract_tpm_nonce(message)?;
    if nonce.len() != expected.len() {
        return Err(AttestationError::QuoteParseFailed(
            "TPM nonce length mismatch".to_string(),
        ));
    }
    if !crate::utils::constant_time_eq(&nonce, expected) {
        return Err(AttestationError::ReportDataMismatch);
    }
    Ok(())
}

/// Verify TPM PCR digest integrity.
///
/// Parses the PCR selection and digest from the TPMS_ATTEST message,
/// then verifies that the digest matches the hash of the selected
/// PCR values.
pub fn verify_tpm_pcrs(message: &[u8], pcrs: &[Vec<u8>]) -> Result<()> {
    if pcrs.is_empty() {
        return Err(AttestationError::QuoteParseFailed(
            "no PCR values in TPM quote".to_string(),
        ));
    }

    for (i, pcr) in pcrs.iter().enumerate() {
        if pcr.len() != 32 {
            return Err(AttestationError::QuoteParseFailed(format!(
                "PCR[{}] has unexpected size: {} (expected 32)",
                i,
                pcr.len()
            )));
        }
    }

    // Parse the TPMS_ATTEST to extract the PCR digest from the attested data.
    // The TPMS_ATTEST layout after the fields we parsed in verify_tpm_nonce:
    // - magic (4) + type (2) + qualifiedSigner (var) + extraData (var) +
    //   clockInfo (17) + firmwareVersion (8) + attested (TPMS_QUOTE_INFO)
    //
    // TPMS_QUOTE_INFO:
    //   - pcrSelect (TPML_PCR_SELECTION): count(4) + selections(count * var)
    //   - pcrDigest (TPM2B_DIGEST): size(2) + data(size)
    //
    // Rather than fully re-parse, extract the digest from the end of the attest
    // and verify by hashing the concatenation of all selected PCR values.

    let (selected_pcrs, expected_digest) = parse_quote_info(message)?;

    // Concatenate all selected PCR values and hash them
    let mut pcr_concat = Vec::new();
    for &idx in &selected_pcrs {
        if idx >= pcrs.len() {
            return Err(AttestationError::QuoteParseFailed(format!(
                "PCR selection references PCR[{}] but only {} PCRs available",
                idx,
                pcrs.len()
            )));
        }
        pcr_concat.extend_from_slice(&pcrs[idx]);
    }

    let computed_digest = crate::utils::sha256(&pcr_concat);

    if !crate::utils::constant_time_eq(&computed_digest, &expected_digest) {
        return Err(AttestationError::QuoteParseFailed(
            "PCR digest in TPM quote does not match hash of PCR values".to_string(),
        ));
    }

    Ok(())
}

/// Parse TPMS_QUOTE_INFO from a TPMS_ATTEST message to extract the PCR
/// selection bitmap and the expected PCR digest.
fn parse_quote_info(message: &[u8]) -> Result<(Vec<usize>, Vec<u8>)> {
    if message.len() < 10 {
        return Err(AttestationError::QuoteParseFailed(
            "TPMS_ATTEST too short".to_string(),
        ));
    }

    // Skip: magic(4) + type(2)
    let mut offset = 6;

    // qualifiedSigner (TPM2B_NAME): size(2) + data
    let signer_size = read_be_u16(message, offset, "qualifiedSigner size")? as usize;
    offset += 2 + signer_size;

    // extraData (TPM2B_DATA): size(2) + data
    let extra_size = read_be_u16(message, offset, "extraData size")? as usize;
    offset += 2 + extra_size;

    // clockInfo (TPMS_CLOCK_INFO): clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17
    offset += 17;

    // firmwareVersion: 8 bytes
    offset += 8;

    // Now we're at the TPMS_QUOTE_INFO (attested data)
    // TPML_PCR_SELECTION: count(4) + selections
    let pcr_selection_count = read_be_u32(message, offset, "PCR selection count")? as usize;
    offset += 4;

    let mut selected_pcrs = Vec::new();

    for _ in 0..pcr_selection_count {
        // TPMS_PCR_SELECTION: hash(2) + sizeofSelect(1) + pcrSelect(sizeofSelect)
        let _hash_alg = read_be_u16(message, offset, "PCR hash alg")?;
        offset += 2;

        if offset >= message.len() {
            return Err(AttestationError::QuoteParseFailed(
                "truncated at PCR selection size".to_string(),
            ));
        }
        let select_size = message[offset] as usize;
        offset += 1;

        if offset + select_size > message.len() {
            return Err(AttestationError::QuoteParseFailed(
                "truncated at PCR selection bitmap".to_string(),
            ));
        }

        // Parse the bitmap to find selected PCR indices
        for byte_idx in 0..select_size {
            let byte = message[offset + byte_idx];
            for bit_idx in 0..8u8 {
                if byte & (1 << bit_idx) != 0 {
                    selected_pcrs.push(byte_idx * 8 + bit_idx as usize);
                }
            }
        }
        offset += select_size;
    }

    // TPM2B_DIGEST (pcrDigest): size(2) + data
    let digest_size = read_be_u16(message, offset, "PCR digest size")? as usize;
    offset += 2;

    if offset + digest_size > message.len() {
        return Err(AttestationError::QuoteParseFailed(
            "truncated at PCR digest data".to_string(),
        ));
    }

    let digest = message[offset..offset + digest_size].to_vec();

    Ok((selected_pcrs, digest))
}

/// Parse TPM quote from evidence, returning decoded (sig, msg, pcrs).
pub fn decode_tpm_quote(quote: &TpmQuote) -> Result<DecodedTpmQuote> {
    let sig = hex::decode(&quote.signature)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TPM sig hex: {e}")))?;
    let msg = hex::decode(&quote.message)
        .map_err(|e| AttestationError::EvidenceDeserialize(format!("TPM msg hex: {e}")))?;
    let pcrs: Vec<Vec<u8>> = quote
        .pcrs
        .iter()
        .map(|p| {
            hex::decode(p)
                .map_err(|e| AttestationError::EvidenceDeserialize(format!("PCR hex: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((sig, msg, pcrs))
}

/// Check TPM nonce against expected report_data, returning `None` if no expectation was provided.
pub fn check_report_data(tpm_msg: &[u8], expected: Option<&[u8]>) -> Result<Option<bool>> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    verify_tpm_nonce(tpm_msg, expected)?;
    Ok(Some(true))
}

/// Check TPM PCR[8] against expected init_data_hash, returning `None` if no expectation was provided.
///
/// TPM PCR extend semantics: `PCR[8] = SHA256(zeros_32 || init_data_hash)`.
/// The guest extends PCR[8] from its initial zero state with the init_data hash,
/// so we must replicate that extend operation before comparing.
pub fn check_init_data(tpm_pcrs: &[Vec<u8>], expected: Option<&[u8]>) -> Result<Option<bool>> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    if expected.len() != 32 {
        return Err(AttestationError::QuoteParseFailed(format!(
            "expected_init_data_hash must be exactly 32 bytes, got {}",
            expected.len()
        )));
    }
    if tpm_pcrs.len() <= 8 {
        return Err(AttestationError::InitDataMismatch);
    }
    // Compute TPM PCR extend: PCR[8] = SHA256(zeros_32 || init_data_hash)
    let extended = crate::utils::sha256_two(&[0u8; 32], expected);
    if !crate::utils::constant_time_eq(&tpm_pcrs[8], &extended) {
        return Err(AttestationError::InitDataMismatch);
    }
    Ok(Some(true))
}

/// Build a `VerificationResult` with TPM PCR values and nonce in platform claims.
pub fn build_tpm_verification_result(
    base_claims: Claims,
    tpm_pcrs: &[Vec<u8>],
    tpm_msg: &[u8],
    platform: PlatformType,
    report_data_match: Option<bool>,
    init_data_match: Option<bool>,
    collateral_verified: bool,
) -> VerificationResult {
    let mut platform_data = base_claims.platform_data.clone();

    let pcr_map: serde_json::Value = tpm_pcrs
        .iter()
        .enumerate()
        .map(|(i, pcr)| {
            (
                format!("pcr{i:02}"),
                serde_json::Value::String(hex::encode(pcr)),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    platform_data["tpm"] = pcr_map;

    let mut signed_data = base_claims.signed_data.clone();
    match extract_tpm_nonce(tpm_msg) {
        Ok(nonce) => {
            platform_data["tpm"]["nonce"] = serde_json::Value::String(hex::encode(&nonce));
            // Safety: strip_trailing_nulls runs AFTER the constant-time comparison
            // in check_report_data, so stripping here is not security-sensitive.
            // The stripped nonce is only used in the public verification result.
            signed_data = strip_trailing_nulls(&nonce).to_vec();
        }
        Err(e) => {
            log::warn!("failed to extract TPM nonce for claims output: {e}");
        }
    }

    let claims = Claims {
        signed_data,
        platform_data,
        ..base_claims
    };

    VerificationResult {
        signature_valid: true,
        platform,
        claims,
        report_data_match,
        init_data_match,
        collateral_verified,
        tcb_status: None,
        // Launch-measurement compares are populated by the caller (az_snp/az_tdx).
        mrtd_match: None,
        rtmr0_match: None,
        rtmr1_match: None,
        rtmr2_match: None,
        rtmr3_match: None,
        launch_digest_match: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper: build a synthetic TPMS_ATTEST message ---
    fn build_tpms_attest(nonce: &[u8], pcr_selection: &[u8], pcr_digest: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        // magic: 0xFF544347
        msg.extend_from_slice(&[0xFF, 0x54, 0x43, 0x47]);
        // type: TPM_ST_ATTEST_QUOTE = 0x8018
        msg.extend_from_slice(&[0x80, 0x18]);
        // qualifiedSigner: size=0
        msg.extend_from_slice(&[0x00, 0x00]);
        // extraData (nonce): size + data
        msg.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        msg.extend_from_slice(nonce);
        // clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 bytes
        msg.extend_from_slice(&[0u8; 17]);
        // firmwareVersion: 8 bytes
        msg.extend_from_slice(&[0u8; 8]);
        // TPML_PCR_SELECTION: count=1
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // TPMS_PCR_SELECTION: hash=SHA256(0x000B), sizeofSelect + bitmap
        msg.extend_from_slice(&[0x00, 0x0B]);
        msg.extend_from_slice(pcr_selection);
        // TPM2B_DIGEST: size + data
        msg.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        msg.extend_from_slice(pcr_digest);
        msg
    }

    // --- Helper: build a minimal TPM2B_PUBLIC for RSA 2048 ---
    fn build_tpm2b_public_rsa(modulus: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // Content (after size field)
        let mut content = Vec::new();
        // type: TPM_ALG_RSA = 0x0001
        content.extend_from_slice(&[0x00, 0x01]);
        // nameAlg: TPM_ALG_SHA256 = 0x000B
        content.extend_from_slice(&[0x00, 0x0B]);
        // objectAttributes: 4 bytes
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // authPolicy: size=0
        content.extend_from_slice(&[0x00, 0x00]);
        // symmetric: TPM_ALG_NULL = 0x0010
        content.extend_from_slice(&[0x00, 0x10]);
        // scheme: TPM_ALG_NULL = 0x0010
        content.extend_from_slice(&[0x00, 0x10]);
        // keyBits: 2048 = 0x0800
        content.extend_from_slice(&[0x08, 0x00]);
        // exponent: 0 (default 65537)
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // unique (TPM2B_PUBLIC_KEY_RSA): size + modulus
        content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        content.extend_from_slice(modulus);

        // TPM2B_PUBLIC.size
        data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        data.extend_from_slice(&content);
        data
    }

    // --- Nonce tests ---

    #[test]
    fn test_tpm_nonce_parse_bad_magic() {
        let msg = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(verify_tpm_nonce(&msg, b"test").is_err());
    }

    #[test]
    fn test_tpm_nonce_parse_too_short() {
        let msg = vec![0xFF, 0x54, 0x43, 0x47, 0x00];
        assert!(verify_tpm_nonce(&msg, b"test").is_err());
    }

    #[test]
    fn test_tpm_nonce_direct_match() {
        // Azure vTPM puts raw report_data as the TPM nonce (qualifyingData).
        // Verification uses direct byte comparison.
        let report_data = b"hello world test nonce";
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(report_data, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);
        assert!(
            verify_tpm_nonce(&msg, report_data).is_ok(),
            "nonce should match via direct comparison"
        );
    }

    #[test]
    fn test_tpm_nonce_mismatch() {
        let nonce = b"correct data nonce value";
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);
        assert!(
            verify_tpm_nonce(&msg, b"wrong___data nonce value").is_err(),
            "nonce should not match for different data"
        );
    }

    #[test]
    fn test_tpm_nonce_length_mismatch() {
        let nonce = b"short";
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);
        let result = verify_tpm_nonce(&msg, b"much longer expected data");
        assert!(
            result.is_err(),
            "different length nonce should return error"
        );
    }

    // --- PCR verification tests ---

    #[test]
    fn test_tpm_pcrs_valid_digest() {
        // Build 24 PCR values (all zeros)
        let pcrs: Vec<Vec<u8>> = (0..24).map(|_| vec![0u8; 32]).collect();

        // Select PCRs 0-7 (first byte = 0xFF)
        let mut pcr_concat = Vec::new();
        for pcr in pcrs.iter().take(8) {
            pcr_concat.extend_from_slice(pcr);
        }
        let expected_digest = crate::utils::sha256(&pcr_concat);

        // Build TPMS_ATTEST with sizeofSelect=3, bitmap [0xFF, 0x00, 0x00] (PCRs 0-7)
        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0xFF, 0x00, 0x00], &expected_digest);

        let result = verify_tpm_pcrs(&msg, &pcrs);
        assert!(
            result.is_ok(),
            "valid PCR digest should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_tpm_pcrs_wrong_digest() {
        let pcrs: Vec<Vec<u8>> = (0..24).map(|_| vec![0u8; 32]).collect();
        let wrong_digest = [0xAA; 32];
        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0xFF, 0x00, 0x00], &wrong_digest);

        let result = verify_tpm_pcrs(&msg, &pcrs);
        assert!(result.is_err(), "wrong PCR digest should fail");
    }

    #[test]
    fn test_tpm_pcrs_empty() {
        let result = verify_tpm_pcrs(&[], &[]);
        assert!(result.is_err(), "empty PCR list should fail");
    }

    #[test]
    fn test_tpm_pcrs_wrong_size() {
        let pcrs = vec![vec![0u8; 16]]; // Wrong size (should be 32)
        let result = verify_tpm_pcrs(&[0u8; 100], &pcrs);
        assert!(result.is_err(), "PCR with wrong size should fail");
    }

    #[test]
    fn test_tpm_pcrs_single_pcr_selected() {
        // Select only PCR[0]
        let pcrs: Vec<Vec<u8>> = (0..24).map(|i| vec![i as u8; 32]).collect();
        let pcr0_digest = crate::utils::sha256(&pcrs[0]);

        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0x01, 0x00, 0x00], &pcr0_digest);

        assert!(verify_tpm_pcrs(&msg, &pcrs).is_ok());
    }

    #[test]
    fn test_tpm_pcrs_non_contiguous_selection() {
        // Select PCR 0, 2, 4 (bitmap: 0b00010101 = 0x15)
        let pcrs: Vec<Vec<u8>> = (0..24).map(|i| vec![i as u8; 32]).collect();
        let mut concat = Vec::new();
        concat.extend_from_slice(&pcrs[0]);
        concat.extend_from_slice(&pcrs[2]);
        concat.extend_from_slice(&pcrs[4]);
        let digest = crate::utils::sha256(&concat);

        let nonce = [0u8; 32];
        let msg = build_tpms_attest(&nonce, &[3, 0x15, 0x00, 0x00], &digest);

        assert!(verify_tpm_pcrs(&msg, &pcrs).is_ok());
    }

    // --- TPM2B_PUBLIC / AK extraction tests ---

    #[test]
    fn test_extract_ak_pub_rsa_2048() {
        let modulus = vec![0xAB; 256]; // 2048-bit modulus
        let var_data = build_tpm2b_public_rsa(&modulus);

        let (extracted_mod, extracted_exp) = extract_ak_pub_from_var_data(&var_data).unwrap();
        assert_eq!(extracted_mod, modulus, "modulus should match");
        assert_eq!(
            extracted_exp,
            vec![0x01, 0x00, 0x01],
            "exponent should be 65537"
        );
    }

    #[test]
    fn test_extract_ak_pub_custom_exponent() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x00]); // authPolicy size=0
        content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
        content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
        content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
        content.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // exponent=65537 explicit
        let modulus = vec![0xCD; 256];
        content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        content.extend_from_slice(&modulus);

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        let (extracted_mod, extracted_exp) = extract_ak_pub_from_var_data(&var_data).unwrap();
        assert_eq!(extracted_mod, modulus);
        // Non-zero exponent is returned as big-endian bytes of the u32
        assert_eq!(extracted_exp, vec![0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn test_extract_ak_pub_too_short() {
        let var_data = vec![0u8; 10]; // Too short for TPM2B_PUBLIC
        assert!(extract_ak_pub_from_var_data(&var_data).is_err());
    }

    #[test]
    fn test_extract_ak_pub_not_rsa() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x23]); // TPM_ALG_ECC (not RSA)
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x00]); // authPolicy size=0
        content.extend_from_slice(&[0x00; 20]); // padding

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        let result = extract_ak_pub_from_var_data(&var_data);
        assert!(result.is_err(), "non-RSA key type should be rejected");
        let err_msg = format!("{:?}", result.err().unwrap());
        assert!(
            err_msg.contains("not RSA"),
            "error should mention RSA: {err_msg}"
        );
    }

    #[test]
    fn test_extract_ak_pub_truncated_at_auth_policy() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
                                               // No authPolicy follows

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        assert!(extract_ak_pub_from_var_data(&var_data).is_err());
    }

    #[test]
    fn test_extract_ak_pub_truncated_at_modulus() {
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x00]); // authPolicy size=0
        content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
        content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
        content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // exponent=0
        content.extend_from_slice(&[0x01, 0x00]); // modulus size=256 but no data

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        assert!(extract_ak_pub_from_var_data(&var_data).is_err());
    }

    #[test]
    fn test_extract_ak_pub_with_auth_policy_data() {
        // Test with non-empty authPolicy (32-byte SHA-256 digest)
        let modulus = vec![0xEF; 256];
        let mut var_data = Vec::new();
        let mut content = Vec::new();
        content.extend_from_slice(&[0x00, 0x01]); // RSA
        content.extend_from_slice(&[0x00, 0x0B]); // SHA-256
        content.extend_from_slice(&[0x00; 4]); // objectAttributes
        content.extend_from_slice(&[0x00, 0x20]); // authPolicy size=32
        content.extend_from_slice(&[0xAA; 32]); // authPolicy data
        content.extend_from_slice(&[0x00, 0x10]); // symmetric=NULL
        content.extend_from_slice(&[0x00, 0x10]); // scheme=NULL
        content.extend_from_slice(&[0x08, 0x00]); // keyBits=2048
        content.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // exponent=0
        content.extend_from_slice(&(modulus.len() as u16).to_be_bytes());
        content.extend_from_slice(&modulus);

        var_data.extend_from_slice(&(content.len() as u16).to_be_bytes());
        var_data.extend_from_slice(&content);

        let (extracted_mod, extracted_exp) = extract_ak_pub_from_var_data(&var_data).unwrap();
        assert_eq!(extracted_mod, modulus);
        assert_eq!(extracted_exp, vec![0x01, 0x00, 0x01]);
    }

    // --- decode_tpm_quote tests ---

    #[test]
    fn test_decode_tpm_quote_valid() {
        let quote = TpmQuote {
            signature: "deadbeef".to_string(),
            message: "cafebabe".to_string(),
            pcrs: vec!["00".repeat(32), "ff".repeat(32)],
        };

        let (sig, msg, pcrs) = decode_tpm_quote(&quote).unwrap();
        assert_eq!(sig, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(msg, vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(pcrs.len(), 2);
        assert_eq!(pcrs[0], vec![0x00; 32]);
        assert_eq!(pcrs[1], vec![0xFF; 32]);
    }

    // --- parse_quote_info tests ---

    #[test]
    fn test_parse_quote_info_valid() {
        let digest = [0xBB; 32];
        // Select PCRs 0, 1, 2 (bitmap byte 0 = 0b00000111 = 0x07)
        let msg = build_tpms_attest(&[0u8; 32], &[3, 0x07, 0x00, 0x00], &digest);

        let (selected, extracted_digest) = parse_quote_info(&msg).unwrap();
        assert_eq!(selected, vec![0, 1, 2]);
        assert_eq!(extracted_digest, digest.to_vec());
    }

    #[test]
    fn test_parse_quote_info_high_pcrs() {
        // Select PCRs 16, 17, 18 (byte 2, bits 0,1,2 = 0x07)
        let digest = [0xCC; 32];
        let msg = build_tpms_attest(&[0u8; 32], &[3, 0x00, 0x00, 0x07], &digest);

        let (selected, _) = parse_quote_info(&msg).unwrap();
        assert_eq!(selected, vec![16, 17, 18]);
    }

    #[test]
    fn test_parse_quote_info_all_24_pcrs() {
        let digest = [0xDD; 32];
        let msg = build_tpms_attest(&[0u8; 32], &[3, 0xFF, 0xFF, 0xFF], &digest);

        let (selected, _) = parse_quote_info(&msg).unwrap();
        assert_eq!(selected.len(), 24);
        assert_eq!(selected, (0..24).collect::<Vec<_>>());
    }

    #[test]
    fn test_parse_quote_info_truncated() {
        assert!(parse_quote_info(&[]).is_err());
        assert!(parse_quote_info(&[0xFF, 0x54, 0x43, 0x47, 0x80, 0x18]).is_err());
    }

    // --- HCL report parsing tests ---

    /// Build a minimal HCL report for testing.
    fn build_hcl_report(tee_report: &[u8], report_type: u32, content: &[u8]) -> Vec<u8> {
        let tee_end = 0x20 + 1184;
        let content_start = tee_end + 20;
        let mut hcl = vec![0u8; content_start + content.len()];

        hcl[0..4].copy_from_slice(b"HCLA");
        let copy_len = tee_report.len().min(1184);
        hcl[0x20..0x20 + copy_len].copy_from_slice(&tee_report[..copy_len]);

        let total = (20 + content.len()) as u32;
        hcl[tee_end..tee_end + 4].copy_from_slice(&total.to_le_bytes());
        hcl[tee_end + 4..tee_end + 8].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_end + 8..tee_end + 12].copy_from_slice(&report_type.to_le_bytes());
        hcl[tee_end + 12..tee_end + 16].copy_from_slice(&1u32.to_le_bytes());
        hcl[tee_end + 16..tee_end + 20].copy_from_slice(&(content.len() as u32).to_le_bytes());
        hcl[content_start..].copy_from_slice(content);
        hcl
    }

    #[test]
    fn test_parse_hcl_report_valid_snp() {
        let content = br#"{"keys":[]}"#;
        let hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_SNP, content);

        let parsed = parse_hcl_report(&hcl).unwrap();
        assert_eq!(parsed.tee_report.len(), 1184);
        assert_eq!(parsed.report_type, HCL_REPORT_TYPE_SNP);
        assert_eq!(parsed.var_data, content);
    }

    #[test]
    fn test_parse_hcl_report_valid_tdx() {
        let content = br#"{"keys":[]}"#;
        let hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_TDX, content);

        let parsed = parse_hcl_report(&hcl).unwrap();
        assert_eq!(parsed.report_type, HCL_REPORT_TYPE_TDX);
        assert_eq!(parsed.var_data, content);
    }

    #[test]
    fn test_parse_hcl_report_trims_nulls() {
        let content = b"test data";
        let mut hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_SNP, content);
        // Extend with null padding
        hcl.extend_from_slice(&[0u8; 100]);

        let parsed = parse_hcl_report(&hcl).unwrap();
        assert_eq!(parsed.var_data, content);
    }

    #[test]
    fn test_parse_hcl_report_too_short() {
        let hcl = vec![0u8; 100];
        assert!(parse_hcl_report(&hcl).is_err());
    }

    #[test]
    fn test_parse_hcl_report_bad_magic() {
        let mut hcl = build_hcl_report(&[0u8; 1184], HCL_REPORT_TYPE_SNP, b"{}");
        hcl[0..4].copy_from_slice(b"BAAD");
        assert!(parse_hcl_report(&hcl).is_err());
    }

    // --- JWK JSON extraction tests ---

    #[test]
    fn test_extract_ak_pub_from_jwk_json_valid() {
        // 256 zero bytes = 342 base64url chars (all 'A')
        let n_b64 = "A".repeat(342);
        let json_str = format!(
            r#"{{"keys":[{{"kid":"HCLAkPub","key_ops":["sign"],"kty":"RSA","e":"AQAB","n":"{n_b64}"}}]}}"#,
        );

        let (modulus, exponent) = extract_ak_pub_from_jwk_json(json_str.as_bytes()).unwrap();
        assert_eq!(exponent, vec![0x01, 0x00, 0x01]); // 65537
        assert_eq!(modulus.len(), 256); // RSA 2048
    }

    #[test]
    fn test_extract_ak_pub_from_jwk_json_no_ak_key() {
        let json = br#"{"keys":[{"kid":"HCLEkPub","kty":"RSA","e":"AQAB","n":"AA"}]}"#;
        assert!(extract_ak_pub_from_jwk_json(json).is_err());
    }

    #[test]
    fn test_extract_ak_pub_from_jwk_json_not_json() {
        assert!(extract_ak_pub_from_jwk_json(b"not json at all").is_err());
    }

    #[test]
    fn test_extract_ak_pub_from_jwk_json_no_keys_array() {
        let json = br#"{"data": "test"}"#;
        assert!(extract_ak_pub_from_jwk_json(json).is_err());
    }

    #[test]
    fn test_verify_tpm_signature_tries_jwk_then_tpm2b() {
        // verify_tpm_signature should accept both JWK JSON and TPM2B_PUBLIC
        // formats for var_data. This test verifies the TPM2B_PUBLIC fallback
        // still works even though JWK JSON is tried first.
        let modulus = vec![0xAB; 256];
        let var_data = build_tpm2b_public_rsa(&modulus);

        // This will fail at signature verification (dummy data) but should
        // successfully extract the key from TPM2B_PUBLIC format
        let dummy_sig = vec![0u8; 256];
        let dummy_msg = vec![0xFF, 0x54, 0x43, 0x47, 0x80, 0x18, 0x00, 0x00, 0x00, 0x00];

        let result = verify_tpm_signature(&dummy_sig, &dummy_msg, &var_data);
        // Should fail at verification step, not at key extraction
        assert!(result.is_err());
        let err = format!("{:?}", result.err().unwrap());
        assert!(
            err.contains("RSA") || err.contains("sig") || err.contains("Signature"),
            "error should be about signature verification, not key extraction: {err}"
        );
    }

    // --- Regression: TPM nonce must NOT be zero-padded ---
    // Azure vTPMs have a TPM2B_DATA max size smaller than 64 bytes.
    // Passing zero-padded report_data to vtpm::get_quote() causes TPM_RC_SIZE.
    // The attest path must pass unpadded data; the verify path must match
    // the original unpadded data against the unpadded nonce in the quote.

    #[test]
    fn test_check_report_data_unpadded_nonce_matches_original() {
        // Simulate: attester passes unpadded "hello" as TPM nonce.
        // Verifier checks with the same unpadded "hello" → should match.
        let nonce = b"hello";
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);

        let result = check_report_data(&msg, Some(b"hello"));
        assert!(
            result.is_ok(),
            "unpadded nonce should match: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), Some(true));
    }

    #[test]
    fn test_check_report_data_unpadded_nonce_rejects_padded_expected() {
        // Simulate: attester passes unpadded "hello" (5 bytes) as TPM nonce.
        // Verifier checks with zero-padded 64-byte version → should fail
        // because lengths differ.
        let nonce = b"hello";
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);

        let mut padded_expected = vec![0u8; 64];
        padded_expected[..5].copy_from_slice(b"hello");

        let result = check_report_data(&msg, Some(&padded_expected));
        assert!(
            result.is_err(),
            "padded expected should not match unpadded nonce"
        );
    }

    #[test]
    fn test_check_report_data_padded_nonce_rejects_unpadded_expected() {
        // Simulate the bug scenario: attester mistakenly passes zero-padded
        // 64-byte nonce to TPM. Verifier checks with original unpadded data.
        // This should fail because the nonce in the quote is 64 bytes but
        // the expected is 5 bytes.
        let mut padded_nonce = vec![0u8; 64];
        padded_nonce[..5].copy_from_slice(b"hello");
        let pcr_digest = [0u8; 32];
        let msg = build_tpms_attest(&padded_nonce, &[3, 0xFF, 0xFF, 0xFF], &pcr_digest);

        let result = check_report_data(&msg, Some(b"hello"));
        assert!(
            result.is_err(),
            "unpadded expected should not match padded nonce (length mismatch)"
        );
    }

    #[test]
    fn test_check_report_data_none_returns_none() {
        let msg = build_tpms_attest(b"any", &[3, 0xFF, 0xFF, 0xFF], &[0u8; 32]);
        let result = check_report_data(&msg, None).unwrap();
        assert_eq!(result, None, "no expected data should return None");
    }

    #[test]
    fn test_build_tpm_verification_result_sets_signed_data_to_nonce() {
        use crate::types::{Claims, TcbInfo};

        let nonce = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let pcr_sel = &[0x03, 0x00, 0x00, 0x00];
        let pcr_digest = vec![0u8; 32];
        let tpm_msg = build_tpms_attest(&nonce, pcr_sel, &pcr_digest);
        let tpm_pcrs: Vec<Vec<u8>> = (0..24).map(|_| vec![0u8; 32]).collect();

        let base_claims = Claims {
            launch_digest: "abcd".to_string(),
            report_data: vec![0xFF; 64],
            signed_data: vec![0xFF; 64],
            init_data: vec![0x00; 32],
            tcb: TcbInfo::Snp {
                bootloader: 1,
                tee: 0,
                snp: 1,
                microcode: 1,
                fmc: None,
            },
            platform_data: serde_json::json!({}),
            #[cfg(feature = "nvidia-gpu")]
            nvidia_gpu: None,
        };

        let result = build_tpm_verification_result(
            base_claims,
            &tpm_pcrs,
            &tpm_msg,
            PlatformType::AzSnp,
            None,
            None,
            false,
        );

        assert_eq!(
            result.claims.signed_data, nonce,
            "signed_data should be the TPM nonce"
        );
        assert_eq!(
            result.claims.report_data,
            vec![0xFF; 64],
            "report_data should be unchanged"
        );
        assert_eq!(
            result.claims.platform_data["tpm"]["nonce"]
                .as_str()
                .unwrap(),
            hex::encode(&nonce),
        );
    }

    #[test]
    fn test_build_tpm_verification_result_strips_trailing_nulls_from_signed_data() {
        use crate::types::{Claims, TcbInfo};

        // Simulate a nonce that was zero-padded to 64 bytes (as attest does)
        let mut padded_nonce = vec![0u8; 64];
        padded_nonce[..5].copy_from_slice(b"hello");

        let pcr_sel = &[0x03, 0x00, 0x00, 0x00];
        let pcr_digest = vec![0u8; 32];
        let tpm_msg = build_tpms_attest(&padded_nonce, pcr_sel, &pcr_digest);
        let tpm_pcrs: Vec<Vec<u8>> = (0..24).map(|_| vec![0u8; 32]).collect();

        let base_claims = Claims {
            launch_digest: "abcd".to_string(),
            report_data: vec![0xFF; 64],
            signed_data: vec![0xFF; 64],
            init_data: vec![0x00; 32],
            tcb: TcbInfo::Snp {
                bootloader: 1,
                tee: 0,
                snp: 1,
                microcode: 1,
                fmc: None,
            },
            platform_data: serde_json::json!({}),
            #[cfg(feature = "nvidia-gpu")]
            nvidia_gpu: None,
        };

        let result = build_tpm_verification_result(
            base_claims,
            &tpm_pcrs,
            &tpm_msg,
            PlatformType::AzSnp,
            None,
            None,
            false,
        );

        assert_eq!(
            result.claims.signed_data,
            b"hello".to_vec(),
            "signed_data should have trailing nulls stripped"
        );
        // platform_data nonce should still contain the full padded value
        assert_eq!(
            result.claims.platform_data["tpm"]["nonce"]
                .as_str()
                .unwrap(),
            hex::encode(&padded_nonce),
        );
    }

    // --- check_init_data tests ---

    #[test]
    fn test_check_init_data_none_expected() {
        let pcrs = vec![vec![0u8; 32]; 16];
        let result = check_init_data(&pcrs, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_check_init_data_pcr_extend_formula() {
        // Simulate TPM PCR extend: PCR[8] = SHA256(zeros_32 || init_data_hash)
        let init_data_hash = [0xAA; 32];
        let extended = crate::utils::sha256_two(&[0u8; 32], &init_data_hash);

        let mut pcrs = vec![vec![0u8; 32]; 16];
        pcrs[8] = extended;

        let result = check_init_data(&pcrs, Some(&init_data_hash));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(true));
    }

    #[test]
    fn test_check_init_data_raw_hash_mismatch() {
        // If PCR[8] contains the raw hash (not extended), it should NOT match.
        // This is the bug this fix corrects.
        let init_data_hash = [0xBB; 32];

        let mut pcrs = vec![vec![0u8; 32]; 16];
        pcrs[8] = init_data_hash.to_vec(); // raw, not extended

        let result = check_init_data(&pcrs, Some(&init_data_hash));
        assert!(
            result.is_err(),
            "raw hash should not match extended PCR value"
        );
    }

    #[test]
    fn test_check_init_data_wrong_hash() {
        let init_data_hash = [0xCC; 32];
        let wrong_hash = [0xDD; 32];
        let extended = crate::utils::sha256_two(&[0u8; 32], &wrong_hash);

        let mut pcrs = vec![vec![0u8; 32]; 16];
        pcrs[8] = extended;

        let result = check_init_data(&pcrs, Some(&init_data_hash));
        assert!(result.is_err());
    }

    #[test]
    fn test_check_init_data_wrong_length() {
        let pcrs = vec![vec![0u8; 32]; 16];
        let result = check_init_data(&pcrs, Some(&[0u8; 16]));
        assert!(result.is_err(), "non-32-byte hash should be rejected");
    }

    #[test]
    fn test_check_init_data_too_few_pcrs() {
        let pcrs = vec![vec![0u8; 32]; 8]; // only PCR[0..7]
        let result = check_init_data(&pcrs, Some(&[0u8; 32]));
        assert!(result.is_err(), "should fail with too few PCRs");
    }
}
