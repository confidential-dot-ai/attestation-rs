use serde::{Deserialize, Serialize};

/// Platform identifier enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PlatformType {
    #[serde(rename = "tdx")]
    Tdx,
    #[serde(rename = "snp")]
    Snp,
    #[serde(rename = "az-tdx")]
    AzTdx,
    #[serde(rename = "az-snp")]
    AzSnp,
    /// GCP Confidential VM running AMD SEV-SNP.
    ///
    /// **Security note:** This tag reflects the *attester's claim*, not a
    /// cryptographic proof of GCP origin. The AMD SNP attestation report
    /// contains no cloud-provider identity. A valid `GcpSnp` result means the
    /// AMD hardware root-of-trust chain verified successfully — not that the
    /// machine is inside GCP. Policy decisions **must not** grant elevated trust
    /// based solely on this tag; use report fields (`measurement`, `chip_id`,
    /// `reported_tcb`) instead.
    #[serde(rename = "gcp-snp")]
    GcpSnp,
    /// GCP Confidential VM running Intel TDX.
    ///
    /// **Security note:** Same caveat as `GcpSnp`. This tag reflects the
    /// *attester's claim*, not a cryptographic proof of GCP origin. The Intel
    /// TDX DCAP quote contains no cloud-provider identity. A valid `GcpTdx`
    /// result means the Intel DCAP signature chain verified successfully — not
    /// that the machine is inside GCP. Policy decisions **must not** grant
    /// elevated trust based solely on this tag; use report fields (`mr_td`,
    /// `rtmr_*`, `tee_tcb_svn`) instead.
    #[serde(rename = "gcp-tdx")]
    GcpTdx,
    #[serde(rename = "dstack")]
    Dstack,
}

/// Self-describing attestation evidence envelope.
///
/// Wraps platform-specific evidence with a platform identifier so that
/// verifiers can auto-detect which platform produced the evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Which platform produced this evidence.
    pub platform: PlatformType,
    /// Platform-specific evidence payload.
    pub evidence: serde_json::Value,
}

impl std::fmt::Display for PlatformType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformType::Tdx => write!(f, "tdx"),
            PlatformType::Snp => write!(f, "snp"),
            PlatformType::AzTdx => write!(f, "az-tdx"),
            PlatformType::AzSnp => write!(f, "az-snp"),
            PlatformType::GcpSnp => write!(f, "gcp-snp"),
            PlatformType::GcpTdx => write!(f, "gcp-tdx"),
            PlatformType::Dstack => write!(f, "dstack"),
        }
    }
}

// ----------------------------------------------------------------------------
// Top-level VerifyParams / VerifyResult
// ----------------------------------------------------------------------------

/// Canonical verification parameters shared across all vendors.
///
/// The outer struct carries the three policy anchors every TEE verifier
/// understands — `nonce`, `report_data`, and `launch_measurement` — plus
/// vendor-specific parameters in [`VendorParams`].
///
/// `nonce` and `report_data` are distinct because bare-metal TEEs put the
/// caller's nonce directly in `report_data`, while vTPM-overlay platforms
/// (Azure SNP/TDX) put the nonce in the TPM quote's `extraData` and reuse
/// `report_data` for the AK-to-TEE binding. Specifying both lets a caller
/// pin freshness on the layer the platform actually exposes it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyParams {
    /// Expected nonce. On bare-metal platforms this is the same byte string
    /// as `report_data` and goes into the TEE quote's report_data field.
    /// On vTPM-overlay platforms (Azure SNP/TDX) this goes into the TPM
    /// quote's extraData; `report_data` then carries the AK binding hash.
    pub nonce: Option<Vec<u8>>,

    /// Expected report_data. For bare-metal platforms this equals `nonce`;
    /// for vTPM-overlay platforms this is the SHA-256 of the AK var_data
    /// (the AK-to-TEE binding) — set this only if you actually want to
    /// pin that bound value, otherwise leave it `None`.
    pub report_data: Option<Vec<u8>>,

    /// Expected canonical launch measurement (the synthetic, vendor-agnostic
    /// 48-byte digest produced by combining vendor-specific launch fields).
    ///
    /// Formula:
    /// - TDX / AzTdx / GcpTdx / Dstack: `SHA-384(mrtd ‖ rtmr1 ‖ rtmr2 ‖ rtmr3)`
    /// - SNP / AzSnp / GcpSnp: `report.measurement` verbatim (48 bytes)
    pub launch_measurement: Option<Vec<u8>>,

    /// If true, allow guests launched with debug policy. Default: false.
    pub allow_debug: bool,

    /// Vendor-specific verification parameters. Defaults to `Auto`, which
    /// detects the vendor from the envelope and skips vendor-specific
    /// policy pinning entirely.
    pub vendor: VendorParams,
}

/// Verification result.
///
/// `#[must_use]`: this struct carries individual policy outcomes
/// (`signature_valid`, `nonce_match`, ...). Dropping it without
/// inspecting those booleans means a caller asked
/// `attestation::verify(...)` and then ignored whether the quote actually
/// matched the policy. That is *always* a bug — the attribute makes the
/// compiler warn at every call site that throws the result away.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[must_use]
pub struct VerifyResult {
    /// Was the hardware signature on the evidence valid?
    pub signature_valid: bool,
    /// Whether collateral was available and all collateral checks passed
    /// (CRL revocation, TCB status, QE identity, etc.). False when
    /// collateral was unavailable or any collateral check was skipped.
    pub collateral_verified: bool,
    /// Observed nonce extracted from the evidence (vendor-specific source).
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    /// Observed report_data extracted from the evidence.
    #[serde(with = "hex_bytes")]
    pub report_data: Vec<u8>,
    /// Observed canonical launch_measurement (see [`VerifyParams::launch_measurement`]).
    #[serde(with = "hex_bytes")]
    pub launch_measurement: Vec<u8>,
    /// Result of comparing observed nonce to [`VerifyParams::nonce`].
    /// `None` if no expected value was provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_match: Option<bool>,
    /// Result of comparing observed report_data to [`VerifyParams::report_data`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_data_match: Option<bool>,
    /// Result of comparing observed canonical launch_measurement to
    /// [`VerifyParams::launch_measurement`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_measurement_match: Option<bool>,
    /// Vendor-specific verification artifacts (parsed quote/report bodies,
    /// TCB status, signature outcomes for vTPM/JWT overlays).
    pub vendor: VendorResult,
    /// Aggregated outcome of all vendor-specific policy pin checks
    /// (mrtd, rtmrs, mr_config_id, min_tcb, ak_pub_thumbprint, etc.).
    /// `true` iff at least one vendor-specific pin check was requested
    /// and failed.
    pub vendor_policy_failed: bool,
}

impl VerifyResult {
    /// Did ANY policy check fail (canonical or vendor-specific)?
    ///
    /// Returns true if:
    /// - any canonical `*_match` field is `Some(false)`, OR
    /// - `vendor_policy_failed` is `true`.
    ///
    /// Use this in CI/deployment gates: combine with `signature_valid` to
    /// decide whether to accept the evidence.
    #[must_use]
    pub fn policy_failed(&self) -> bool {
        matches!(self.nonce_match, Some(false))
            || matches!(self.report_data_match, Some(false))
            || matches!(self.launch_measurement_match, Some(false))
            || self.vendor_policy_failed
    }
}

// ----------------------------------------------------------------------------
// Vendor enums
// ----------------------------------------------------------------------------

/// Vendor-specific verification parameters.
///
/// `Auto` detects the vendor from the envelope and applies no vendor-specific
/// policy. To pin vendor-specific fields (mrtd, rtmrs, min_tcb, ...) pick the
/// matching variant explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum VendorParams {
    /// Detect vendor from the evidence envelope; no vendor policy is enforced.
    #[serde(rename = "auto")]
    Auto,
    Tdx(VerifyTdx),
    Snp(VerifySnp),
    AzTdx(VerifyAzTdx),
    AzSnp(VerifyAzSnp),
    GcpTdx(VerifyGcpTdx),
    GcpSnp(VerifyGcpSnp),
    Dstack(VerifyDstack),
}

impl Default for VendorParams {
    fn default() -> Self {
        Self::Auto
    }
}

impl VendorParams {
    /// Platform tag the explicit variant targets. Returns `None` for `Auto`
    /// (which accepts whatever the envelope claims).
    #[must_use]
    pub fn platform_tag(&self) -> Option<PlatformType> {
        match self {
            VendorParams::Auto => None,
            VendorParams::Tdx(_) => Some(PlatformType::Tdx),
            VendorParams::Snp(_) => Some(PlatformType::Snp),
            VendorParams::AzTdx(_) => Some(PlatformType::AzTdx),
            VendorParams::AzSnp(_) => Some(PlatformType::AzSnp),
            VendorParams::GcpTdx(_) => Some(PlatformType::GcpTdx),
            VendorParams::GcpSnp(_) => Some(PlatformType::GcpSnp),
            VendorParams::Dstack(_) => Some(PlatformType::Dstack),
        }
    }
}

/// Vendor-specific verification result artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum VendorResult {
    Tdx(TdxResult),
    Snp(SnpResult),
    AzTdx(AzTdxResult),
    AzSnp(AzSnpResult),
    GcpTdx(GcpTdxResult),
    GcpSnp(GcpSnpResult),
    Dstack(DstackResult),
}

impl VendorResult {
    /// Platform tag for the vendor variant.
    #[must_use]
    pub fn platform(&self) -> PlatformType {
        match self {
            VendorResult::Tdx(_) => PlatformType::Tdx,
            VendorResult::Snp(_) => PlatformType::Snp,
            VendorResult::AzTdx(_) => PlatformType::AzTdx,
            VendorResult::AzSnp(_) => PlatformType::AzSnp,
            VendorResult::GcpTdx(_) => PlatformType::GcpTdx,
            VendorResult::GcpSnp(_) => PlatformType::GcpSnp,
            VendorResult::Dstack(_) => PlatformType::Dstack,
        }
    }
}

// ----------------------------------------------------------------------------
// Per-vendor params — fields the canonical outer struct doesn't cover
// ----------------------------------------------------------------------------

/// Bare-metal TDX verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifyTdx {
    /// Expected MRTD (TD launch measurement, 48 bytes).
    #[serde(default, with = "hex_option_array48")]
    pub mrtd: Option<[u8; 48]>,
    /// Expected per-RTMR digests (`None` entries are skipped).
    #[serde(default, with = "hex_array_of_option_array48")]
    pub rtmrs: [Option<[u8; 48]>; 4],
    /// Expected MRCONFIGID (48 bytes).
    #[serde(default, with = "hex_option_array48")]
    pub mr_config_id: Option<[u8; 48]>,
}

/// Bare-metal SNP verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifySnp {
    /// Minimum TCB the reported TCB must satisfy (component-wise `>=`).
    pub min_tcb: Option<SnpTcb>,
}

/// Azure TDX (vTPM-wrapped) verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifyAzTdx {
    /// Expected MRTD (TD launch measurement, 48 bytes).
    #[serde(default, with = "hex_option_array48")]
    pub mrtd: Option<[u8; 48]>,
    /// Expected per-RTMR digests.
    #[serde(default, with = "hex_array_of_option_array48")]
    pub rtmrs: [Option<[u8; 48]>; 4],
    /// Expected MRCONFIGID.
    #[serde(default, with = "hex_option_array48")]
    pub mr_config_id: Option<[u8; 48]>,
    /// Expected report_data inside the inner TDX quote. The inner report_data
    /// for Azure vTPM platforms is `SHA-256(var_data) ‖ 32 zero bytes` (the
    /// AK-to-TEE binding); pin it here if you need to.
    pub inner_report_data: Option<Vec<u8>>,
    /// Expected AK public-key thumbprint (SHA-256 of canonical JWK), bound
    /// in the inner TDX quote's report_data via SHA-256(var_data).
    pub ak_pub_thumbprint: Option<Vec<u8>>,
}

/// Azure SNP (vTPM-wrapped) verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifyAzSnp {
    /// Minimum TCB the reported TCB must satisfy.
    pub min_tcb: Option<SnpTcb>,
    /// Expected report_data inside the inner SNP report.
    pub inner_report_data: Option<Vec<u8>>,
    /// Expected AK public-key thumbprint.
    pub ak_pub_thumbprint: Option<Vec<u8>>,
}

/// GCP TDX verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifyGcpTdx {
    /// Expected MRTD.
    #[serde(default, with = "hex_option_array48")]
    pub mrtd: Option<[u8; 48]>,
    /// Expected per-RTMR digests.
    #[serde(default, with = "hex_array_of_option_array48")]
    pub rtmrs: [Option<[u8; 48]>; 4],
    /// Expected MRCONFIGID.
    #[serde(default, with = "hex_option_array48")]
    pub mr_config_id: Option<[u8; 48]>,
    /// Expected GCP attestation-JWT audience (`aud` claim). Set this if
    /// your evidence carries a GCP-issued attestation JWT and you want to
    /// pin which audience the JWT was issued for. Today the GCP verifier
    /// delegates to the bare-metal TDX path and does not parse a JWT; the
    /// pin is recorded for forward compatibility.
    pub gcp_jwt_audience: Option<String>,
}

/// GCP SNP verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifyGcpSnp {
    /// Minimum TCB the reported TCB must satisfy.
    pub min_tcb: Option<SnpTcb>,
    /// Expected GCP attestation-JWT audience. See [`VerifyGcpTdx::gcp_jwt_audience`].
    pub gcp_jwt_audience: Option<String>,
}

/// Dstack TDX verification parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct VerifyDstack {
    /// Expected MRTD.
    #[serde(default, with = "hex_option_array48")]
    pub mrtd: Option<[u8; 48]>,
    /// Expected per-RTMR digests.
    #[serde(default, with = "hex_array_of_option_array48")]
    pub rtmrs: [Option<[u8; 48]>; 4],
    /// Expected MRCONFIGID.
    #[serde(default, with = "hex_option_array48")]
    pub mr_config_id: Option<[u8; 48]>,
}

// ----------------------------------------------------------------------------
// Per-vendor results
// ----------------------------------------------------------------------------

/// Bare-metal TDX verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct TdxResult {
    /// Fully parsed TDX quote (header + body).
    pub quote: ParsedTdxQuote,
    /// DCAP TCB status when a collateral provider was available; `None` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_status: Option<DcapVerificationStatus>,
}

/// Bare-metal SNP verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct SnpResult {
    /// Parsed SNP attestation report.
    pub report: ParsedSnpReport,
}

impl SnpResult {
    /// Builder for callers outside this crate. `#[non_exhaustive]` blocks
    /// struct literals from foreign crates; this constructor preserves
    /// future field-addition flexibility while letting the API crate's
    /// test fixtures (and future external consumers) create instances.
    #[must_use]
    pub fn new(report: ParsedSnpReport) -> Self {
        Self { report }
    }
}

/// Azure TDX (vTPM-wrapped) verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct AzTdxResult {
    /// Decoded TPM quote (sig/msg/PCRs).
    pub tpm_quote: ParsedTpmQuote,
    /// Parsed HCL report metadata.
    pub hcl_report: ParsedHclReport,
    /// Parsed inner TDX quote (from the HCL TEE report).
    pub inner_tdx_quote: ParsedTdxQuote,
    /// DCAP TCB status when collateral was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_status: Option<DcapVerificationStatus>,
    /// Did the TPM RSA signature over the TPM quote message verify?
    pub tpm_signature_valid: bool,
    /// Did `inner_tdx_quote.report_data[..32] == SHA-256(hcl.var_data)`?
    pub ak_to_tee_binding_valid: bool,
}

/// Azure SNP (vTPM-wrapped) verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct AzSnpResult {
    /// Decoded TPM quote.
    pub tpm_quote: ParsedTpmQuote,
    /// Parsed HCL report metadata.
    pub hcl_report: ParsedHclReport,
    /// Parsed inner SNP attestation report.
    pub inner_snp_report: ParsedSnpReport,
    /// Did the TPM RSA signature verify?
    pub tpm_signature_valid: bool,
    /// Did the AK-to-TEE binding verify?
    pub ak_to_tee_binding_valid: bool,
}

/// GCP TDX verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct GcpTdxResult {
    /// Parsed GCP attestation JWT, if present. `None` indicates the
    /// envelope did not carry a JWT (today's evidence is bare DCAP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<ParsedAttestationJwt>,
    /// Parsed inner TDX quote.
    pub inner_tdx_quote: ParsedTdxQuote,
    /// DCAP TCB status when collateral was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_status: Option<DcapVerificationStatus>,
    /// Did the GCP attestation JWT signature verify? `false` when no JWT
    /// was present (today's GCP envelope).
    pub jwt_signature_valid: bool,
}

/// GCP SNP verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct GcpSnpResult {
    /// Parsed GCP attestation JWT, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<ParsedAttestationJwt>,
    /// Parsed inner SNP attestation report.
    pub inner_snp_report: ParsedSnpReport,
    /// Did the GCP attestation JWT signature verify?
    pub jwt_signature_valid: bool,
}

/// Dstack TDX verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct DstackResult {
    /// Parsed TDX quote.
    pub quote: ParsedTdxQuote,
    /// DCAP TCB status when collateral was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_status: Option<DcapVerificationStatus>,
}

// ----------------------------------------------------------------------------
// Serializable parsed-evidence projections
// ----------------------------------------------------------------------------

/// Serializable projection of a parsed TDX quote body.
///
/// This is the canonical, on-wire-friendly view used by vendor results. It
/// mirrors the inner TDX measurements that the verifier already parses; it
/// is kept narrow (no auth-data / cert-chain bytes) so vendor results stay
/// JSON-serializable without dragging the full DCAP authentication payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedTdxQuote {
    pub quote_version: u16,
    #[serde(with = "hex_bytes")]
    pub tee_tcb_svn: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mr_seam: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mrsigner_seam: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub seam_attributes: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub td_attributes: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub xfam: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mr_td: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mr_config_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mr_owner: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mr_owner_config: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr0: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr1: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr2: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rtmr3: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub report_data: Vec<u8>,
}

/// Serializable projection of a parsed SNP attestation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedSnpReport {
    pub version: u32,
    pub vmpl: u32,
    #[serde(with = "hex_bytes")]
    pub measurement: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub report_data: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub host_data: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub chip_id: Vec<u8>,
    pub policy_debug_allowed: bool,
    pub reported_tcb: SnpTcb,
}

/// Serializable projection of a TPM quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedTpmQuote {
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,
    /// Per-PCR digests (each typically 32 bytes for SHA-256).
    pub pcrs: Vec<String>,
}

/// Serializable projection of a parsed Azure HCL report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedHclReport {
    pub report_type: u32,
    #[serde(with = "hex_bytes")]
    pub var_data: Vec<u8>,
}

/// Parsed GCP attestation JWT.
///
/// GCP's Confidential VMs can optionally produce a signed attestation JWT
/// via Google Cloud Attestation (`confidentialcomputing.googleapis.com`).
/// Today's `gcp-snp` / `gcp-tdx` evidence does not include this JWT — the
/// envelope is a bare hardware report, and the verifier delegates to the
/// bare-metal verifier. This type is present so the per-vendor result
/// shape is forward-compatible: once the envelope grows a JWT, populating
/// `jwt: Some(_)` and `jwt_signature_valid: true` is the natural extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedAttestationJwt {
    /// JWT issuer (`iss` claim).
    pub issuer: String,
    /// JWT audience (`aud` claim).
    pub audience: String,
    /// Subject (`sub` claim).
    pub subject: String,
    /// Issued-at (`iat`, seconds since epoch).
    pub issued_at: u64,
    /// Expiry (`exp`).
    pub expires_at: u64,
    /// Vendor-specific JWT body claims passed through as JSON.
    pub claims: serde_json::Value,
}

// ----------------------------------------------------------------------------
// TCB / DCAP types (unchanged)
// ----------------------------------------------------------------------------

/// TDX TCB status from Intel DCAP collateral evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TdxTcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl std::fmt::Display for TdxTcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TdxTcbStatus::UpToDate => write!(f, "UpToDate"),
            TdxTcbStatus::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            TdxTcbStatus::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            TdxTcbStatus::ConfigurationAndSWHardeningNeeded => {
                write!(f, "ConfigurationAndSWHardeningNeeded")
            }
            TdxTcbStatus::OutOfDate => write!(f, "OutOfDate"),
            TdxTcbStatus::OutOfDateConfigurationNeeded => {
                write!(f, "OutOfDateConfigurationNeeded")
            }
            TdxTcbStatus::Revoked => write!(f, "Revoked"),
        }
    }
}

/// DCAP verification status from Intel collateral evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcapVerificationStatus {
    /// TCB status determined by matching against Intel TCB Info.
    pub tcb_status: TdxTcbStatus,
    /// FMSPC (Family-Model-Stepping-Platform-CustomSKU) extracted from PCK cert.
    pub fmspc: String,
    /// Security advisory IDs affecting this TCB level.
    pub advisory_ids: Vec<String>,
    /// Whether the TCB Info collateral has expired (nextUpdate in the past).
    #[serde(default)]
    pub collateral_expired: bool,
}

/// AMD processor generation for SNP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessorGeneration {
    Milan,
    Genoa,
    Turin,
}

impl ProcessorGeneration {
    /// Determine processor generation from CPUID family and model IDs.
    pub fn from_cpuid(family_id: u8, model_id: u8) -> Option<Self> {
        match (family_id, model_id) {
            (0x19, 0x00..=0x0F) => Some(ProcessorGeneration::Milan),
            (0x19, 0x10..=0x1F) | (0x19, 0xA0..=0xAF) => Some(ProcessorGeneration::Genoa),
            (0x1A, 0x00..=0x11) => Some(ProcessorGeneration::Turin),
            _ => None,
        }
    }

    /// Product name string used in AMD KDS URLs.
    pub fn product_name(&self) -> &'static str {
        match self {
            ProcessorGeneration::Milan => "Milan",
            ProcessorGeneration::Genoa => "Genoa",
            ProcessorGeneration::Turin => "Turin",
        }
    }
}

/// SNP TCB version components (used for KDS URL construction and TCB checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnpTcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
    /// FMC (Firmware Microcontroller) SPL — present only on Turin processors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fmc: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_generation_from_cpuid() {
        // Milan range: family 0x19, model 0x00..0x0F
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x00),
            Some(ProcessorGeneration::Milan)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x0F),
            Some(ProcessorGeneration::Milan)
        );

        // Genoa range: family 0x19, model 0x10..0x1F or 0xA0..0xAF
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x10),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0x1F),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xA0),
            Some(ProcessorGeneration::Genoa)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x19, 0xAF),
            Some(ProcessorGeneration::Genoa)
        );

        // Turin range: family 0x1A, model 0x00..0x11
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x00),
            Some(ProcessorGeneration::Turin)
        );
        assert_eq!(
            ProcessorGeneration::from_cpuid(0x1A, 0x11),
            Some(ProcessorGeneration::Turin)
        );

        // Unknown combinations
        assert_eq!(ProcessorGeneration::from_cpuid(0x00, 0x00), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0xFF, 0xFF), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0x18, 0x01), None);
        assert_eq!(ProcessorGeneration::from_cpuid(0x19, 0x20), None); // Gap between Milan/Genoa
        assert_eq!(ProcessorGeneration::from_cpuid(0x1A, 0x12), None); // Just past Turin range
    }

    #[test]
    fn test_vendor_params_default_is_auto() {
        let params = VerifyParams::default();
        assert!(matches!(params.vendor, VendorParams::Auto));
        assert_eq!(params.vendor.platform_tag(), None);
    }

    #[test]
    fn test_vendor_params_platform_tag() {
        assert_eq!(VendorParams::Auto.platform_tag(), None);
        assert_eq!(
            VendorParams::Tdx(VerifyTdx::default()).platform_tag(),
            Some(PlatformType::Tdx)
        );
        assert_eq!(
            VendorParams::Snp(VerifySnp::default()).platform_tag(),
            Some(PlatformType::Snp)
        );
        assert_eq!(
            VendorParams::AzTdx(VerifyAzTdx::default()).platform_tag(),
            Some(PlatformType::AzTdx)
        );
        assert_eq!(
            VendorParams::AzSnp(VerifyAzSnp::default()).platform_tag(),
            Some(PlatformType::AzSnp)
        );
        assert_eq!(
            VendorParams::GcpTdx(VerifyGcpTdx::default()).platform_tag(),
            Some(PlatformType::GcpTdx)
        );
        assert_eq!(
            VendorParams::GcpSnp(VerifyGcpSnp::default()).platform_tag(),
            Some(PlatformType::GcpSnp)
        );
        assert_eq!(
            VendorParams::Dstack(VerifyDstack::default()).platform_tag(),
            Some(PlatformType::Dstack)
        );
    }

    fn dummy_result(
        nonce_match: Option<bool>,
        report_data_match: Option<bool>,
        launch_measurement_match: Option<bool>,
        vendor_policy_failed: bool,
    ) -> VerifyResult {
        VerifyResult {
            signature_valid: true,
            collateral_verified: false,
            nonce: vec![],
            report_data: vec![],
            launch_measurement: vec![],
            nonce_match,
            report_data_match,
            launch_measurement_match,
            vendor: VendorResult::Tdx(TdxResult {
                quote: ParsedTdxQuote {
                    quote_version: 4,
                    tee_tcb_svn: vec![0; 16],
                    mr_seam: vec![0; 48],
                    mrsigner_seam: vec![0; 48],
                    seam_attributes: vec![0; 8],
                    td_attributes: vec![0; 8],
                    xfam: vec![0; 8],
                    mr_td: vec![0; 48],
                    mr_config_id: vec![0; 48],
                    mr_owner: vec![0; 48],
                    mr_owner_config: vec![0; 48],
                    rtmr0: vec![0; 48],
                    rtmr1: vec![0; 48],
                    rtmr2: vec![0; 48],
                    rtmr3: vec![0; 48],
                    report_data: vec![0; 64],
                },
                tcb_status: None,
            }),
            vendor_policy_failed,
        }
    }

    #[test]
    fn policy_failed_all_none_returns_false() {
        let r = dummy_result(None, None, None, false);
        assert!(!r.policy_failed());
    }

    #[test]
    fn policy_failed_canonical_mismatch() {
        assert!(dummy_result(Some(false), None, None, false).policy_failed());
        assert!(dummy_result(None, Some(false), None, false).policy_failed());
        assert!(dummy_result(None, None, Some(false), false).policy_failed());
    }

    #[test]
    fn policy_failed_vendor_policy() {
        assert!(dummy_result(None, None, None, true).policy_failed());
    }

    #[test]
    fn policy_failed_canonical_matches_are_not_failures() {
        let r = dummy_result(Some(true), Some(true), Some(true), false);
        assert!(!r.policy_failed());
    }

    #[test]
    fn vendor_params_serializes_with_type_tag() {
        let p = VerifyParams {
            vendor: VendorParams::Tdx(VerifyTdx {
                mrtd: Some([0u8; 48]),
                rtmrs: [None; 4],
                mr_config_id: None,
            }),
            ..Default::default()
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["vendor"]["type"], "tdx");
    }

    #[test]
    fn vendor_params_auto_round_trips() {
        let json = serde_json::json!({"type": "auto"});
        let v: VendorParams = serde_json::from_value(json).unwrap();
        assert!(matches!(v, VendorParams::Auto));
    }

    #[test]
    fn verify_params_default_serializes_with_auto_vendor() {
        let p = VerifyParams::default();
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["vendor"]["type"], "auto");
        assert_eq!(json["allow_debug"], false);
    }

    #[test]
    fn verify_tdx_serializes_array_of_options() {
        // External wire format must encode RTMR pins as a 4-element array of
        // nullable hex strings, not Rust's structural [Option<[u8;48]>; 4].
        let mut tdx = VerifyTdx::default();
        tdx.mrtd = Some([0x11; 48]);
        tdx.rtmrs = [None, Some([0x22; 48]), None, Some([0x44; 48])];

        let json = serde_json::to_value(&tdx).unwrap();
        assert_eq!(json["mrtd"], serde_json::Value::String("11".repeat(48)));
        assert_eq!(json["rtmrs"][0], serde_json::Value::Null);
        assert_eq!(json["rtmrs"][1], serde_json::Value::String("22".repeat(48)));
        assert_eq!(json["rtmrs"][2], serde_json::Value::Null);
        assert_eq!(json["rtmrs"][3], serde_json::Value::String("44".repeat(48)));

        // Round-trip
        let back: VerifyTdx = serde_json::from_value(json).unwrap();
        assert_eq!(back.mrtd, tdx.mrtd);
        assert_eq!(back.rtmrs, tdx.rtmrs);
    }

    #[test]
    fn verify_tdx_rejects_wrong_length_digest() {
        let json = serde_json::json!({
            "mrtd": "deadbeef", // 4 bytes — not 48
            "rtmrs": [null, null, null, null],
            "mr_config_id": null,
        });
        let err = serde_json::from_value::<VerifyTdx>(json).unwrap_err();
        assert!(err.to_string().contains("48-byte"), "got: {err}");
    }

    #[test]
    fn verify_result_round_trip_preserves_anchors() {
        let r = dummy_result(Some(true), None, Some(false), false);
        let json = serde_json::to_string(&r).unwrap();
        let back: VerifyResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signature_valid, r.signature_valid);
        assert_eq!(back.nonce_match, r.nonce_match);
        assert_eq!(back.launch_measurement_match, r.launch_measurement_match);
        assert_eq!(back.policy_failed(), r.policy_failed());
    }
}

// ----------------------------------------------------------------------------
// Legacy Claims projection (used by the token issuer)
// ----------------------------------------------------------------------------

/// Normalized claims extracted from evidence.
///
/// This projection is consumed by the API crate's JWT issuer to populate the
/// signed token body; it is still produced internally by each vendor's
/// `extract_claims` helper. The verifier's new `VerifyResult` does not embed
/// `Claims` directly — vendor-specific parsed bodies live in [`VendorResult`].
/// Callers who want the legacy shape can build it from the vendor result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Hex-encoded launch measurement (MRTD for TDX, measurement for SNP).
    pub launch_digest: String,
    /// The report_data field from inside the HW quote, raw bytes.
    #[serde(with = "hex_bytes")]
    pub report_data: Vec<u8>,
    /// The data requested to be signed by the attestation requester.
    /// For bare-metal platforms this equals report_data; for vTPM platforms
    /// this is the TPM nonce (the user's original challenge data).
    #[serde(with = "hex_bytes")]
    pub signed_data: Vec<u8>,
    /// Init data / host data from the quote, raw bytes.
    #[serde(with = "hex_bytes")]
    pub init_data: Vec<u8>,
    /// TCB version information, platform-specific.
    pub tcb: TcbInfo,
    /// All platform-specific claim fields as a JSON map.
    pub platform_data: serde_json::Value,
}

/// TCB version information, varies by platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TcbInfo {
    Snp {
        bootloader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
        /// FMC (Firmware Microcontroller) SPL — present only on Turin processors.
        #[serde(skip_serializing_if = "Option::is_none")]
        fmc: Option<u8>,
    },
    Tdx {
        /// Raw 16-byte TCB SVN from the quote body.
        #[serde(with = "hex_bytes")]
        tcb_svn: Vec<u8>,
    },
}

/// Helper module for serializing Vec<u8> as hex strings.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Helper module for serializing `Option<[u8; 48]>` as `Option<hex string>`.
pub(crate) mod hex_option_array48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<[u8; 48]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if v.len() != 48 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 48-byte hex digest, got {} bytes",
                        v.len()
                    )));
                }
                let mut out = [0u8; 48];
                out.copy_from_slice(&v);
                Ok(Some(out))
            }
        }
    }
}

/// Helper module for serializing `[Option<[u8; 48]>; 4]` as an array of
/// nullable hex strings.
pub(crate) mod hex_array_of_option_array48 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        arr: &[Option<[u8; 48]>; 4],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex: [Option<String>; 4] = [
            arr[0].as_ref().map(hex::encode),
            arr[1].as_ref().map(hex::encode),
            arr[2].as_ref().map(hex::encode),
            arr[3].as_ref().map(hex::encode),
        ];
        hex.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[Option<[u8; 48]>; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<Option<String>> = Vec::deserialize(deserializer)?;
        if v.len() != 4 {
            return Err(serde::de::Error::custom(format!(
                "expected 4-element RTMR array, got {}",
                v.len()
            )));
        }
        let mut out: [Option<[u8; 48]>; 4] = [None, None, None, None];
        for (i, slot) in v.into_iter().enumerate() {
            if let Some(s) = slot {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 48 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 48-byte rtmr[{i}], got {} bytes",
                        bytes.len()
                    )));
                }
                let mut a = [0u8; 48];
                a.copy_from_slice(&bytes);
                out[i] = Some(a);
            }
        }
        Ok(out)
    }
}
