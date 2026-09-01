use wasm_bindgen::prelude::*;

use attestation::collateral::{CertProvider, DefaultCertProvider};
use attestation::error::Result as AttestationResult;
use attestation::platforms::az_snp::evidence::AzSnpEvidence;
use attestation::platforms::az_snp::verify::{verify_report, VerifiedReport};
use attestation::platforms::az_tdx::evidence::AzTdxEvidence;
use attestation::platforms::az_tdx::verify::verify_evidence as verify_az_tdx_evidence;
use attestation::platforms::snp::certs::get_ark;
use attestation::platforms::snp::claims::extract_claims;
use attestation::platforms::snp::verify::{
    check_vcek_not_revoked, enforce_min_tcb, parse_report, verify_report_signature,
    verify_vek_endorsement, MAX_REPORT_VERSION,
};
use attestation::platforms::tdx::evidence::TdxEvidence;
use attestation::platforms::tdx::verify::verify_evidence as verify_tdx_evidence;
use attestation::types::{ProcessorGeneration, SnpTcb, VerifyParams};
use attestation::utils::{constant_time_eq, pad_report_data};

/// Parse the optional minimum-TCB policy JSON (the [`SnpTcb`] shape:
/// `{ "bootloader": u8, "tee": u8, "snp": u8, "microcode": u8, "fmc"?: u8 }`).
fn parse_min_tcb(min_tcb_json: Option<String>) -> Result<Option<SnpTcb>, String> {
    match min_tcb_json {
        None => Ok(None),
        Some(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| format!("min_tcb deserialize: {e}")),
    }
}

/// Cert provider for the generic offline entry point: VEK resolution and the
/// ARK/ASK chain behave exactly like [`DefaultCertProvider`] on wasm (inline
/// VEK required, bundled roots), but the SNP CRL is the caller-supplied DER
/// blob instead of a network fetch. The core verifies the CRL's signature
/// against the bundled ARK and its freshness before trusting it, so the bytes
/// themselves need no transport trust.
struct StaticSnpCollateral {
    inner: DefaultCertProvider,
    crl_der: Option<Vec<u8>>,
}

#[async_trait::async_trait]
impl CertProvider for StaticSnpCollateral {
    async fn get_snp_vcek(
        &self,
        processor_gen: ProcessorGeneration,
        chip_id: &[u8; 64],
        reported_tcb: &SnpTcb,
    ) -> AttestationResult<Vec<u8>> {
        self.inner
            .get_snp_vcek(processor_gen, chip_id, reported_tcb)
            .await
    }

    async fn get_snp_cert_chain(
        &self,
        processor_gen: ProcessorGeneration,
    ) -> AttestationResult<(Vec<u8>, Vec<u8>)> {
        self.inner.get_snp_cert_chain(processor_gen).await
    }

    async fn get_snp_crl(
        &self,
        _processor_gen: ProcessorGeneration,
    ) -> AttestationResult<Option<Vec<u8>>> {
        Ok(self.crl_der.clone())
    }
}

/// Verify attestation evidence from a self-describing envelope — the generic,
/// platform-dispatching entry point and the preferred API for JS embedders.
///
/// `envelope_json` is the core [`attestation::AttestationEvidence`] envelope:
/// `{ "platform": "<tag>", "evidence": { ... } }`, where `platform` is one of
/// the compiled-in platform tags (`snp`, `tdx`, `az-snp`, `az-tdx`, `gcp-snp`,
/// `gcp-tdx` with default features) and `evidence` is that platform's evidence
/// payload, verbatim. Dispatch happens in the Rust core
/// (`Verifier::verify_platform`), so JS callers need no per-platform routing —
/// but they MUST assert the platform themselves by comparing the result's
/// `platform` field against the one they expect, never trusting a
/// server-chosen tag to pick the verification path.
///
/// Runs in offline mode ([`attestation::Verifier::offline`]): quote signatures
/// and cert chains verify against the bundled AMD/Intel roots (SNP evidence
/// must carry its VEK inline, as c8s evidence does), and the SNP processor
/// generation is auto-detected from the report's CPUID fields (v3+ reports).
/// Debug guests are always rejected (`allow_debug` is never exposed to the
/// browser; fail closed).
///
/// Collateral: the TDX network-backed checks (PCK CRL, TCB status, QE
/// identity) need an async provider and are skipped. For SNP, the caller may
/// staple the AMD KDS CRL as `snp_crl_der` — its signature is verified against
/// the bundled ARK and its thisUpdate/nextUpdate window against the current
/// time before it is trusted, then the VEK is checked against it and
/// `collateral_verified` becomes `true`. Without it, revocation is skipped and
/// `collateral_verified` stays `false` — the caller's policy layer decides
/// whether that qualifies as verified.
///
/// `min_tcb_json`, when supplied, is the minimum SNP TCB policy as
/// [`SnpTcb`] JSON (`{ "bootloader": u8, "tee": u8, "snp": u8,
/// "microcode": u8, "fmc"?: u8 }`); a report whose reported TCB is below any
/// component fails closed. SNP platforms only — it is ignored by the TDX
/// verifiers, so TDX callers must not rely on it.
///
/// The freshness semantics of `expected_report_data` are per-platform, handled
/// inside each core verifier: for bare-metal platforms it is checked against
/// the hardware quote's `report_data` (zero-padded, constant-time); for the
/// Azure vTPM platforms it is checked against the vTPM quote's `extraData`.
/// Either way a supplied-but-mismatched anchor fails closed.
///
/// - `envelope_json`: `{ platform, evidence }` envelope JSON
/// - `expected_report_data`: optional freshness anchor bytes
/// - `expected_init_data_hash`: optional init-data binding (SNP HOST_DATA /
///   TDX MRCONFIGID / vTPM PCR[8])
/// - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON)
/// - `snp_crl_der`: optional DER AMD KDS CRL for the report's generation
///
/// Returns the [`attestation::types::VerificationResult`] as JSON, or throws
/// on any check failure.
#[wasm_bindgen]
pub async fn verify(
    envelope_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    snp_crl_der: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let min_tcb = parse_min_tcb(min_tcb_json).map_err(|e| JsError::new(&e))?;
    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        min_tcb,
        ..VerifyParams::default()
    };

    let result = attestation::Verifier::offline()
        .with_cert_provider(StaticSnpCollateral {
            inner: DefaultCertProvider::new(),
            crl_der: snp_crl_der,
        })
        .verify(envelope_json.as_bytes(), &params)
        .await
        .map_err(|e| JsError::new(&format!("verify: {e}")))?;

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

/// Verify live SNP evidence in WASM.
///
/// Enforces the same endorsement-key and platform-security policy as the
/// native SNP verifier (`platforms/snp/verify.rs`), minus only VEK fetching
/// (the VEK must be inline). The one intentional difference from the generic
/// [`verify`] entry point is the explicit `generation` argument: v2 reports
/// (Azure HCL evidence unwrapped to a bare report) carry no CPUID fields to
/// auto-detect from, so the caller declares the generation and the VEK chain
/// check authenticates it — a wrong declaration fails its own chain.
///
/// Checks, in native order: ARK → ASK/ASVK → VEK chain against the bundled
/// roots (VLEK auto-detected), VEK validity period, optional CRL revocation,
/// report signature, VMPL == 0, debug-policy rejection (no opt-in here; fail
/// closed), VEK chip-id/TCB OID cross-validation against the report, and the
/// optional minimum-TCB floor.
///
/// Collateral: when `crl_der` carries the AMD KDS CRL for this generation,
/// its signature is verified against the bundled ARK and its
/// thisUpdate/nextUpdate window against the current time, then the VEK is
/// checked against it and the result's `collateral_verified` is `true`.
/// Without it, revocation is skipped and `collateral_verified` is `false` —
/// surfaced, never silently upgraded.
///
/// - `evidence_json`: evidence JSON with inline cert_chain.vcek
/// - `generation`: processor generation ("milan", "genoa", "turin")
/// - `expected_report_data`: optional raw bytes to check against report_data
///   in the report (comparison reported as `report_data_match`, not fatal —
///   the policy layer decides)
/// - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON); a
///   reported TCB below any component fails closed
/// - `crl_der`: optional DER AMD KDS CRL for this generation
///
/// Returns verification result as JSON.
#[wasm_bindgen]
pub fn verify_snp(
    evidence_json: &str,
    generation: &str,
    expected_report_data: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, JsError> {
    verify_snp_impl(
        evidence_json,
        generation,
        expected_report_data,
        min_tcb_json,
        crl_der,
    )
    .map_err(|e| JsError::new(&e))
}

// The whole entry point behind the wasm-bindgen boundary, so every enforcement
// gate is exercisable by native tests (JsError carries no readable message off
// the wasm target). Behavior-identical to the wrapper.
fn verify_snp_impl(
    evidence_json: &str,
    generation: &str,
    expected_report_data: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, String> {
    let gen = match generation {
        "milan" | "Milan" => ProcessorGeneration::Milan,
        "genoa" | "Genoa" => ProcessorGeneration::Genoa,
        "turin" | "Turin" => ProcessorGeneration::Turin,
        _ => return Err(format!("unknown generation: {generation}")),
    };
    let min_tcb = parse_min_tcb(min_tcb_json)?;

    let evidence: attestation::platforms::snp::evidence::SnpEvidence =
        serde_json::from_str(evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;

    use base64::Engine;
    let report_bytes = base64::engine::general_purpose::STANDARD
        .decode(&evidence.attestation_report)
        .map_err(|e| format!("base64 decode report: {e}"))?;

    let report = parse_report(&report_bytes).map_err(|e| format!("parse report: {e}"))?;

    // Same version window as the native az-snp path: v2 (HCL-unwrapped, no
    // CPUID fields) up to the shared maximum.
    const MIN_REPORT_VERSION: u32 = 2;
    if report.version < MIN_REPORT_VERSION || report.version > MAX_REPORT_VERSION {
        return Err(format!(
            "report version {} not supported (min: {MIN_REPORT_VERSION}, max: {MAX_REPORT_VERSION})",
            report.version
        ));
    }

    // Get VCEK from evidence
    let vek_der = match &evidence.cert_chain {
        Some(chain) => base64::engine::general_purpose::STANDARD
            .decode(&chain.vcek)
            .map_err(|e| format!("base64 decode vcek: {e}"))?,
        None => return Err("evidence missing cert_chain.vcek".to_string()),
    };

    // Endorsement-key policy: bundled ARK → ASK/ASVK → VEK chain, VEK validity
    // period, and VEK chip-id/TCB OID cross-validation against the report —
    // the checks whose absence let an expired or wrong-platform VEK vouch for
    // a report here while the native verifier rejected it.
    verify_vek_endorsement(&report, &vek_der, gen).map_err(|e| format!("VEK endorsement: {e}"))?;

    // CRL revocation check — caller-supplied collateral, ARK-signature- and
    // freshness-verified before it is trusted (AMD CRLs are signed by the
    // ARK, not the ASK/ASVK intermediate).
    let collateral_verified = match crl_der {
        Some(crl) => {
            check_vcek_not_revoked(&vek_der, &crl, get_ark(gen))
                .map_err(|e| format!("CRL check: {e}"))?;
            true
        }
        None => false,
    };

    // Verify report signature
    verify_report_signature(&report_bytes, &vek_der)
        .map_err(|e| format!("report signature: {e}"))?;

    // Guest-policy enforcement — mirrors the native `verify_report` path
    // (`platforms/snp/verify.rs`: VMPL==0 and debug-policy rejection). Without
    // these, a malicious host can launch the *correctly-measured* image as a
    // debug-enabled or non-VMPL-0 SNP guest: the launch_digest still matches a
    // pinned allowlist, the VCEK chain and report signature are genuine, and
    // report_data still binds the session key — yet the hypervisor can read the
    // guest's memory (debug) or a lower-privilege VMPL can, so it extracts the
    // session key and reads the "confidential" channel. The browser entry has no
    // `allow_debug` opt-in: it fails closed. (SEV-SNP guest policy lives in the
    // report, not the launch measurement, so a measurement pin cannot catch this.)
    if report.vmpl != 0 {
        return Err(format!(
            "VMPL check failed: report VMPL is {} (expected 0)",
            report.vmpl
        ));
    }
    if report.policy.debug_allowed() {
        return Err(
            "SNP guest policy permits debug (host can read guest memory); rejecting (fail closed)"
                .to_string(),
        );
    }

    // Minimum-TCB floor
    if let Some(ref min) = min_tcb {
        enforce_min_tcb(&report.reported_tcb, min).map_err(|e| format!("minimum TCB: {e}"))?;
    }

    // Check report_data binding
    let report_data_match = expected_report_data.map(|expected| {
        let padded = pad_report_data(&expected, 64).unwrap_or_default();
        constant_time_eq(&report.report_data[..], &padded)
    });

    // Extract claims
    let claims = extract_claims(&report);

    let result = serde_json::json!({
        "signature_valid": true,
        "platform": "snp",
        "report_version": report.version,
        "report_data_match": report_data_match,
        "collateral_verified": collateral_verified,
        "claims": claims,
    });

    serde_json::to_string_pretty(&result).map_err(|e| format!("json serialize: {e}"))
}

/// Verify Azure SEV-SNP (az-snp) vTPM attestation evidence in WASM.
///
/// Unlike [`verify_snp`], which only checks the bare SNP hardware report, this
/// verifies the full az-snp evidence: the HCL-wrapped SNP report **and** the
/// vTPM quote that binds freshness. The freshness anchor for az-snp lives in
/// the TPM quote's `extraData` (qualifyingData), not in the SNP `report_data`
/// — the SNP `report_data` instead binds the vTPM attestation key (AK).
///
/// Verification (mirrors the native async path):
/// 1. Verify the TPM quote signature with the AK extracted from HCL var_data.
/// 2. Check the quote's `extraData` equals `expected_report_data` (freshness),
///    failing closed when an anchor is supplied and does not match.
/// 3. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
/// 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
/// 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
///    SNP report signature, then enforce VMPL/debug/TCB policy and the optional
///    minimum-TCB floor.
/// 6. When `crl_der` carries the AMD KDS CRL for the matched generation, verify
///    its ARK signature and freshness, then check the VCEK against it —
///    `collateral_verified` becomes `true`. Without it, revocation is skipped
///    and `collateral_verified` stays `false`.
///
/// - `evidence_json`: az-snp evidence JSON (`{ version, tpm_quote, hcl_report, vcek }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
/// - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON)
/// - `crl_der`: optional DER AMD KDS CRL for the report's generation
///
/// Returns the verification result as JSON, or throws on any check failure.
#[wasm_bindgen]
pub fn verify_az_snp(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, JsError> {
    verify_az_snp_impl(
        evidence_json,
        expected_report_data,
        expected_init_data_hash,
        min_tcb_json,
        crl_der,
    )
    .map_err(|e| JsError::new(&e))
}

// Off-wasm-testable body, same rationale as verify_snp_impl / verify_tdx_impl.
fn verify_az_snp_impl(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, String> {
    let evidence: AzSnpEvidence =
        serde_json::from_str(evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;
    let min_tcb = parse_min_tcb(min_tcb_json)?;

    // Run the full az-snp verification core, freshness included. When an anchor is
    // supplied, the core binds the TPM quote's extraData (qualifyingData) to it and
    // fails closed on a mismatch — defense in depth, rather than downgrading the
    // freshness check to a non-throwing bool for the JS policy layer to interpret.
    // The core still populates report_data_match (Some(true) when an anchor was
    // supplied and matched, None otherwise) for the result shape.
    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        min_tcb,
        ..VerifyParams::default()
    };

    let VerifiedReport {
        mut result,
        matched_gen,
        vcek_der,
        report_version,
    } = verify_report(&evidence, &params).map_err(|e| format!("az-snp verify: {e}"))?;

    // CRL revocation check — caller-supplied collateral, exactly the check the
    // native async wrapper (`az_snp::verify::verify_evidence`) runs with a
    // provider-fetched CRL. AMD CRLs are signed by the ARK, not the ASK/ASVK
    // intermediate, and the CRL's signature and freshness are verified before
    // it is trusted.
    if let Some(crl) = crl_der {
        check_vcek_not_revoked(&vcek_der, &crl, get_ark(matched_gen))
            .map_err(|e| format!("CRL check: {e}"))?;
        result.collateral_verified = true;
    }

    // Serialize the VerificationResult, then graft on report_version, matching the
    // shape verify_snp returns so the JS policy layer reads it uniformly.
    let mut result = serde_json::to_value(&result).map_err(|e| format!("json serialize: {e}"))?;
    result["report_version"] = serde_json::json!(report_version);

    serde_json::to_string_pretty(&result).map_err(|e| format!("json serialize: {e}"))
}

/// Verify bare-metal Intel TDX (tdx) DCAP attestation evidence in WASM.
///
/// This is the direct-DCAP counterpart of [`verify_az_tdx`]: no vTPM in the
/// path, so the freshness anchor lives directly in the TD quote's 64-byte
/// `report_data` (zero-padded), as produced by attesters that bind
/// `SHA-384(anchor)` — e.g. a serving-cert SPKI + nonce, or a session
/// public key + nonce. Verification (see `platforms/tdx/verify.rs`):
/// 1. Parse the TD quote (v4/v5) and verify its ECDSA P-256 signature.
/// 2. Verify the full DCAP chain: PCK cert chain to the pinned Intel SGX Root
///    CA, QE report signature, and QE report binding.
/// 3. Enforce the TD debug-attribute policy (reject debug TDs — no opt-in here).
/// 4. Bind `report_data` to `expected_report_data` (padded, constant-time),
///    failing closed when an anchor is supplied and does not match.
/// 5. Optionally bind MRCONFIGID to `expected_init_data_hash`.
/// 6. When the evidence carries a `cc_eventlog`, replay it against the RTMRs:
///    RTMR[0-2] divergence fails closed; RTMR[3] divergence only warns, because
///    runtime extends after the log was captured are expected there (see
///    `platforms/tdx/ccel.rs`).
/// 7. When `expected_rtmr3` is supplied, require the TD's RTMR[3] to match it.
///
/// Like the other vTPM-less entry points, the DCAP **collateral** checks (PCK
/// CRL, TCB status, TD-QE identity) need an async provider and are skipped in
/// WASM, so `collateral_verified` is always `false`. The measurement surfaces
/// as `claims.launch_digest` = hex(MRTD); MRTD pinning is the JS policy
/// layer's job.
///
/// - `evidence_json`: tdx evidence JSON (`{ quote, cc_eventlog? }`, base64 std)
/// - `expected_report_data`: optional raw bytes the TD quote `report_data`
///   must equal after zero-padding to 64 bytes
/// - `expected_init_data_hash`: optional bytes to bind against MRCONFIGID
/// - `expected_rtmr3`: optional 48 raw bytes the TD's RTMR[3] must equal
///
/// RTMR[3] is the runtime measurement register: unlike MRTD it is extended
/// after launch, so it can carry deployment identity a launch measurement
/// cannot — on a c8s node, the operator-key seed plus any per-workload
/// extends. Pinning it is what distinguishes *this* cluster from anyone
/// else's genuine instance of the same audited image. It is not replayable
/// from the CCEL by construction (see `platforms/tdx/ccel.rs`), which is why
/// it must be supplied rather than derived.
///
/// Unlike [`VerifyParams::expected_rtmr3`], which only *reports* the
/// comparison via `rtmr3_match`, this entry point **fails closed**: a
/// mismatch throws, matching how `expected_report_data` behaves here. A
/// browser policy layer that forwarded the pin but forgot to inspect
/// `rtmr3_match` would otherwise silently accept any node.
///
/// Returns the verification result as JSON, or throws on any check failure.
///
/// `async` for the same reason as [`verify_az_tdx`]: the shared core is
/// `async` for its optional collateral provider; with a `None` provider it
/// performs no actual awaiting. Callers `await` the returned Promise.
#[wasm_bindgen]
pub async fn verify_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,
) -> Result<String, JsError> {
    verify_tdx_impl(
        evidence_json,
        expected_report_data,
        expected_init_data_hash,
        expected_rtmr3,
    )
    .await
    .map_err(|e| JsError::new(&e))
}

// The whole entry point behind the wasm-bindgen boundary, so the enforcement
// gate is exercisable by native tests (JsError carries no readable message off
// the wasm target). Behavior-identical to the wrapper.
async fn verify_tdx_impl(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,
) -> Result<String, String> {
    let evidence: TdxEvidence =
        serde_json::from_str(&evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;

    // Reject a wrong-sized pin rather than truncating or dropping it: a pin
    // that silently does not apply is worse than no pin at all.
    let expected_rtmr3: Option<[u8; 48]> = match expected_rtmr3 {
        None => None,
        Some(bytes) => Some(
            <[u8; 48]>::try_from(bytes.as_slice())
                .map_err(|_| format!("expected_rtmr3 is {} bytes, want 48", bytes.len()))?,
        ),
    };
    let rtmr3_pinned = expected_rtmr3.is_some();

    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        expected_rtmr3,
        ..VerifyParams::default()
    };

    // None collateral provider: CRL/TCB/QE-identity checks are skipped (same
    // trade-off the other WASM entry points document), collateral_verified
    // stays false.
    let result = verify_tdx_evidence(&evidence, &params, None)
        .await
        .map_err(|e| format!("tdx verify: {e}"))?;

    // The core records the comparison without acting on it. Enforce here so a
    // supplied pin cannot be a no-op. `None` means the core never performed the
    // comparison at all — treat that as a failure, not an absence.
    if rtmr3_pinned && result.rtmr3_match != Some(true) {
        return Err("tdx verify: RTMR[3] does not match expected_rtmr3 \
             (the guest was not launched with the pinned operator key, \
             or it measured workloads the pin does not account for)"
            .to_string());
    }

    serde_json::to_string_pretty(&result).map_err(|e| format!("json serialize: {e}"))
}

/// Verify Azure TDX (az-tdx) vTPM attestation evidence in WASM.
///
/// The Azure TDX shape mirrors az-snp: the freshness anchor lives in the vTPM
/// quote's `extraData` (qualifyingData), while the Intel-signed TD quote's
/// `report_data` binds the vTPM attestation key (AK). Verification order
/// (see `platforms/az_tdx/verify.rs`):
/// 1. Parse the HCL report and require `report_type == TDX`.
/// 2. Verify the vTPM quote signature with the AK extracted from HCL var_data.
/// 3. Check the quote's `extraData` equals `expected_report_data` (freshness),
///    failing closed when an anchor is supplied and does not match.
/// 4. Verify the PCR digest, and optionally bind PCR[8] to `expected_init_data_hash`.
/// 5. Parse the TD quote, verify its ECDSA signature, and verify the DCAP chain
///    to the pinned Intel SGX Root CA.
/// 6. Enforce the TD debug-attribute policy (reject debug TDs — no opt-in here).
/// 7. Bind the AK to the TEE: `td_report.report_data[..32] == SHA-256(var_data)`.
///
/// Like [`verify_az_snp`], the DCAP **collateral** checks (PCK CRL, TCB status,
/// TD-QE identity) need an async provider and are skipped in WASM, so
/// `collateral_verified` is always `false`. The measurement surfaces as
/// `claims.launch_digest` = hex(MRTD); MRTD/RTMR pinning is the JS policy
/// layer's job (a mismatch is reported, not fatal, in the core).
///
/// - `evidence_json`: az-tdx evidence JSON (`{ version, tpm_quote, hcl_report, td_quote }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
///
/// Unlike [`verify_tdx`], this entry point has **no `expected_rtmr3`
/// parameter and enforces no RTMR[3] pin** — do not assume parity. The az-tdx
/// core computes `rtmr3_match` the same way, so extending this entry point is
/// a known follow-up; until then an az-tdx caller cannot pin deployment
/// identity here.
///
/// Returns the verification result as JSON, or throws on any check failure.
///
/// This is `async` (unlike `verify_az_snp`, whose core is sync) because the
/// shared az-tdx core is `async` for its optional collateral provider; with a
/// `None` provider it performs no actual awaiting. Callers `await` the returned
/// Promise.
#[wasm_bindgen]
pub async fn verify_az_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    let evidence: AzTdxEvidence = serde_json::from_str(&evidence_json)
        .map_err(|e| JsError::new(&format!("evidence deserialize: {e}")))?;

    let params = VerifyParams {
        expected_report_data,
        expected_init_data_hash,
        ..VerifyParams::default()
    };

    // None collateral provider: CRL/TCB/QE-identity checks are skipped (same
    // trade-off verify_az_snp documents), collateral_verified stays false.
    let result = verify_az_tdx_evidence(&evidence, &params, None)
        .await
        .map_err(|e| JsError::new(&format!("az-tdx verify: {e}")))?;

    serde_json::to_string_pretty(&result).map_err(|e| JsError::new(&format!("json serialize: {e}")))
}

// Native tests for the RTMR[3] enforcement gate. They run on the host target
// (`cargo test -p attestation-wasm`), not under wasm — which is exactly why
// the gate lives in verify_tdx_impl rather than inside the #[wasm_bindgen]
// wrapper: JsError exposes no readable message off-wasm, and the fail-closed
// property ("only Some(true) passes") deserves CI coverage rather than
// by-inspection assurance.
#[cfg(test)]
mod tests {
    use super::*;
    use attestation::platforms::tdx::verify::parse_tdx_quote;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    // The v5 fixture verifies fully under default params (no debug bit — the
    // v4 fixture has it set and would fail the debug policy before the gate).
    const V5_QUOTE: &[u8] = include_bytes!("../../attestation/test_data/tdx_quote_5.dat");

    fn v5_evidence_json() -> String {
        serde_json::to_string(&TdxEvidence {
            quote: BASE64.encode(V5_QUOTE),
            cc_eventlog: None,
        })
        .unwrap()
    }

    fn v5_rtmr3() -> [u8; 48] {
        parse_tdx_quote(V5_QUOTE).unwrap().body.rtmr_3
    }

    #[tokio::test]
    async fn rtmr3_pin_matching_register_passes() {
        let out = verify_tdx_impl(v5_evidence_json(), None, None, Some(v5_rtmr3().to_vec()))
            .await
            .expect("matching RTMR[3] pin must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            json["rtmr3_match"],
            serde_json::json!(true),
            "result must record the comparison"
        );
    }

    #[tokio::test]
    async fn rtmr3_pin_mismatch_fails_closed() {
        let err = verify_tdx_impl(v5_evidence_json(), None, None, Some(vec![0xAA; 48]))
            .await
            .expect_err("wrong RTMR[3] pin must fail");
        assert!(
            err.contains("RTMR[3] does not match expected_rtmr3"),
            "failure must name the pin, got: {err}"
        );
    }

    #[tokio::test]
    async fn rtmr3_pin_wrong_length_rejected_before_verification() {
        for len in [0usize, 47, 49, 96] {
            let err = verify_tdx_impl(v5_evidence_json(), None, None, Some(vec![0xAA; len]))
                .await
                .expect_err("wrong-length pin must be rejected");
            assert!(
                err.contains("want 48"),
                "length {len}: error must name the size contract, got: {err}"
            );
        }
    }

    // --- bare-SNP entry point: endorsement parity, min-TCB floor, CRL ---

    const SNP_REPORT_V5: &[u8] =
        include_bytes!("../../attestation/test_data/snp/live-report-v5-genoa.bin");
    const SNP_VCEK_GENOA: &[u8] =
        include_bytes!("../../attestation/test_data/snp/live-vcek-genoa.der");
    const AZ_SNP_MILAN_V3: &str =
        include_str!("../../attestation/test_data/az_snp/milan-v3-attestation.json");

    fn snp_evidence_json() -> String {
        serde_json::json!({
            "attestation_report": BASE64.encode(SNP_REPORT_V5),
            "cert_chain": { "vcek": BASE64.encode(SNP_VCEK_GENOA) },
        })
        .to_string()
    }

    fn reported_tcb_json(microcode_bump: u8) -> String {
        let report = parse_report(SNP_REPORT_V5).unwrap();
        let tcb = report.reported_tcb;
        serde_json::json!({
            "bootloader": tcb.bootloader,
            "tee": tcb.tee,
            "snp": tcb.snp,
            "microcode": tcb.microcode + microcode_bump,
        })
        .to_string()
    }

    #[test]
    fn snp_valid_evidence_passes_without_collateral() {
        let out = verify_snp_impl(&snp_evidence_json(), "genoa", None, None, None)
            .expect("live genoa fixture must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["signature_valid"], serde_json::json!(true));
        assert_eq!(json["report_version"], serde_json::json!(5));
        assert_eq!(
            json["collateral_verified"],
            serde_json::json!(false),
            "no CRL supplied ⇒ revocation was not checked, and the result must say so"
        );
    }

    #[test]
    fn snp_wrong_generation_fails_chain() {
        let err = verify_snp_impl(&snp_evidence_json(), "milan", None, None, None)
            .expect_err("declared generation must be authenticated by the VEK chain");
        assert!(err.contains("VEK endorsement"), "got: {err}");
    }

    #[test]
    fn snp_min_tcb_at_floor_passes() {
        verify_snp_impl(
            &snp_evidence_json(),
            "genoa",
            None,
            Some(reported_tcb_json(0)),
            None,
        )
        .expect("reported TCB at the floor must pass");
    }

    #[test]
    fn snp_min_tcb_below_floor_fails_closed() {
        let err = verify_snp_impl(
            &snp_evidence_json(),
            "genoa",
            None,
            Some(reported_tcb_json(1)),
            None,
        )
        .expect_err("below-floor TCB must fail closed");
        assert!(err.contains("below minimum"), "got: {err}");
    }

    #[test]
    fn snp_malformed_min_tcb_rejected_before_verification() {
        for bad in ["not json", "{}", r#"{"bootloader": 3}"#] {
            let err = verify_snp_impl(
                &snp_evidence_json(),
                "genoa",
                None,
                Some(bad.to_string()),
                None,
            )
            .expect_err("malformed min_tcb must be rejected, not dropped");
            assert!(err.contains("min_tcb deserialize"), "{bad}: got {err}");
        }
    }

    #[test]
    fn snp_garbage_crl_rejected() {
        let err = verify_snp_impl(
            &snp_evidence_json(),
            "genoa",
            None,
            None,
            Some(vec![0xAB; 64]),
        )
        .expect_err("unparseable CRL must fail closed, never read as checked");
        assert!(err.contains("CRL check"), "got: {err}");
    }

    // --- az-snp entry point: min-TCB floor and CRL pass-through ---

    #[test]
    fn az_snp_min_tcb_below_floor_fails_closed() {
        let evidence: serde_json::Value = serde_json::from_str(AZ_SNP_MILAN_V3).unwrap();
        let evidence = evidence["evidence"].to_string();
        // A floor above any real Milan microcode SPL.
        let floor = r#"{"bootloader":0,"tee":0,"snp":0,"microcode":255}"#;
        let err = verify_az_snp_impl(&evidence, None, None, Some(floor.to_string()), None)
            .expect_err("below-floor TCB must fail closed on az-snp too");
        assert!(err.contains("below minimum"), "got: {err}");
    }

    #[test]
    fn az_snp_garbage_crl_rejected() {
        let evidence: serde_json::Value = serde_json::from_str(AZ_SNP_MILAN_V3).unwrap();
        let evidence = evidence["evidence"].to_string();
        let err = verify_az_snp_impl(&evidence, None, None, None, Some(vec![0xAB; 64]))
            .expect_err("unparseable CRL must fail closed");
        assert!(err.contains("CRL check"), "got: {err}");
    }

    #[test]
    fn az_snp_no_collateral_surfaces_false() {
        let evidence: serde_json::Value = serde_json::from_str(AZ_SNP_MILAN_V3).unwrap();
        let evidence = evidence["evidence"].to_string();
        let out = verify_az_snp_impl(&evidence, None, None, None, None)
            .expect("milan v3 fixture must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["collateral_verified"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn no_pin_verifies_and_omits_rtmr3_match() {
        let out = verify_tdx_impl(v5_evidence_json(), None, None, None)
            .await
            .expect("unpinned verification must still pass");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            json.get("rtmr3_match").is_none(),
            "no pin ⇒ no rtmr3_match field, so \"never checked\" cannot read as \"held\""
        );
    }
}
