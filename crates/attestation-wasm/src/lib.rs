use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use wasm_bindgen::prelude::*;

use attestation::collateral::CertProvider;
use attestation::error::{AttestationError, Result as AttestationResult};
use attestation::platforms::az_snp::evidence::AzSnpEvidence;
use attestation::platforms::az_snp::verify::verify_report;
use attestation::platforms::az_tdx::evidence::AzTdxEvidence;
use attestation::platforms::snp::verify::{
    check_report_bindings, check_vek_against_crl, evaluate_report, parse_report,
    verify_report_signature, verify_vek_endorsement, MAX_REPORT_VERSION,
};
use attestation::platforms::tdx::collateral::StaticTdxCollateral;
use attestation::platforms::tdx::evidence::TdxEvidence;
use attestation::platforms::tdx::verify::{
    parse_tdx_quote, verify_collateral as verify_tdx_collateral,
};
use attestation::types::{PlatformType, ProcessorGeneration, SnpTcb};
use attestation::{
    AzSnpParams, AzTdx, AzTdxParams, Context, GcpSnpParams, GcpTdxParams, Platform, Policies,
    SnpParams, Tdx, TdxParams,
};

/// Serialize a result for JS: the result's fields plus `platform` and
/// `passed`, so every entry point returns the same top-level keys.
fn result_json(
    result: &impl serde::Serialize,
    platform: &str,
    passed: bool,
) -> Result<serde_json::Value, String> {
    let mut json = serde_json::to_value(result).map_err(|e| format!("json serialize: {e}"))?;
    json["platform"] = platform.into();
    json["passed"] = passed.into();
    Ok(json)
}

fn to_string(json: &serde_json::Value) -> Result<String, String> {
    serde_json::to_string_pretty(json).map_err(|e| format!("json serialize: {e}"))
}

/// Current time in Unix seconds (the browser clock on wasm).
fn now() -> i64 {
    Context::offline().now()
}

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

/// Caller-supplied TDX DCAP collateral as `evaluate_tdx` takes it: the Intel
/// PCS v4 JSON bodies verbatim (the signatures cover them), the issuer chains
/// as URL-decoded PEM (PCS sends the headers percent-encoded), the CRLs
/// base64-encoded (DER or PEM inside), and the verification time in Unix
/// seconds.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TdxCollateralJson {
    tcb_info: String,
    tcb_info_issuer_chain: String,
    qe_identity: String,
    qe_identity_issuer_chain: String,
    pck_crl: String,
    root_ca_crl: String,
    at: i64,
}

fn parse_tdx_collateral(json: &str) -> Result<StaticTdxCollateral, String> {
    let c: TdxCollateralJson =
        serde_json::from_str(json).map_err(|e| format!("tdx collateral deserialize: {e}"))?;
    let crl = |name: &str, b64: &str| {
        BASE64
            .decode(b64)
            .map_err(|e| format!("tdx collateral {name} base64: {e}"))
    };
    Ok(StaticTdxCollateral {
        pck_crl: crl("pck_crl", &c.pck_crl)?,
        root_ca_crl: crl("root_ca_crl", &c.root_ca_crl)?,
        tcb_info: c.tcb_info.into_bytes(),
        tcb_info_issuer_chain: c.tcb_info_issuer_chain.into_bytes(),
        qe_identity: c.qe_identity.into_bytes(),
        qe_identity_issuer_chain: c.qe_identity_issuer_chain.into_bytes(),
        at: c.at,
    })
}

/// Cert provider for the generic entry point: no fetches (the VEK must be
/// inline), and the SNP CRL is the caller-supplied DER blob. The core verifies
/// the CRL's signature against the bundled ARK and its freshness before
/// trusting it, so the bytes need no transport trust.
struct StaticSnpCollateral {
    crl_der: Option<Vec<u8>>,
}

fn not_fetched(what: &str) -> AttestationError {
    AttestationError::CollateralUnavailable(format!("the browser verifier does not fetch {what}"))
}

#[async_trait::async_trait]
impl CertProvider for StaticSnpCollateral {
    async fn get_snp_vcek(
        &self,
        _processor_gen: ProcessorGeneration,
        _chip_id: &[u8; 64],
        _reported_tcb: &SnpTcb,
    ) -> AttestationResult<Vec<u8>> {
        Err(not_fetched("the VEK (the evidence carries none)"))
    }

    async fn get_snp_cert_chain(
        &self,
        _processor_gen: ProcessorGeneration,
    ) -> AttestationResult<(Vec<u8>, Vec<u8>)> {
        Err(not_fetched("the AMD cert chain"))
    }

    async fn get_snp_crl(
        &self,
        _processor_gen: ProcessorGeneration,
    ) -> AttestationResult<Option<Vec<u8>>> {
        Ok(self.crl_der.clone())
    }
}

/// Evaluate attestation evidence from a self-describing envelope — the
/// generic, platform-dispatching entry point.
///
/// `envelope_json` is the core [`attestation::AttestationEvidence`] envelope:
/// `{ "platform": "<tag>", "evidence": { ... } }`. `platforms` lists the
/// platform tags the caller accepts (`snp`, `tdx`, `az-snp`, `az-tdx`,
/// `gcp-snp`, `gcp-tdx`); evidence for any other platform throws, so the
/// envelope's tag (an attester claim) cannot pick a platform the caller did
/// not allow. An empty list throws.
///
/// Runs offline ([`attestation::Context::offline`]): quote signatures and cert
/// chains verify against the bundled AMD/Intel roots (SNP evidence must carry
/// its VEK inline), and the SNP processor generation is auto-detected from
/// the report's CPUID fields (v3+ reports). Debug guests never pass
/// (`allow_debug` is never exposed to the browser).
///
/// Collateral: the TDX checks that need Intel PCS (PCK CRL, TCB status, QE
/// identity) are skipped; use [`evaluate_tdx`] to supply that collateral. For
/// SNP, the caller may staple the AMD KDS CRL as `snp_crl_der`; its signature
/// and thisUpdate/nextUpdate window are verified before the VEK's issuing
/// ASK/ASVK is checked against it (`crl_ok`, false if revoked). Without it,
/// revocation is skipped (`crl_ok: null`). A CRL that cannot be parsed, is
/// not ARK-signed or is stale throws.
///
/// `min_tcb_json`, when supplied, is the minimum SNP TCB policy as
/// [`SnpTcb`] JSON (`{ "bootloader": u8, "tee": u8, "snp": u8,
/// "microcode": u8, "fmc"?: u8 }`), reported as `min_tcb_met`. SNP platforms
/// only.
///
/// `expected_report_data` is checked against the hardware quote's
/// `report_data` on bare-metal platforms and against the vTPM quote's
/// `extraData` on Azure. A mismatch is `report_data_match: false` and
/// `passed: false`.
///
/// - `envelope_json`: `{ platform, evidence }` envelope JSON
/// - `platforms`: accepted platform tags, at least one
/// - `expected_report_data`: optional freshness anchor bytes
/// - `expected_init_data_hash`: optional init-data binding (SNP HOST_DATA /
///   TDX MRCONFIGID / vTPM PCR[8])
/// - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON)
/// - `snp_crl_der`: optional DER AMD KDS CRL for the report's generation
///
/// Returns the [`attestation::Verified`] result as JSON with `passed`. Throws
/// only when the evidence cannot be evaluated (malformed, not genuine,
/// platform not accepted, invalid params, bad collateral); mismatches and
/// policy flags are values in the result, so the caller must read `passed`.
#[wasm_bindgen]
pub async fn evaluate(
    envelope_json: String,
    platforms: Vec<String>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    snp_crl_der: Option<Vec<u8>>,
) -> Result<String, JsError> {
    evaluate_impl(
        envelope_json,
        platforms,
        expected_report_data,
        expected_init_data_hash,
        min_tcb_json,
        snp_crl_der,
    )
    .await
    .map_err(|e| JsError::new(&e))
}

async fn evaluate_impl(
    envelope_json: String,
    platforms: Vec<String>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    snp_crl_der: Option<Vec<u8>>,
) -> Result<String, String> {
    if platforms.is_empty() {
        return Err("platforms: name at least one accepted platform".into());
    }
    let min_tcb = parse_min_tcb(min_tcb_json)?;
    let tdx = TdxParams {
        report_data: expected_report_data.clone(),
        init_data: expected_init_data_hash.clone(),
        ..Default::default()
    };
    let snp = SnpParams {
        report_data: expected_report_data,
        host_data: expected_init_data_hash,
        min_tcb,
        ..Default::default()
    };
    let mut policies = Policies::default();
    for tag in &platforms {
        let platform: PlatformType = serde_json::from_value(tag.as_str().into())
            .map_err(|_| format!("platforms: unknown platform {tag:?}"))?;
        match platform {
            PlatformType::Tdx => policies.tdx = Some(tdx.clone()),
            PlatformType::AzTdx => {
                policies.az_tdx = Some(AzTdxParams {
                    tdx: tdx.clone(),
                    ..Default::default()
                })
            }
            PlatformType::GcpTdx => {
                policies.gcp_tdx = Some(GcpTdxParams {
                    tdx: tdx.clone(),
                    ..Default::default()
                })
            }
            PlatformType::Snp => policies.snp = Some(snp.clone()),
            PlatformType::AzSnp => {
                policies.az_snp = Some(AzSnpParams {
                    snp: snp.clone(),
                    ..Default::default()
                })
            }
            PlatformType::GcpSnp => {
                policies.gcp_snp = Some(GcpSnpParams {
                    snp: snp.clone(),
                    ..Default::default()
                })
            }
            PlatformType::Dstack => return Err(format!("platforms: {tag} is not compiled in")),
        }
    }

    let ctx = Context::offline().with_cert_provider(StaticSnpCollateral {
        crl_der: snp_crl_der,
    });
    let verified = attestation::Verifier::new(ctx)
        .verify(envelope_json.as_bytes(), &policies)
        .await
        .map_err(|e| format!("verify: {e}"))?;

    let mut json = serde_json::to_value(&verified).map_err(|e| format!("json serialize: {e}"))?;
    json["passed"] = verified.passed().into();
    to_string(&json)
}

/// Evaluate live SNP evidence in WASM.
///
/// Enforces the same endorsement-key and platform-security policy as the
/// native SNP verifier (`platforms/snp/verify.rs`), minus only VEK fetching
/// (the VEK must be inline). The one intentional difference from the generic
/// [`evaluate`] entry point is the explicit `generation` argument: v2 reports
/// (Azure HCL evidence unwrapped to a bare report) carry no CPUID fields to
/// auto-detect from, so the caller declares the generation and the VEK chain
/// check authenticates it — a wrong declaration fails its own chain.
///
/// Checks, in native order: ARK → ASK/ASVK → VEK chain against the bundled
/// roots (VLEK auto-detected), VEK validity period, VEK chip-id/TCB OID
/// cross-validation against the report, the report signature, and optional
/// CRL revocation; a failure there throws. Then the policy, reported as
/// values: VMPL must be 0 and debug off (no opt-in here), the optional
/// minimum-TCB floor, and the optional `report_data` anchor. `passed` is true
/// only when all of them hold.
///
/// Collateral: when `crl_der` carries the AMD KDS CRL for this generation,
/// its signature is verified against the bundled ARK and its
/// thisUpdate/nextUpdate window against the current time, then the VEK's
/// issuing ASK/ASVK is checked against it: `crl_ok` (false if revoked).
/// Without it, revocation is skipped (`crl_ok: null`).
///
/// - `evidence_json`: evidence JSON with inline cert_chain.vcek
/// - `generation`: processor generation ("milan", "genoa", "turin")
/// - `expected_report_data`: optional raw bytes to check against report_data
///   in the report (reported as `report_data_match`)
/// - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON),
///   reported as `min_tcb_met`
/// - `crl_der`: optional DER AMD KDS CRL for this generation
///
/// Returns the result as JSON with `passed`. Throws only when the evidence
/// cannot be evaluated (including an `expected_report_data` over 64 bytes).
#[wasm_bindgen]
pub fn evaluate_snp(
    evidence_json: &str,
    generation: &str,
    expected_report_data: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, JsError> {
    evaluate_snp_impl(
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
fn evaluate_snp_impl(
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
    let params = SnpParams {
        report_data: expected_report_data,
        min_tcb: parse_min_tcb(min_tcb_json)?,
        ..Default::default()
    };
    params.validate().map_err(|e| e.to_string())?;

    let evidence: attestation::platforms::snp::evidence::SnpEvidence =
        serde_json::from_str(evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;

    let report_bytes = BASE64
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
        Some(chain) => BASE64
            .decode(&chain.vcek)
            .map_err(|e| format!("base64 decode vcek: {e}"))?,
        None => return Err("evidence missing cert_chain.vcek".to_string()),
    };

    // Endorsement-key policy: bundled ARK → ASK/ASVK → VEK chain, VEK validity
    // period, and VEK chip-id/TCB OID cross-validation against the report —
    // the checks whose absence let an expired or wrong-platform VEK vouch for
    // a report here while the native verifier rejected it.
    let now = now();
    verify_vek_endorsement(&report, &vek_der, gen, now)
        .map_err(|e| format!("VEK endorsement: {e}"))?;

    // Verify report signature
    verify_report_signature(&report_bytes, &vek_der)
        .map_err(|e| format!("report signature: {e}"))?;

    // CRL revocation check, once the report is known to be genuine —
    // caller-supplied collateral, ARK-signature- and freshness-verified
    // before it is trusted. A revoked ASK/ASVK is a value (`crl_ok: false`).
    let crl_ok = crl_der
        .map(|crl| check_vek_against_crl(&vek_der, &crl, gen, now))
        .transpose()
        .map_err(|e| format!("CRL check: {e}"))?;

    // Guest policy, as values. VMPL must be 0 and debug off: a malicious host
    // can launch the *correctly-measured* image as a debug-enabled or
    // non-VMPL-0 SNP guest and read its memory, and a measurement pin cannot
    // catch that (SEV-SNP guest policy lives in the report, not the launch
    // measurement). The browser entry has no `allow_debug` opt-in.
    let mut result = evaluate_report(&report, &params, crl_ok);
    check_report_bindings(&mut result, &report, &params).map_err(|e| e.to_string())?;

    let mut json = result_json(&result, "snp", result.passed())?;
    json["report_version"] = report.version.into();
    to_string(&json)
}

/// Evaluate Azure SEV-SNP (az-snp) vTPM attestation evidence in WASM.
///
/// Unlike [`evaluate_snp`], which only checks the bare SNP hardware report, this
/// verifies the full az-snp evidence: the HCL-wrapped SNP report **and** the
/// vTPM quote that binds freshness. The freshness anchor for az-snp lives in
/// the TPM quote's `extraData` (qualifyingData), not in the SNP `report_data`
/// — the SNP `report_data` instead binds the vTPM attestation key (AK).
///
/// Verification (mirrors the native async path):
/// 1. Verify the TPM quote signature with the AK extracted from HCL var_data.
/// 2. Check the quote's `extraData` equals `expected_report_data` (freshness),
///    reported as `report_data_match`.
/// 3. Verify the PCR digest, and optionally compare PCR[8] with
///    `expected_init_data_hash` (`host_data_match`).
/// 4. Bind the AK to the TEE: `snp.report_data[..32] == SHA-256(var_data)`.
/// 5. Validate the VCEK chain (auto-detecting the generation from CPUID) and the
///    SNP report signature, then evaluate VMPL/debug and the optional
///    minimum-TCB floor as values.
/// 6. When `crl_der` carries the AMD KDS CRL for the matched generation, verify
///    its ARK signature and freshness, then check the VCEK's issuing ASK
///    against it: `crl_ok` (false if revoked). Without it, revocation is
///    skipped (`crl_ok: null`).
///
/// - `evidence_json`: az-snp evidence JSON (`{ version, tpm_quote, hcl_report, vcek }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
/// - `min_tcb_json`: optional minimum SNP TCB policy ([`SnpTcb`] JSON)
/// - `crl_der`: optional DER AMD KDS CRL for the report's generation
///
/// Returns the verification result as JSON with `passed`. Throws only when
/// the evidence cannot be verified; mismatches and policy flags are values.
#[wasm_bindgen]
pub fn evaluate_az_snp(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, JsError> {
    evaluate_az_snp_impl(
        evidence_json,
        expected_report_data,
        expected_init_data_hash,
        min_tcb_json,
        crl_der,
    )
    .map_err(|e| JsError::new(&e))
}

// Off-wasm-testable body, same rationale as evaluate_snp_impl / evaluate_tdx_impl.
fn evaluate_az_snp_impl(
    evidence_json: &str,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    crl_der: Option<Vec<u8>>,
) -> Result<String, String> {
    let evidence: AzSnpEvidence =
        serde_json::from_str(evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;
    let min_tcb = parse_min_tcb(min_tcb_json)?;

    let params = AzSnpParams {
        snp: SnpParams {
            report_data: expected_report_data,
            host_data: expected_init_data_hash,
            min_tcb,
            ..Default::default()
        },
        ..Default::default()
    };
    let now = now();
    let verified =
        verify_report(&evidence, &params, now).map_err(|e| format!("az-snp verify: {e}"))?;
    let report_version = verified.report_version;

    // CRL revocation check — caller-supplied collateral, exactly the check the
    // native async path (`AzSnp::verify`) runs with a provider-fetched CRL.
    let result = match crl_der {
        Some(crl) => verified
            .check_crl(&crl, now)
            .map_err(|e| format!("CRL check: {e}"))?,
        None => verified.result,
    };

    let mut json = result_json(&result, "az-snp", result.passed())?;
    json["report_version"] = report_version.into();
    to_string(&json)
}

/// Evaluate bare-metal Intel TDX (tdx) DCAP attestation evidence in WASM.
///
/// This is the direct-DCAP counterpart of [`evaluate_az_tdx`]: no vTPM in the
/// path, so the freshness anchor lives directly in the TD quote's 64-byte
/// `report_data` (zero-padded), as produced by attesters that bind
/// `SHA-384(anchor)` — e.g. a serving-cert SPKI + nonce, or a session
/// public key + nonce. Verification (see `platforms/tdx/verify.rs`):
/// 1. Parse the TD quote (v4/v5) and verify its ECDSA P-256 signature.
/// 2. Verify the full DCAP chain: PCK cert chain to the pinned Intel SGX Root
///    CA, QE report signature, and QE report binding.
/// 3. Report the TD debug attribute (`debug`; debug TDs never pass — no
///    opt-in here).
/// 4. Compare `report_data` with `expected_report_data` (padded,
///    constant-time): `report_data_match`.
/// 5. Optionally compare MRCONFIGID with `expected_init_data_hash`:
///    `init_data_match`.
/// 6. When the evidence carries a `cc_eventlog`, replay it against the RTMRs:
///    RTMR[0-2] divergence fails closed; RTMR[3] divergence only warns, because
///    runtime extends after the log was captured are expected there (see
///    `platforms/tdx/ccel.rs`).
/// 7. When `expected_rtmr3` is supplied, compare the TD's RTMR[3] with it:
///    `rtmr_match[3]`.
///
/// The DCAP **collateral** checks (PCK CRL, TCB status, TD-QE identity) run
/// only on caller-supplied collateral (`tdx_collateral_json`): the browser
/// cannot fetch Intel PCS itself. Without it they are skipped (`tcb_status`
/// and `crl_ok` are `null`). With it, every item is verified
/// against Intel's signatures, and TCB Info, QE Identity and the CRLs must be
/// current at `at` (certificate validity uses the current time; see
/// [`StaticTdxCollateral`]). A failure throws with a `TDX collateral:`
/// prefix, and the result carries the evaluated `tcb_status` and `crl_ok`. A
/// `Revoked` or `NoMatchingLevel` TCB and a revoked PCK certificate do not
/// pass; accepting the other statuses is the caller's policy.
/// The measurement surfaces as `claims.launch_digest` = hex(MRTD); MRTD
/// pinning is the JS policy layer's job.
///
/// - `evidence_json`: tdx evidence JSON (`{ quote, cc_eventlog? }`, base64 std)
/// - `expected_report_data`: optional raw bytes the TD quote `report_data`
///   must equal after zero-padding to 64 bytes
/// - `expected_init_data_hash`: optional bytes to bind against MRCONFIGID
/// - `expected_rtmr3`: optional 48 raw bytes the TD's RTMR[3] must equal
/// - `tdx_collateral_json`: optional collateral `{ tcb_info,
///   tcb_info_issuer_chain, qe_identity, qe_identity_issuer_chain, pck_crl,
///   root_ca_crl, at }` — PCS JSON bodies verbatim, issuer chains as
///   URL-decoded PEM, CRLs base64, `at` in Unix seconds
///
/// RTMR[3] is the runtime measurement register: unlike MRTD it is extended
/// after launch, so it can carry deployment identity a launch measurement
/// cannot — on a c8s node, the operator-key seed plus any per-workload
/// extends. Pinning it is what distinguishes *this* cluster from anyone
/// else's genuine instance of the same audited image. It is not replayable
/// from the CCEL by construction (see `platforms/tdx/ccel.rs`), which is why
/// it must be supplied rather than derived.
///
/// A mismatch is `rtmr_match[3]: false` and `passed: false`: a browser policy
/// layer must read `passed`, not rely on a throw.
///
/// Returns the verification result as JSON with `passed`. Throws only when
/// the evidence or the collateral cannot be verified.
///
/// `async` because the shared core is `async` for its collateral provider;
/// the supplied-collateral provider performs no actual awaiting. Callers
/// `await` the returned Promise.
#[wasm_bindgen]
pub async fn evaluate_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,
    tdx_collateral_json: Option<String>,
) -> Result<String, JsError> {
    evaluate_tdx_impl(
        evidence_json,
        expected_report_data,
        expected_init_data_hash,
        expected_rtmr3,
        tdx_collateral_json,
    )
    .await
    .map_err(|e| JsError::new(&e))
}

// The whole entry point behind the wasm-bindgen boundary, so the enforcement
// gate is exercisable by native tests (JsError carries no readable message off
// the wasm target). Behavior-identical to the wrapper.
async fn evaluate_tdx_impl(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,
    tdx_collateral_json: Option<String>,
) -> Result<String, String> {
    let evidence: TdxEvidence =
        serde_json::from_str(&evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;
    let collateral = tdx_collateral_json
        .as_deref()
        .map(parse_tdx_collateral)
        .transpose()?;

    // Reject a wrong-sized pin rather than truncating or dropping it: a pin
    // that silently does not apply is worse than no pin at all.
    let expected_rtmr3: Option<[u8; 48]> = match expected_rtmr3 {
        None => None,
        Some(bytes) => Some(
            <[u8; 48]>::try_from(bytes.as_slice())
                .map_err(|_| format!("expected_rtmr3 is {} bytes, want 48", bytes.len()))?,
        ),
    };

    let params = TdxParams {
        report_data: expected_report_data,
        init_data: expected_init_data_hash,
        rtmr: [None, None, None, expected_rtmr3.map(|v| vec![v])],
        ..Default::default()
    };

    // Evidence fully first, then the collateral step alone, so a failure of
    // the latter is attributable to the collateral.
    let ctx = Context::offline();
    let mut result = Tdx::verify(&evidence, &params, &ctx)
        .await
        .map_err(|e| format!("tdx verify: {e}"))?;
    if let Some(collateral) = &collateral {
        // Re-decoding is parsing only; the evidence pass already accepted these bytes.
        let quote_bytes = BASE64
            .decode(&evidence.quote)
            .map_err(|e| format!("tdx verify: quote base64: {e}"))?;
        let quote = parse_tdx_quote(&quote_bytes).map_err(|e| format!("tdx verify: {e}"))?;
        let checked = verify_tdx_collateral(&quote_bytes, &quote, collateral, ctx.now())
            .await
            .map_err(|e| format!("tdx verify: TDX collateral: {e}"))?;
        result.set_collateral(checked, &params);
    }

    to_string(&result_json(&result, "tdx", result.passed())?)
}

/// Evaluate Azure TDX (az-tdx) vTPM attestation evidence in WASM.
///
/// The Azure TDX shape mirrors az-snp: the freshness anchor lives in the vTPM
/// quote's `extraData` (qualifyingData), while the Intel-signed TD quote's
/// `report_data` binds the vTPM attestation key (AK). Verification order
/// (see `platforms/az_tdx/verify.rs`):
/// 1. Parse the HCL report and require `report_type == TDX`.
/// 2. Verify the vTPM quote signature with the AK extracted from HCL var_data.
/// 3. Check the quote's `extraData` equals `expected_report_data` (freshness),
///    reported as `report_data_match`.
/// 4. Verify the PCR digest, and optionally compare PCR[8] with
///    `expected_init_data_hash` (`init_data_match`).
/// 5. Parse the TD quote, verify its ECDSA signature, and verify the DCAP chain
///    to the pinned Intel SGX Root CA.
/// 6. Report the TD debug attribute (debug TDs never pass — no opt-in here).
/// 7. Bind the AK to the TEE: `td_report.report_data[..32] == SHA-256(var_data)`.
///
/// Like [`evaluate_az_snp`], the DCAP **collateral** checks (PCK CRL, TCB
/// status, TD-QE identity) need an async provider and are skipped in WASM, so
/// `tcb_status` and `crl_ok` are always `null`. The measurement surfaces as
/// `claims.launch_digest` = hex(MRTD); MRTD/RTMR pinning is the JS policy
/// layer's job (a mismatch is reported, not fatal, in the core).
///
/// - `evidence_json`: az-tdx evidence JSON (`{ version, tpm_quote, hcl_report, td_quote }`)
/// - `expected_report_data`: optional raw bytes the TPM quote `extraData` must equal
/// - `expected_init_data_hash`: optional 32-byte hash to bind against PCR[8]
///
/// Unlike [`evaluate_tdx`], this entry point has **no `expected_rtmr3`
/// parameter and enforces no RTMR[3] pin** — do not assume parity. The az-tdx
/// core computes `rtmr_match[3]` the same way, so extending this entry point is
/// a known follow-up; until then an az-tdx caller cannot pin deployment
/// identity here.
///
/// Returns the verification result as JSON with `passed`. Throws only when
/// the evidence cannot be verified; mismatches and policy flags are values.
///
/// This is `async` (unlike `evaluate_az_snp`, whose core is sync) because the
/// shared az-tdx core is `async` for its optional collateral provider; with a
/// `None` provider it performs no actual awaiting. Callers `await` the returned
/// Promise.
#[wasm_bindgen]
pub async fn evaluate_az_tdx(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, JsError> {
    evaluate_az_tdx_impl(evidence_json, expected_report_data, expected_init_data_hash)
        .await
        .map_err(|e| JsError::new(&e))
}

async fn evaluate_az_tdx_impl(
    evidence_json: String,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
) -> Result<String, String> {
    let evidence: AzTdxEvidence =
        serde_json::from_str(&evidence_json).map_err(|e| format!("evidence deserialize: {e}"))?;

    let params = AzTdxParams {
        tdx: TdxParams {
            report_data: expected_report_data,
            init_data: expected_init_data_hash,
            ..Default::default()
        },
        ..Default::default()
    };

    // Offline context: CRL/TCB/QE-identity checks are skipped (same trade-off
    // evaluate_az_snp documents).
    let result = AzTdx::verify(&evidence, &params, &Context::offline())
        .await
        .map_err(|e| format!("az-tdx verify: {e}"))?;

    to_string(&result_json(&result, "az-tdx", result.passed())?)
}

// Native tests for the entry points. They run on the host target
// (`cargo test -p attestation-wasm`), not under wasm — which is why each
// entry point's body lives in an `_impl` function: JsError exposes no
// readable message off-wasm.
#[cfg(test)]
mod tests {
    use super::*;
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
        let out = evaluate_tdx_impl(
            v5_evidence_json(),
            None,
            None,
            Some(v5_rtmr3().to_vec()),
            None,
        )
        .await
        .expect("matching RTMR[3] pin must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            json["rtmr_match"][3],
            serde_json::json!(true),
            "result must record the comparison"
        );
        assert_eq!(json["passed"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn rtmr3_pin_mismatch_does_not_pass() {
        let out = evaluate_tdx_impl(v5_evidence_json(), None, None, Some(vec![0xAA; 48]), None)
            .await
            .expect("a pin mismatch is a value, not a throw");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["rtmr_match"][3], serde_json::json!(false));
        assert_eq!(json["passed"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn rtmr3_pin_wrong_length_rejected_before_verification() {
        for len in [0usize, 47, 49, 96] {
            let err =
                evaluate_tdx_impl(v5_evidence_json(), None, None, Some(vec![0xAA; len]), None)
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
        let out = evaluate_snp_impl(&snp_evidence_json(), "genoa", None, None, None)
            .expect("live genoa fixture must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["passed"], serde_json::json!(true));
        assert_eq!(json["report_version"], serde_json::json!(5));
        assert!(json["crl_ok"].is_null(), "no CRL supplied: not checked");
    }

    #[test]
    fn snp_oversize_report_data_throws() {
        evaluate_snp_impl(&snp_evidence_json(), "genoa", Some(vec![0; 65]), None, None)
            .expect_err("report_data over 64 bytes is invalid params, not a mismatch");
    }

    #[test]
    fn snp_wrong_generation_fails_chain() {
        let err = evaluate_snp_impl(&snp_evidence_json(), "milan", None, None, None)
            .expect_err("declared generation must be authenticated by the VEK chain");
        assert!(err.contains("VEK endorsement"), "got: {err}");
    }

    #[test]
    fn snp_min_tcb_at_floor_passes() {
        evaluate_snp_impl(
            &snp_evidence_json(),
            "genoa",
            None,
            Some(reported_tcb_json(0)),
            None,
        )
        .expect("reported TCB at the floor must pass");
    }

    #[test]
    fn snp_min_tcb_below_floor_does_not_pass() {
        let out = evaluate_snp_impl(
            &snp_evidence_json(),
            "genoa",
            None,
            Some(reported_tcb_json(1)),
            None,
        )
        .expect("a TCB below the floor is a value, not a throw");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["min_tcb_met"], serde_json::json!(false));
        assert_eq!(json["passed"], serde_json::json!(false));
    }

    #[test]
    fn snp_malformed_min_tcb_rejected_before_verification() {
        for bad in ["not json", "{}", r#"{"bootloader": 3}"#] {
            let err = evaluate_snp_impl(
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
        let err = evaluate_snp_impl(
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
    fn az_snp_min_tcb_below_floor_does_not_pass() {
        let evidence: serde_json::Value = serde_json::from_str(AZ_SNP_MILAN_V3).unwrap();
        let evidence = evidence["evidence"].to_string();
        // A floor above any real Milan microcode SPL.
        let floor = r#"{"bootloader":0,"tee":0,"snp":0,"microcode":255}"#;
        let out = evaluate_az_snp_impl(&evidence, None, None, Some(floor.to_string()), None)
            .expect("a TCB below the floor is a value on az-snp too");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["min_tcb_met"], serde_json::json!(false));
        assert_eq!(json["passed"], serde_json::json!(false));
    }

    #[test]
    fn az_snp_garbage_crl_rejected() {
        let evidence: serde_json::Value = serde_json::from_str(AZ_SNP_MILAN_V3).unwrap();
        let evidence = evidence["evidence"].to_string();
        let err = evaluate_az_snp_impl(&evidence, None, None, None, Some(vec![0xAB; 64]))
            .expect_err("unparseable CRL must fail closed");
        assert!(err.contains("CRL check"), "got: {err}");
    }

    #[tokio::test]
    async fn no_pin_leaves_rtmr3_match_null() {
        let out = evaluate_tdx_impl(v5_evidence_json(), None, None, None, None)
            .await
            .expect("unpinned verification must still pass");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            json["rtmr_match"][3].is_null(),
            "no pin ⇒ null, so \"never checked\" cannot read as \"held\""
        );
    }

    // --- bare-TDX supplied collateral ---

    const C8S_QUOTE: &[u8] =
        include_bytes!("../../attestation/test_data/tdx_quote_00a06d080000.dat");
    const COLLATERAL_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../attestation/test_data/collateral/2026-10-05/"
    );
    /// 2026-10-06T00:00:00Z, inside every fixture item's validity window.
    const COLLATERAL_AT: i64 = 1_791_244_800;

    fn c8s_evidence_json() -> String {
        serde_json::to_string(&TdxEvidence {
            quote: BASE64.encode(C8S_QUOTE),
            cc_eventlog: None,
        })
        .unwrap()
    }

    fn collateral_json(at: i64) -> serde_json::Value {
        let read = |f: &str| std::fs::read(format!("{COLLATERAL_DIR}{f}")).unwrap();
        let text = |f: &str| String::from_utf8(read(f)).unwrap();
        serde_json::json!({
            "tcb_info": text("tcb_info_00a06d080000.json"),
            "tcb_info_issuer_chain": text("tcb_signing_chain.pem"),
            "qe_identity": text("td_qe_identity.json"),
            "qe_identity_issuer_chain": text("qe_identity_signing_chain.pem"),
            "pck_crl": BASE64.encode(read("pck_crl_platform.der")),
            "root_ca_crl": BASE64.encode(read("root_ca_crl.der")),
            "at": at,
        })
    }

    #[tokio::test]
    async fn tdx_collateral_surfaces_the_tcb_status() {
        let out = evaluate_tdx_impl(
            c8s_evidence_json(),
            None,
            None,
            None,
            Some(collateral_json(COLLATERAL_AT).to_string()),
        )
        .await
        .expect("current collateral must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["crl_ok"], serde_json::json!(true));
        assert_eq!(json["tcb_status"]["tcb_status"], "UpToDate");
        assert_eq!(json["tcb_status"]["fmspc"], "00a06d080000");
    }

    #[tokio::test]
    async fn tdx_without_collateral_reports_none_evaluated() {
        let out = evaluate_tdx_impl(c8s_evidence_json(), None, None, None, None)
            .await
            .expect("evidence must verify");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(json["crl_ok"].is_null());
        assert!(json["tcb_status"].is_null());
    }

    #[tokio::test]
    async fn tdx_collateral_failure_is_tagged() {
        let err = evaluate_tdx_impl(
            c8s_evidence_json(),
            None,
            None,
            None,
            Some(collateral_json(COLLATERAL_AT + 60 * 86_400).to_string()),
        )
        .await
        .expect_err("stale collateral must fail");
        assert!(err.starts_with("tdx verify: TDX collateral: "), "{err}");
    }

    #[tokio::test]
    async fn tdx_wrong_report_data_does_not_pass() {
        let out = evaluate_tdx_impl(
            c8s_evidence_json(),
            Some(vec![0xFF; 64]),
            None,
            None,
            Some(collateral_json(COLLATERAL_AT).to_string()),
        )
        .await
        .expect("a report_data mismatch is a value, not a throw");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["report_data_match"], serde_json::json!(false));
        assert_eq!(json["passed"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn tdx_quote_signature_failure_is_not_tagged_as_collateral() {
        let mut quote = C8S_QUOTE.to_vec();
        quote[100] ^= 0x01; // inside the signed TD report body
        let evidence = serde_json::to_string(&TdxEvidence {
            quote: BASE64.encode(quote),
            cc_eventlog: None,
        })
        .unwrap();
        let err = evaluate_tdx_impl(
            evidence,
            None,
            None,
            None,
            Some(collateral_json(COLLATERAL_AT).to_string()),
        )
        .await
        .expect_err("tampered quote must fail");
        assert!(!err.contains("TDX collateral"), "{err}");
        assert!(err.contains("ECDSA P-256 DCAP"), "{err}");
    }

    #[tokio::test]
    async fn tdx_malformed_collateral_rejected_before_verification() {
        let mut c = collateral_json(COLLATERAL_AT);
        c["extra"] = serde_json::json!(1);
        let err = evaluate_tdx_impl(c8s_evidence_json(), None, None, None, Some(c.to_string()))
            .await
            .expect_err("unknown field must be rejected");
        assert!(err.contains("tdx collateral deserialize"), "{err}");
    }

    fn tdx_envelope() -> String {
        serde_json::json!({
            "platform": "tdx",
            "evidence": { "quote": BASE64.encode(V5_QUOTE) },
        })
        .to_string()
    }

    #[tokio::test]
    async fn evaluate_accepts_only_the_listed_platforms() {
        let accepted = |platforms: &[&str]| {
            evaluate_impl(
                tdx_envelope(),
                platforms.iter().map(|p| p.to_string()).collect(),
                None,
                None,
                None,
                None,
            )
        };
        let out = accepted(&["tdx"]).await.expect("tdx accepted");
        let json: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(json["platform"], "tdx");
        assert_eq!(json["passed"], true);

        accepted(&["snp", "az-tdx"])
            .await
            .expect_err("tdx evidence when only snp and az-tdx are accepted");
        accepted(&[]).await.expect_err("no accepted platform");
        accepted(&["sgx"]).await.expect_err("unknown platform tag");
    }
}
