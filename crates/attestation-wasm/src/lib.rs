//! The verifier for browsers and other JS runtimes. WASM does no network or
//! disk I/O, so the caller fetches the vendor URLs for the evidence
//! ([`collateral_needed`]) and hands the responses to [`evaluate`], which
//! verifies each piece of collateral exactly as the native verifier does.

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use attestation::types::{PlatformType, SnpTcb};
use attestation::{
    AttestationError, AzSnpParams, AzTdxParams, Context, GcpSnpParams, GcpTdxParams, Policies,
    SnpParams, TdxParams, Verifier,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// Why a call failed. Thrown as a JS `Error` with this `kind`, named like
/// the API's error keys:
/// - `collateral_unavailable`: a piece of collateral is missing; fetch and
///   retry.
/// - `bad_request`: the call's arguments or params cannot be applied.
/// - `platform_not_allowed`: the evidence is for a platform not accepted.
/// - `verification_failed`: the evidence, or its collateral, is not genuine.
#[derive(Debug)]
struct Failure {
    kind: &'static str,
    message: String,
}

impl Failure {
    fn bad_request(message: String) -> Self {
        Self {
            kind: "bad_request",
            message,
        }
    }
}

impl From<AttestationError> for Failure {
    fn from(e: AttestationError) -> Self {
        let kind = match &e {
            _ if e.is_retryable() => "collateral_unavailable",
            _ if e.is_invalid_params() => "bad_request",
            AttestationError::PlatformNotAllowed(_) => "platform_not_allowed",
            _ => "verification_failed",
        };
        Self {
            kind,
            message: e.to_string(),
        }
    }
}

impl From<Failure> for JsValue {
    fn from(f: Failure) -> Self {
        let error = js_sys::Error::new(&f.message);
        js_sys::Reflect::set(&error, &"kind".into(), &f.kind.into())
            .expect("setting a property on a new Error");
        error.into()
    }
}

/// A vendor response: the URL [`collateral_needed`] listed, the body
/// base64, and the URL-decoded value of the `*-Issuer-Chain` header Intel
/// PCS sends with TCB Info, QE Identity and PCK CRLs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Held {
    url: String,
    body: String,
    #[serde(default)]
    issuer_chain: Option<String>,
}

/// The vendor URLs to fetch to verify `envelope_json` (an `{ platform,
/// evidence }` envelope), as a JSON array of strings. Fetch each and pass the
/// responses to [`evaluate`] as `{ url, body (base64), issuer_chain }`.
///
/// Evidence that is malformed or not genuine throws (see [`Failure`]): it
/// never names collateral to fetch.
#[wasm_bindgen]
pub async fn collateral_needed(envelope_json: String) -> Result<String, JsValue> {
    Ok(collateral_needed_impl(&envelope_json).await?)
}

async fn collateral_needed_impl(envelope_json: &str) -> Result<String, Failure> {
    let verifier = Verifier::new(Context::held([]));
    match verifier
        .verify(envelope_json.as_bytes(), &Policies::all())
        .await
    {
        Err(e) if !e.is_retryable() => return Err(e.into()),
        _ => {}
    }
    let needed = verifier.context().store().missing();
    Ok(serde_json::to_string(&needed).expect("URLs serialize"))
}

/// Evaluate attestation evidence from a self-describing envelope with the
/// collateral the caller fetched.
///
/// - `envelope_json`: `{ platform, evidence }` envelope JSON
/// - `platforms`: accepted platform tags (`snp`, `tdx`, `az-snp`, `az-tdx`,
///   `gcp-snp`, `gcp-tdx`), at least one; evidence for any other platform
///   throws
/// - `expected_report_data`: optional freshness anchor bytes (the hardware
///   report's `report_data`, or the vTPM quote nonce on Azure)
/// - `expected_init_data_hash`: optional init-data binding (SNP HOST_DATA /
///   TDX MRCONFIGID / vTPM PCR[8])
/// - `expected_rtmr3`: optional 48 bytes the TD's RTMR[3] must equal (TDX
///   platforms)
/// - `min_tcb_json`: optional minimum SNP TCB policy (`SnpTcb` JSON)
/// - `collateral_json`: the responses for the URLs [`collateral_needed`]
///   listed
///
/// Returns the `Verified` result as JSON with `passed`. Throws (see
/// [`Failure`]) when the evidence cannot be evaluated: malformed, not
/// genuine, platform not accepted, invalid params, needed collateral
/// missing, or collateral that is not the vendor's. Mismatches, policy
/// flags and expired collateral are values: read `passed`.
#[wasm_bindgen]
pub async fn evaluate(
    envelope_json: String,
    platforms: Vec<String>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
    collateral_json: String,
) -> Result<String, JsValue> {
    let request = Request {
        platforms,
        expected_report_data,
        expected_init_data_hash,
        expected_rtmr3,
        min_tcb_json,
    };
    Ok(evaluate_impl(&envelope_json, request, &collateral_json, None).await?)
}

struct Request {
    platforms: Vec<String>,
    expected_report_data: Option<Vec<u8>>,
    expected_init_data_hash: Option<Vec<u8>>,
    expected_rtmr3: Option<Vec<u8>>,
    min_tcb_json: Option<String>,
}

impl Request {
    fn policies(self) -> Result<Policies, String> {
        if self.platforms.is_empty() {
            return Err("platforms: name at least one accepted platform".into());
        }
        let min_tcb: Option<SnpTcb> = self
            .min_tcb_json
            .map(|s| serde_json::from_str(&s).map_err(|e| format!("min_tcb deserialize: {e}")))
            .transpose()?;
        // A pin that silently does not apply is worse than no pin at all.
        let rtmr3: Option<[u8; 48]> = self
            .expected_rtmr3
            .map(|bytes| {
                <[u8; 48]>::try_from(bytes.as_slice())
                    .map_err(|_| format!("expected_rtmr3 is {} bytes, want 48", bytes.len()))
            })
            .transpose()?;
        let tdx = TdxParams {
            report_data: self.expected_report_data.clone(),
            init_data: self.expected_init_data_hash.clone(),
            rtmr: [None, None, None, rtmr3.map(|v| vec![v])],
            ..Default::default()
        };
        let snp = SnpParams {
            report_data: self.expected_report_data,
            host_data: self.expected_init_data_hash,
            min_tcb,
            ..Default::default()
        };
        let mut policies = Policies::default();
        for tag in &self.platforms {
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
                PlatformType::GcpTdx => policies.gcp_tdx = Some(GcpTdxParams { tdx: tdx.clone() }),
                PlatformType::Snp => policies.snp = Some(snp.clone()),
                PlatformType::AzSnp => {
                    policies.az_snp = Some(AzSnpParams {
                        snp: snp.clone(),
                        ..Default::default()
                    })
                }
                PlatformType::GcpSnp => policies.gcp_snp = Some(GcpSnpParams { snp: snp.clone() }),
                PlatformType::Dstack => return Err(format!("platforms: {tag} is not compiled in")),
            }
        }
        Ok(policies)
    }
}

/// `now` fixes the evaluation time (Unix seconds); `None` is the clock.
async fn evaluate_impl(
    envelope_json: &str,
    request: Request,
    collateral_json: &str,
    now: Option<i64>,
) -> Result<String, Failure> {
    let policies = request.policies().map_err(Failure::bad_request)?;
    let held: Vec<Held> = serde_json::from_str(collateral_json)
        .map_err(|e| Failure::bad_request(format!("collateral deserialize: {e}")))?;
    let mut responses = Vec::with_capacity(held.len());
    for h in held {
        let body = BASE64
            .decode(&h.body)
            .map_err(|e| Failure::bad_request(format!("{}: body base64: {e}", h.url)))?;
        responses.push((h.url, body, h.issuer_chain));
    }
    let ctx = Context::held(responses);
    let ctx = match now {
        Some(t) => ctx.at(t)?,
        None => ctx,
    };
    let verified = Verifier::new(ctx)
        .verify(envelope_json.as_bytes(), &policies)
        .await?;
    let mut json = serde_json::to_value(&verified).expect("verdicts serialize");
    json["passed"] = verified.passed().into();
    Ok(serde_json::to_string_pretty(&json).expect("JSON serializes"))
}

// Native tests for the entry points (`cargo test -p attestation-wasm`): each
// entry point's body lives in an `_impl` function because JsError exposes no
// readable message off-wasm.
#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../attestation/test_data/");
    /// 2026-10-16T00:00:00Z: the fixture collateral is current.
    const NOW: i64 = 1_792_108_800;

    fn read(file: &str) -> Vec<u8> {
        std::fs::read(format!("{DATA}{file}")).unwrap()
    }

    fn tdx_envelope() -> String {
        serde_json::json!({
            "platform": "tdx",
            "evidence": { "quote": BASE64.encode(read("tdx_quote_00a06d080000.dat")) },
        })
        .to_string()
    }

    fn snp_envelope() -> String {
        String::from_utf8(read("snp/live-evidence-genoa.json")).unwrap()
    }

    fn request(platforms: &[&str]) -> Request {
        Request {
            platforms: platforms.iter().map(|p| p.to_string()).collect(),
            expected_report_data: None,
            expected_init_data_hash: None,
            expected_rtmr3: None,
            min_tcb_json: None,
        }
    }

    /// Fetch what `collateral_needed` lists from the fixtures, by URL.
    async fn fetch(envelope: &str) -> String {
        let needed: Vec<String> =
            serde_json::from_str(&collateral_needed_impl(envelope).await.unwrap()).unwrap();
        let file = |url: &str| -> (&str, Option<&str>) {
            match url {
                u if u.ends_with("/vcek/v1/Genoa/crl") => ("amd_crl_genoa.der", None),
                u if u.ends_with("fmspc=00a06d080000") => {
                    ("tcb_info_00a06d080000.json", Some("tcb_signing_chain.pem"))
                }
                u if u.ends_with("/qe/identity") => {
                    ("td_qe_identity.json", Some("tcb_signing_chain.pem"))
                }
                u if u.ends_with("pckcrl?ca=platform") => {
                    ("pck_crl_platform.pem", Some("pck_crl_platform_chain.pem"))
                }
                u if u.ends_with("IntelSGXRootCA.der") => ("root_ca_crl.der", None),
                other => panic!("unexpected URL {other}"),
            }
        };
        let held: Vec<serde_json::Value> = needed
            .iter()
            .map(|url| {
                let (body, chain) = file(url);
                let dir = "collateral/2026-10-14/";
                serde_json::json!({
                    "url": url,
                    "body": BASE64.encode(read(&format!("{dir}{body}"))),
                    "issuer_chain": chain.map(|c| String::from_utf8(read(&format!("{dir}{c}"))).unwrap()),
                })
            })
            .collect();
        serde_json::Value::from(held).to_string()
    }

    async fn evaluate(envelope: &str, request: Request) -> Result<serde_json::Value, Failure> {
        let collateral = fetch(envelope).await;
        evaluate_impl(envelope, request, &collateral, Some(NOW))
            .await
            .map(|json| serde_json::from_str(&json).unwrap())
    }

    #[tokio::test]
    async fn tdx_needs_four_intel_pieces_and_passes_with_them() {
        let needed: Vec<serde_json::Value> =
            serde_json::from_str(&collateral_needed_impl(&tdx_envelope()).await.unwrap()).unwrap();
        assert_eq!(needed.len(), 4);
        let r = evaluate(&tdx_envelope(), request(&["tdx"])).await.unwrap();
        assert_eq!(r["passed"], true);
        assert_eq!(r["tcb_status"]["tcb_status"], "UpToDate");
        assert_eq!(r["crl_ok"], true);
    }

    #[tokio::test]
    async fn snp_with_an_inline_vcek_needs_only_the_crl() {
        let needed: Vec<serde_json::Value> =
            serde_json::from_str(&collateral_needed_impl(&snp_envelope()).await.unwrap()).unwrap();
        assert_eq!(needed.len(), 1);
        let r = evaluate(&snp_envelope(), request(&["snp"])).await.unwrap();
        assert_eq!(r["passed"], true);
        assert_eq!(r["crl_ok"], true);
    }

    #[tokio::test]
    async fn missing_or_forged_collateral_throws() {
        let err = evaluate_impl(&tdx_envelope(), request(&["tdx"]), "[]", Some(NOW))
            .await
            .unwrap_err();
        assert_eq!(err.kind, "collateral_unavailable", "{err:?}");

        let mut held: Vec<serde_json::Value> =
            serde_json::from_str(&fetch(&snp_envelope()).await).unwrap();
        let mut crl = BASE64.decode(held[0]["body"].as_str().unwrap()).unwrap();
        *crl.last_mut().unwrap() ^= 1;
        held[0]["body"] = BASE64.encode(crl).into();
        let err = evaluate_impl(
            &snp_envelope(),
            request(&["snp"]),
            &serde_json::Value::from(held).to_string(),
            Some(NOW),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, "verification_failed", "{err:?}");
    }

    #[tokio::test]
    async fn forged_evidence_throws_and_names_no_collateral() {
        let mut quote = read("tdx_quote_00a06d080000.dat");
        quote[48 + 520] ^= 1;
        let forged = serde_json::json!({
            "platform": "tdx",
            "evidence": { "quote": BASE64.encode(quote) },
        })
        .to_string();
        let err = collateral_needed_impl(&forged).await.unwrap_err();
        assert_eq!(err.kind, "verification_failed", "{err:?}");
    }

    #[tokio::test]
    async fn rules_are_values() {
        let mut req = request(&["tdx"]);
        req.expected_rtmr3 = Some(vec![0; 48]);
        req.expected_report_data = Some(b"another nonce".to_vec());
        let r = evaluate(&tdx_envelope(), req).await.unwrap();
        assert_eq!(r["passed"], false);
        assert_eq!(r["rtmr_match"][3], false);
        assert_eq!(r["report_data_match"], false);
    }

    #[tokio::test]
    async fn bad_requests_throw_before_verification() {
        let mut short_pin = request(&["tdx"]);
        short_pin.expected_rtmr3 = Some(vec![0; 47]);
        let mut bad_tcb = request(&["snp"]);
        bad_tcb.min_tcb_json = Some("{".into());
        for req in [request(&[]), request(&["nope"]), short_pin, bad_tcb] {
            let err = evaluate_impl(&tdx_envelope(), req, "[]", Some(NOW))
                .await
                .unwrap_err();
            assert_eq!(err.kind, "bad_request", "{err:?}");
        }
    }

    #[tokio::test]
    async fn the_answer_is_the_librarys() {
        for (envelope, platform) in [(tdx_envelope(), "tdx"), (snp_envelope(), "snp")] {
            let collateral = fetch(&envelope).await;
            let wasm = evaluate_impl(&envelope, request(&[platform]), &collateral, Some(NOW))
                .await
                .unwrap();
            let held: Vec<Held> = serde_json::from_str(&collateral).unwrap();
            let ctx = Context::held(
                held.into_iter()
                    .map(|h| (h.url, BASE64.decode(h.body).unwrap(), h.issuer_chain)),
            )
            .at(NOW)
            .unwrap();
            let policies = request(&[platform]).policies().unwrap();
            let lib = Verifier::new(ctx)
                .verify(envelope.as_bytes(), &policies)
                .await
                .unwrap();
            let mut lib_json = serde_json::to_value(&lib).unwrap();
            lib_json["passed"] = lib.passed().into();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&wasm).unwrap(),
                lib_json
            );
        }
    }

    #[tokio::test]
    async fn evidence_for_a_platform_not_listed_throws() {
        let err = evaluate(&tdx_envelope(), request(&["snp"]))
            .await
            .unwrap_err();
        assert_eq!(err.kind, "platform_not_allowed", "{err:?}");
    }
}
