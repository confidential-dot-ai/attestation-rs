//! The verifier for browsers and other JS runtimes. Evidence normally
//! carries its own collateral, which is used first. WASM does no network or
//! disk I/O, so for anything the evidence lacks the caller fetches the vendor
//! URLs [`collateral_needed`] lists and hands the responses to [`evaluate`],
//! which verifies each piece exactly as the native verifier does.

use wasm_bindgen::prelude::*;

use attestation::{AttachedCollateral, AttestationError, Context, Policies, Verifier};

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

/// The vendor URLs to fetch to verify `envelope_json` (an `{ platform,
/// evidence }` envelope), as a JSON array of strings. Fetch each and pass the
/// responses to [`evaluate`] as `{ url, body (base64), issuer_chain }`.
///
/// Evidence that is malformed or not genuine throws a JS Error with `kind`: it
/// never names collateral to fetch. The exception is SNP evidence without a
/// VEK: its VCEK is named from the unverified report and checked once held.
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
/// - `policies_json`: the accepted platforms and their params, in the shape
///   of the attestation-api `/verify` `policies` (`{ "snp": { "report_data":
///   "<base64>" } }`); evidence for a platform without an entry throws
/// - `collateral_json`: the responses for the URLs [`collateral_needed`]
///   listed
///
/// Returns the `Verified` result as JSON with `passed`. Throws a JS Error
/// with `kind` when the evidence cannot be evaluated: malformed, not
/// genuine, platform not accepted, invalid params, needed collateral
/// missing, or collateral that is not the vendor's. Mismatches, policy
/// flags and expired collateral are values: read `passed`.
#[wasm_bindgen]
pub async fn evaluate(
    envelope_json: String,
    policies_json: String,
    collateral_json: String,
) -> Result<String, JsValue> {
    Ok(evaluate_impl(&envelope_json, &policies_json, &collateral_json, None).await?)
}

/// `now` fixes the evaluation time (Unix seconds); `None` is the clock.
async fn evaluate_impl(
    envelope_json: &str,
    policies_json: &str,
    collateral_json: &str,
    now: Option<i64>,
) -> Result<String, Failure> {
    let policies: Policies = serde_json::from_str(policies_json)
        .map_err(|e| Failure::bad_request(format!("policies deserialize: {e}")))?;
    let held: Vec<AttachedCollateral> = serde_json::from_str(collateral_json)
        .map_err(|e| Failure::bad_request(format!("collateral deserialize: {e}")))?;
    let ctx = Context::held(held.into_iter().map(|h| (h.url, h.body, h.issuer_chain)));
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
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

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

    /// `platform` accepted with its default params.
    fn request(platform: &str) -> String {
        serde_json::json!({ platform: {} }).to_string()
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

    async fn evaluate(envelope: &str, policies: &str) -> Result<serde_json::Value, Failure> {
        let collateral = fetch(envelope).await;
        evaluate_impl(envelope, policies, &collateral, Some(NOW))
            .await
            .map(|json| serde_json::from_str(&json).unwrap())
    }

    #[tokio::test]
    async fn tdx_needs_four_intel_pieces_and_passes_with_them() {
        let needed: Vec<serde_json::Value> =
            serde_json::from_str(&collateral_needed_impl(&tdx_envelope()).await.unwrap()).unwrap();
        assert_eq!(needed.len(), 4);
        let r = evaluate(&tdx_envelope(), &request("tdx")).await.unwrap();
        assert_eq!(r["passed"], true);
        assert_eq!(r["tcb_status"]["tcb_status"], "UpToDate");
        assert_eq!(r["crl_ok"], true);
    }

    #[tokio::test]
    async fn dstack_passes_with_the_tdx_pieces() {
        let mut envelope: serde_json::Value = serde_json::from_str(&tdx_envelope()).unwrap();
        envelope["platform"] = "dstack".into();
        let r = evaluate(&envelope.to_string(), &request("dstack"))
            .await
            .unwrap();
        assert_eq!(r["passed"], true);
        assert_eq!(r["platform"], "dstack");
    }

    #[tokio::test]
    async fn snp_with_an_inline_vcek_needs_only_the_crl() {
        let needed: Vec<serde_json::Value> =
            serde_json::from_str(&collateral_needed_impl(&snp_envelope()).await.unwrap()).unwrap();
        assert_eq!(needed.len(), 1);
        let r = evaluate(&snp_envelope(), &request("snp")).await.unwrap();
        assert_eq!(r["passed"], true);
        assert_eq!(r["crl_ok"], true);
    }

    #[tokio::test]
    async fn snp_runtime_registers_are_checked() {
        let report = read("snp/kmr-full-report.bin");
        let envelope = serde_json::json!({
            "platform": "snp",
            "evidence": {
                "attestation_report": BASE64.encode(&report),
                "cert_chain": { "vcek": BASE64.encode(read("snp/kmr-vcek.der")) },
                "event_log": BASE64.encode(read("snp/kmr-full-event-log.bin")),
            },
        })
        .to_string();
        let held = fetch(&envelope).await;
        let registers: Vec<String> = read("snp/kmr-full-registers.bin")
            .chunks_exact(48)
            .map(|r| BASE64.encode(r))
            .collect();
        let evaluate = |registers: &[String]| {
            let policies = serde_json::json!({ "snp": {
                "report_data": BASE64.encode(read("snp/kmr-full-caller-data.bin")),
                "launch_digest": BASE64.encode(&report[0x90..0xC0]),
                "runtime_registers": registers,
            } })
            .to_string();
            let (envelope, held) = (envelope.clone(), held.clone());
            // 2026-10-20, inside the kernel guest VCEK's window.
            async move {
                let r = evaluate_impl(&envelope, &policies, &held, Some(1_792_454_400));
                serde_json::from_str::<serde_json::Value>(&r.await.unwrap()).unwrap()
            }
        };
        let r = evaluate(&registers).await;
        assert_eq!(r["runtime_registers"]["event_count"], 4096);
        assert_eq!(r["runtime_registers_match"], true);
        assert_eq!(r["passed"], true);

        let r = evaluate(&registers[..15]).await;
        assert_eq!(r["runtime_registers_match"], false);
        assert_eq!(r["passed"], false);
    }

    #[tokio::test]
    async fn missing_or_forged_collateral_throws() {
        let err = evaluate_impl(&tdx_envelope(), &request("tdx"), "[]", Some(NOW))
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
            &request("snp"),
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
        let policies = serde_json::json!({
            "tdx": { "rtmr3": BASE64.encode([0; 48]), "report_data": BASE64.encode("another nonce") },
        });
        let r = evaluate(&tdx_envelope(), &policies.to_string())
            .await
            .unwrap();
        assert_eq!(r["passed"], false);
        assert_eq!(r["rtmr_match"][3], false);
        assert_eq!(r["report_data_match"], false);
    }

    #[tokio::test]
    async fn bad_requests_throw_before_verification() {
        let short_pin = serde_json::json!({ "tdx": { "rtmr3": BASE64.encode([0; 47]) } });
        let bad_tcb = serde_json::json!({ "snp": { "min_tcb": { "tee": 1 } } });
        let empty_set = serde_json::json!({ "tdx": { "accepted_tcb_statuses": [] } });
        for policies in [
            "{".to_string(),
            request("nope"),
            short_pin.to_string(),
            bad_tcb.to_string(),
            empty_set.to_string(),
        ] {
            let err = evaluate_impl(&tdx_envelope(), &policies, "[]", Some(NOW))
                .await
                .unwrap_err();
            assert_eq!(err.kind, "bad_request", "{err:?}");
        }
    }

    #[tokio::test]
    async fn the_answer_is_the_librarys() {
        for (envelope, platform) in [(tdx_envelope(), "tdx"), (snp_envelope(), "snp")] {
            let collateral = fetch(&envelope).await;
            let wasm = evaluate_impl(&envelope, &request(platform), &collateral, Some(NOW))
                .await
                .unwrap();
            let held: Vec<AttachedCollateral> = serde_json::from_str(&collateral).unwrap();
            let ctx = Context::held(held.into_iter().map(|h| (h.url, h.body, h.issuer_chain)))
                .at(NOW)
                .unwrap();
            let policies = serde_json::from_str(&request(platform)).unwrap();
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
        let err = evaluate(&tdx_envelope(), &request("snp"))
            .await
            .unwrap_err();
        assert_eq!(err.kind, "platform_not_allowed", "{err:?}");
    }
}
