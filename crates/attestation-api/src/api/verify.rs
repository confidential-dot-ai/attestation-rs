use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::Json;
use std::sync::Arc;

use attestation::{Attempt, Fetched};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{normalize_platform, AttestationConfig};
use crate::error::ApiError;
use crate::pool::Refused;
use crate::token::issuer::{PassedVerification, TokenIssuer};
use crate::AppState;

/// Rounds of vendor requests one verification may need: each round asks
/// what the previous attempt found missing. The most any platform needs
/// today is three, for cold TDX or SNP evidence with a GPU bundle: the
/// platform collateral (fetched together, e.g. VCEK and CRL), then NRAS,
/// then NRAS's key set. A step that needs a fourth round would get a
/// retryable 502 on its first, cold call; the test
/// `a_cold_tdx_verification_with_a_gpu_bundle_ends_within_the_fetch_rounds`
/// pins the count.
const MAX_FETCHES: usize = 3;

/// Collateral unavailable for this request, retryable at once.
fn unavailable(detail: &str) -> ApiError {
    ApiError::Verification(attestation::AttestationError::CollateralUnavailable {
        collateral: "collateral".to_string(),
        retry_after: Some(1),
        detail: detail.to_string(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    /// Platform for the platform-specific evidence returned by /attest.
    pub platform: Option<String>,
    pub evidence: Value,
    /// NVIDIA GPU evidence bundle, as returned by /attest with `nvidia_gpu: true`.
    /// When present, `policies.nvidia_gpu` must be set.
    #[serde(default)]
    pub nvidia_gpu: Option<Value>,
    /// The collateral /attest attached, `[{url, body, issuer_chain}]`.
    pub collateral: Option<Value>,
    /// Accepted platforms and their params. Evidence for a platform without an
    /// entry is refused. Issued tokens carry it as their `policy` claim.
    #[serde(default, deserialize_with = "api_policies")]
    pub policies: attestation::Policies,
    #[serde(default)]
    pub issue_token: bool,
}

// Filter keys while streaming, so library serde still rejects duplicate keys.
// Feature unification must not expand the service's accepted policy surface.
fn api_policies<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<attestation::Policies, D::Error> {
    struct ApiPolicies;
    impl<'de> serde::de::Visitor<'de> for ApiPolicies {
        type Value = attestation::Policies;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("supported API policies")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            struct Supported<M>(M);
            impl<'de, M: serde::de::MapAccess<'de>> serde::de::MapAccess<'de> for Supported<M> {
                type Error = M::Error;
                fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
                    &mut self,
                    seed: K,
                ) -> Result<Option<K::Value>, Self::Error> {
                    use serde::de::IntoDeserializer;
                    let Some(key) = self.0.next_key::<String>()? else {
                        return Ok(None);
                    };
                    if !crate::config::SUPPORTED_ATTESTATION_PLATFORMS.contains(&key.as_str())
                        && !matches!(key.as_str(), "floors" | "nvidia_gpu")
                    {
                        return Err(serde::de::Error::custom(format!(
                            "unsupported policy: {key}"
                        )));
                    }
                    seed.deserialize(key.into_deserializer()).map(Some)
                }
                fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(
                    &mut self,
                    seed: V,
                ) -> Result<V::Value, Self::Error> {
                    self.0.next_value_seed(seed)
                }
            }
            attestation::Policies::deserialize(serde::de::value::MapAccessDeserializer::new(
                Supported(map),
            ))
        }
    }
    deserializer.deserialize_map(ApiPolicies)
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: attestation::Verified,
    /// True when the evidence satisfied every rule in the policies.
    pub passed: bool,
    /// Issued only when requested and `passed` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    payload: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let Json(req) = payload?;
    let platform = canonical_platform(req.platform.as_deref())?;
    check_server_floors(&req.policies, &state.config.attestation)?;
    if req.issue_token
        && req
            .policies
            .report_data(platform)
            .is_none_or(<[u8]>::is_empty)
    {
        return Err(ApiError::BadRequest(format!(
            "issue_token requires a non-empty policies.{platform}.report_data"
        )));
    }
    let evidence_json = build_evidence_envelope(
        &platform.to_string(),
        req.evidence,
        req.nvidia_gpu,
        req.collateral,
    )?;

    // Verification is CPU-bound: the pool runs it, with the token signing,
    // off the async workers, and refuses at once what it cannot start soon.
    // The pool never waits on a vendor: what a verification must ask a
    // vendor first (collateral, NRAS) is asked here, on the async workers,
    // within `fetch_deadline_ms` for the request, and the verification is
    // queued again with the answers. Each vendor request is made once per
    // request, so the rounds end; MAX_FETCHES bounds them anyway.
    let evidence: Arc<[u8]> = evidence_json.into();
    let policies = Arc::new(req.policies);
    let issuer = req.issue_token.then(|| state.token_issuer.clone());
    let fetch_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(state.config.server.fetch_deadline_ms);
    let mut fetched = Fetched::default();
    let mut fetches = 0;
    let (result, token) = loop {
        let job = {
            let (verifier, evidence, policies, issuer, fetched) = (
                state.verifier.clone(),
                evidence.clone(),
                policies.clone(),
                issuer.clone(),
                fetched.clone(),
            );
            async move {
                match verifier.verify_cached(&evidence, &policies, &fetched).await {
                    Attempt::Done(result) => with_token(result?, issuer, &policies).map(Ok),
                    Attempt::Fetch(fetch) => Ok(Err(fetch)),
                }
            }
        };
        // A verification back from a fetch was admitted already; it is
        // refused only when the queue is far past the admission limit.
        let attempt = if fetches == 0 {
            state.verify_pool.run(job).await
        } else {
            state.verify_pool.rerun(job).await
        }
        .map_err(|refused| match refused {
            Refused::Full | Refused::Expired => ApiError::Overloaded,
            Refused::Panicked => ApiError::Internal("verification panicked".to_string()),
        })??;
        let fetch = match attempt {
            Ok(done) => break done,
            Err(fetch) => fetch,
        };
        if fetches == MAX_FETCHES {
            return Err(unavailable(
                "more vendor requests than one verification makes",
            ));
        }
        tokio::time::timeout_at(fetch_deadline, fetch.run(&mut fetched))
            .await
            .map_err(|_| unavailable("the vendors did not answer in time"))?;
        fetches += 1;
    };
    let passed = result.passed();

    Ok(Json(VerifyResponse {
        result,
        passed,
        token,
    }))
}

/// `result` and, when asked for (`issuer` is `Some`) and it passed, a token.
fn with_token(
    result: attestation::Verified,
    issuer: Option<Option<Arc<TokenIssuer>>>,
    policies: &attestation::Policies,
) -> Result<(attestation::Verified, Option<String>), ApiError> {
    let token = match (PassedVerification::new(&result), issuer) {
        (Some(passed), Some(issuer)) => Some(
            issuer
                .ok_or(ApiError::TokenNotConfigured)?
                .issue(&passed, policies)?,
        ),
        _ => None,
    };
    Ok((result, token))
}

/// Params below the server's floors are refused unless its config allows
/// them: `allow_debug`, a TCB status outside the default set, and `max_vmpl`
/// above 0. Collateral floors below the shipped ones and a GPU device policy
/// weaker than the default are always refused.
fn check_server_floors(
    policies: &attestation::Policies,
    config: &AttestationConfig,
) -> Result<(), ApiError> {
    let refuse = |what: &str| {
        Err(ApiError::BadRequest(format!(
            "{what} is disabled by server configuration"
        )))
    };
    let gpu = policies.gpu.as_ref().map(|p| &p.device_policy);
    let debug = policies.tdx_params().any(|p| p.allow_debug)
        || policies.snp_params().any(|p| p.allow_debug)
        || gpu.is_some_and(|p| p.allow_debug);
    if debug && !config.allow_debug {
        return refuse("allow_debug");
    }
    if !config.allow_revoked_or_unlisted_tcb {
        let valid = attestation::TdxParams::default().accepted_tcb_statuses;
        let mut statuses = policies.tdx_params().flat_map(|p| &p.accepted_tcb_statuses);
        if let Some(status) = statuses.find(|s| !valid.contains(s)) {
            return refuse(&format!("accepting TCB status {status}"));
        }
    }
    if !config.allow_nonzero_vmpl && policies.snp_params().any(|p| p.max_vmpl > 0) {
        return refuse("max_vmpl above 0");
    }
    if policies
        .floors
        .lowers(&attestation::collateral::VersionFloors::default())
    {
        return Err(ApiError::BadRequest(
            "floors may raise, not lower, the collateral versions accepted".to_string(),
        ));
    }
    if gpu.is_some_and(|p| !p.require_secboot || !p.require_measres_success) {
        return Err(ApiError::BadRequest(
            "nvidia_gpu.device_policy must require secboot and measres success".to_string(),
        ));
    }
    Ok(())
}

fn canonical_platform(platform: Option<&str>) -> Result<attestation::PlatformType, ApiError> {
    let platform = platform.ok_or_else(|| {
        ApiError::BadRequest("platform is required for evidence verification".to_string())
    })?;
    normalize_platform(platform)
        .and_then(|p| serde_json::from_value(p.into()).ok())
        .ok_or_else(|| ApiError::BadRequest(format!("unknown platform: {platform}")))
}

fn build_evidence_envelope(
    platform: &str,
    evidence: Value,
    nvidia_gpu: Option<Value>,
    collateral: Option<Value>,
) -> Result<Vec<u8>, ApiError> {
    if is_attestation_envelope(&evidence) {
        return Err(ApiError::BadRequest(
            "evidence must be platform-specific evidence; put platform at the top level"
                .to_string(),
        ));
    }

    let mut envelope = serde_json::json!({
        "platform": platform,
        "evidence": evidence,
    });
    if let Some(gpu) = nvidia_gpu {
        envelope["nvidia_gpu"] = gpu;
    }
    if let Some(collateral) = collateral {
        envelope["collateral"] = collateral;
    }

    serde_json::to_vec(&envelope)
        .map_err(|e| ApiError::BadRequest(format!("invalid evidence JSON: {e}")))
}

fn is_attestation_envelope(evidence: &Value) -> bool {
    evidence.get("platform").is_some() && evidence.get("evidence").is_some()
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::{build_evidence_envelope, canonical_platform};
    use crate::error::ApiError;

    #[test]
    fn build_evidence_envelope_wraps_split_form_with_canonical_platform() {
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope(
                &canonical_platform(Some("SNP")).unwrap().to_string(),
                json!({ "report": "abc" }),
                None,
                None,
            )
            .unwrap(),
        )
        .expect("normalized evidence should be JSON");

        assert_eq!(normalized["platform"], "snp");
        assert_eq!(normalized["evidence"]["report"], "abc");
        assert!(normalized.get("nvidia_gpu").is_none());
    }

    #[test]
    fn build_evidence_envelope_includes_gpu_bundle_when_present() {
        let gpu = json!({ "devices": [], "binding": { "kind": "concat" } });
        let normalized: Value = serde_json::from_slice(
            &build_evidence_envelope("tdx", json!({ "quote": "abc" }), Some(gpu.clone()), None)
                .unwrap(),
        )
        .expect("normalized evidence should be JSON");

        assert_eq!(normalized["platform"], "tdx");
        assert_eq!(normalized["nvidia_gpu"], gpu);
    }

    #[test]
    fn build_evidence_envelope_rejects_full_envelope_evidence() {
        let err = build_evidence_envelope(
            "snp",
            json!({
                "platform": "snp",
                "evidence": { "report": "abc" }
            }),
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn policy_boundary_preserves_duplicate_key_rejection() {
        let valid = r#"{"evidence":{},"policies":{"tdx":{}}}"#;
        assert!(serde_json::from_str::<super::VerifyRequest>(valid).is_ok());
        for policies in [
            r#"{"tdx":{},"tdx":{}}"#,
            r#"{"dstack":null}"#,
            r#"{"future":{}}"#,
        ] {
            let request = format!(r#"{{"evidence":{{}},"policies":{policies}}}"#);
            assert!(serde_json::from_str::<super::VerifyRequest>(&request).is_err());
        }
    }

    #[test]
    fn platform_is_required_and_must_be_known() {
        assert!(matches!(
            canonical_platform(None),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            canonical_platform(Some("not-a-platform")),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn is_attestation_envelope_detects_nested_envelope_shape() {
        assert!(super::is_attestation_envelope(&json!({
            "platform": "snp",
            "evidence": { "report": "abc" }
        })));
    }
}
