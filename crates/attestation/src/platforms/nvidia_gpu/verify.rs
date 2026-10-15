//! Verify a [`NvidiaGpuEvidenceBundle`] using NRAS.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::collateral::{Doc, NrasJwks, Store};
use crate::error::{AttestationError, Result};
use crate::platforms::nvidia_gpu::provider::{Jwks, NrasEvidenceEntry, NrasRequest};
use crate::platforms::nvidia_gpu::{gpu_nonce, switch_nonce};
use crate::types::{
    NvidiaGpuArch, NvidiaGpuClaims, NvidiaGpuDeviceClaims, NvidiaGpuEvidenceBundle,
    NvidiaGpuParams, NvidiaGpuResult,
};

/// What GPU verification needs besides the bundle: NRAS's attestation for
/// each architecture group, and its signing keys.
pub struct GpuCollateral {
    pub nras: std::collections::BTreeMap<NvidiaGpuArch, serde_json::Value>,
    pub jwks: Doc<NrasJwks>,
}

/// Send each architecture group of the bundle to NRAS and get its signing
/// keys, refetching them once if a token names a key they lack.
pub async fn gather_bundle(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &NvidiaGpuParams,
    store: &Store,
    now: i64,
) -> Result<GpuCollateral> {
    let user_nonce = check_preconditions(bundle, params)?;
    let mut nras = std::collections::BTreeMap::new();
    for (arch, devices) in group_by_arch(bundle) {
        let request = NrasRequest {
            nonce: hex::encode(arch_nonce(arch, user_nonce, bundle)),
            evidence_list: devices
                .iter()
                .map(|d| NrasEvidenceEntry {
                    evidence: d.evidence_b64.clone(),
                    certificate: d.cert_chain_b64.clone(),
                })
                .collect(),
            arch,
            claims_version: "2.0".into(),
        };
        nras.insert(arch, nras_attest(store, &request).await?);
    }
    let mut jwks = store.get(NrasJwks {}, now).await?;
    let known = |jwks: &Doc<NrasJwks>| {
        nras.values().all(|response| {
            split_eat_response(response).is_ok_and(|(overall, subs)| {
                std::iter::once(&overall)
                    .chain(subs.iter().map(|(_, t)| t))
                    .all(|t| {
                        jwt_kid(t).is_none_or(|kid| jwks.value.keys.iter().any(|k| k.kid == kid))
                    })
            })
        })
    };
    if !known(&jwks) {
        store.refresh(&NrasJwks {}.into(), now).await?;
        jwks = store.get(NrasJwks {}, now).await?;
    }
    Ok(GpuCollateral { nras, jwks })
}

#[cfg(not(target_arch = "wasm32"))]
async fn nras_attest(store: &Store, request: &NrasRequest) -> Result<serde_json::Value> {
    match store.vendor() {
        Some(vendor) => vendor.nras_attest(request).await,
        None => Err(AttestationError::CollateralUnavailable {
            document: "NRAS attestation".into(),
            reason: crate::error::Unavailable::Offline,
        }),
    }
}

#[cfg(target_arch = "wasm32")]
async fn nras_attest(_store: &Store, _request: &NrasRequest) -> Result<serde_json::Value> {
    Err(AttestationError::CollateralUnavailable {
        document: "NRAS attestation".into(),
        reason: crate::error::Unavailable::Offline,
    })
}

/// The `kid` a compact JWS names, if it can be read.
fn jwt_kid(token: &str) -> Option<String> {
    let header = URL_SAFE_NO_PAD.decode(token.split('.').next()?).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    header.get("kid")?.as_str().map(String::from)
}

fn arch_nonce(
    arch: NvidiaGpuArch,
    user_nonce: &[u8],
    bundle: &NvidiaGpuEvidenceBundle,
) -> [u8; 32] {
    match arch {
        NvidiaGpuArch::Ls10 => switch_nonce(user_nonce, &bundle.binding),
        _ => gpu_nonce(user_nonce, &bundle.binding),
    }
}

/// Verify a GPU bundle against NRAS's answers:
/// - JWS-verify each overall and submodule token, check every `eat_nonce`
///   against the SPDM nonce derived from `params.user_nonce`.
/// - Evaluate the params' rules (arch allowlist, device policy, device count)
///   and NRAS's `x-nvidia-overall-att-result` into the result.
///
/// `now` is the evaluation time (Unix seconds) for token and certificate
/// validity. Caller is responsible for asserting the CPU ↔ GPU coupling (the
/// same `user_nonce` was used as the CPU report data).
pub fn verify_bundle(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &NvidiaGpuParams,
    collateral: &GpuCollateral,
    now: i64,
) -> Result<NvidiaGpuResult> {
    let user_nonce = check_preconditions(bundle, params)?;

    let mut claims = NvidiaGpuClaims {
        overall_ok: true,
        eat_nonce: None,
        devices: Vec::with_capacity(bundle.devices.len()),
        overall_raw: serde_json::Value::Null,
    };
    let mut device_policy_met = true;

    for (arch, _) in group_by_arch(bundle) {
        let response = collateral.nras.get(&arch).ok_or_else(|| {
            AttestationError::NrasResponseParse(format!("no NRAS answer for {arch:?}"))
        })?;
        let group = verify_arch_group(
            arch,
            response,
            &arch_nonce(arch, user_nonce, bundle),
            params,
            &collateral.jwks.value,
            now,
        )?;
        device_policy_met &= group.device_policy_met;
        fold_arch_group(&mut claims, group);
    }

    if !claims.overall_ok {
        log::warn!("NVIDIA GPU attestation: NRAS overall result is false");
    }
    let device_count_match = claims.devices.len() == bundle.devices.len();
    if !device_count_match {
        log::warn!(
            "NVIDIA GPU attestation: device count mismatch (expected {}, got {})",
            bundle.devices.len(),
            claims.devices.len()
        );
    }
    let archs_allowed = params
        .expected_archs
        .as_ref()
        .map(|allowed| bundle.devices.iter().all(|d| allowed.contains(&d.arch)));

    Ok(NvidiaGpuResult {
        claims,
        archs_allowed,
        device_count_match,
        device_policy_met,
    })
}

const MAX_GPU_DEVICES: usize = 32;

/// Validate bundle and params before any network or crypto work. Returns the
/// validated `user_nonce` slice on success.
pub(crate) fn check_preconditions<'a>(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &'a NvidiaGpuParams,
) -> Result<&'a [u8]> {
    if bundle.devices.is_empty() {
        return Err(AttestationError::NvidiaGpuBundleEmpty);
    }
    if bundle.devices.len() > MAX_GPU_DEVICES {
        return Err(AttestationError::NvidiaGpuTooManyDevices(
            bundle.devices.len(),
            MAX_GPU_DEVICES,
        ));
    }
    let user_nonce = params
        .user_nonce
        .as_deref()
        .ok_or(AttestationError::NvidiaGpuUserNonceMissing)?;
    super::check_user_nonce_len(user_nonce)?;

    // Enforce allowed binding algorithms. Default: only Concat { Sha256 }.
    let default_allowed = [crate::types::NvidiaGpuBinding::default()];
    let allowed = params
        .allowed_bindings
        .as_deref()
        .unwrap_or(&default_allowed);
    if !allowed.contains(&bundle.binding) {
        return Err(AttestationError::NvidiaGpuBindingNotAllowed);
    }

    Ok(user_nonce)
}

/// NRAS requires one request per arch. Group the bundle accordingly.
fn group_by_arch(
    bundle: &NvidiaGpuEvidenceBundle,
) -> std::collections::BTreeMap<NvidiaGpuArch, Vec<&crate::types::NvidiaGpuDeviceEvidence>> {
    let mut by_arch: std::collections::BTreeMap<
        NvidiaGpuArch,
        Vec<&crate::types::NvidiaGpuDeviceEvidence>,
    > = Default::default();
    for dev in &bundle.devices {
        by_arch.entry(dev.arch).or_default().push(dev);
    }
    by_arch
}

/// Result of attesting + verifying one arch group. The caller folds these
/// into the running [`NvidiaGpuClaims`] aggregate.
struct ArchGroupResult {
    overall_ok: bool,
    eat_nonce: Option<String>,
    overall_raw: serde_json::Value,
    devices: Vec<crate::types::NvidiaGpuDeviceClaims>,
    device_policy_met: bool,
}

/// JWS-verify NRAS's overall and per-submodule tokens for one architecture
/// group, and check the eat_nonce binding against the derived SPDM nonce.
fn verify_arch_group(
    arch: NvidiaGpuArch,
    response: &serde_json::Value,
    nonce_bytes: &[u8; 32],
    params: &NvidiaGpuParams,
    jwks: &Jwks,
    now: i64,
) -> Result<ArchGroupResult> {
    let (overall_jwt, submodule_jwts) = split_eat_response(response)?;
    let overall_claims = verify_jws_es384(&overall_jwt, jwks, now)?;
    let overall_ok = overall_claims
        .get("x-nvidia-overall-att-result")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // DEVIATION (RFC 9711): the spec encodes the JSON `eat_nonce` as a base64url
    // string (and permits an array of strings). NRAS instead returns a single
    // hex string, so we hex-decode below. An array form is not produced by NRAS;
    // if one appears, `as_str()` yields None and the binding check fails closed.
    let eat_nonce = overall_claims
        .get("eat_nonce")
        .and_then(|v| v.as_str())
        .map(String::from);
    let nonce_binding_ok = eat_nonce
        .as_deref()
        .and_then(|n| hex::decode(n).ok())
        .is_some_and(|decoded| {
            use subtle::ConstantTimeEq;
            decoded.ct_eq(nonce_bytes).into()
        });
    if !nonce_binding_ok {
        log::warn!("NVIDIA GPU attestation: nonce binding mismatch");
        return Err(AttestationError::NvidiaGpuBindingMismatch);
    }

    let mut device_claims = Vec::with_capacity(submodule_jwts.len());
    let mut device_policy_met = true;
    for (name, sub_jwt) in submodule_jwts {
        let sub_claims = verify_jws_es384(&sub_jwt, jwks, now)?;
        // Bind this submodule to the session: its `eat_nonce` must equal the
        // SPDM nonce we derived. The overall token's `eat_nonce` alone does not
        // cover the submodule JWTs (NRAS's RFC 9711 `submods` DIGEST is computed
        // over an intermediate that excludes the issued JWT's time claims, so it
        // is not byte-verifiable against the returned compact JWS — see the
        // module docs). Per-submodule `eat_nonce` is the cheaper, robust subset:
        // a submodule spliced from another session carries a different nonce and
        // is rejected here.
        check_submodule_nonce(&name, &sub_claims, nonce_bytes)?;
        let mut dc = device_claims_from_submodule(&sub_claims);
        check_device_report_nonce(&name, &dc)?;
        if dc.arch.is_none() {
            dc.arch = Some(arch);
        }
        device_policy_met &= device_policy_holds(&name, &dc, &params.device_policy);
        device_claims.push(dc);
    }

    Ok(ArchGroupResult {
        overall_ok,
        eat_nonce,
        overall_raw: overall_claims,
        devices: device_claims,
        device_policy_met,
    })
}

/// Merge a per-arch result into the running aggregate. `overall_raw` overwrites
/// each iteration — fine for v1, where multiple arches in one bundle is rare.
fn fold_arch_group(aggregated: &mut NvidiaGpuClaims, group: ArchGroupResult) {
    aggregated.overall_ok &= group.overall_ok;
    if aggregated.eat_nonce.is_none() {
        aggregated.eat_nonce = group.eat_nonce;
    }
    aggregated.overall_raw = group.overall_raw;
    aggregated.devices.extend(group.devices);
}

/// NRAS returns a 2-tuple "detached EAT" of the shape
/// `[ ["JWT", "<overall>"], { "<name>": "<jwt>", ... } ]`, where the object
/// carries one signed submodule JWT per attested device.
///
/// A bare JWT string is *not* a usable attestation here: it carries no
/// per-device submodules, so it would always fail the downstream device-count
/// check. We reject it at the parse site with a clear error rather than letting
/// it surface as a misleading `DeviceCountMismatch`. Likewise, a submodule
/// whose value is not a string is a malformed entry and is reported as a parse
/// error instead of being silently dropped (which would also masquerade as a
/// count mismatch).
fn split_eat_response(v: &serde_json::Value) -> Result<(String, Vec<(String, String)>)> {
    if v.is_string() {
        return Err(AttestationError::NrasResponseParse(
            "NRAS returned a bare JWT string with no per-device submodules; \
             expected a detached EAT 2-tuple"
                .into(),
        ));
    }
    if let Some(arr) = v.as_array() {
        if arr.len() == 2 {
            let inner = arr[0].as_array().ok_or_else(|| {
                AttestationError::NrasResponseParse("EAT[0] is not an array".into())
            })?;
            if inner.first().and_then(|v| v.as_str()) != Some("JWT") {
                return Err(AttestationError::NrasResponseParse(
                    "EAT[0][0] is not \"JWT\"".into(),
                ));
            }
            let overall = inner
                .get(1)
                .and_then(|j| j.as_str())
                .ok_or_else(|| {
                    AttestationError::NrasResponseParse("missing overall JWT in EAT".into())
                })?
                .to_string();
            let map = arr[1].as_object().ok_or_else(|| {
                AttestationError::NrasResponseParse("EAT[1] is not a submodule object".into())
            })?;
            let mut subs = Vec::with_capacity(map.len());
            for (k, val) in map {
                let s = val.as_str().ok_or_else(|| {
                    AttestationError::NrasResponseParse(format!(
                        "EAT submodule \"{k}\" value is not a JWT string"
                    ))
                })?;
                subs.push((k.clone(), s.to_string()));
            }
            return Ok((overall, subs));
        }
    }
    let preview = {
        let s = v.to_string();
        if s.len() > 512 {
            let mut end = 512;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &s[..end])
        } else {
            s
        }
    };
    Err(AttestationError::NrasResponseParse(format!(
        "unexpected NRAS response shape: {preview}"
    )))
}

/// Verify an ES384-signed compact JWS against a JWKS at `now` (Unix seconds),
/// returning the decoded claims body.
pub fn verify_jws_es384(token: &str, jwks: &Jwks, now: i64) -> Result<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AttestationError::JwsVerification(
            "not a compact JWS".into(),
        ));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| AttestationError::JwsVerification(format!("header b64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| AttestationError::JwsVerification(format!("header json: {e}")))?;
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != "ES384" {
        return Err(AttestationError::JwsVerification(format!(
            "unsupported alg {alg}"
        )));
    }
    // RFC 7515 §4.1.11: any extension marked critical that we don't understand
    // makes the JWS invalid. We support no extensions, so reject any `crit`.
    if header.get("crit").is_some() {
        return Err(AttestationError::JwsVerification(
            "unsupported crit header parameter".into(),
        ));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::JwsVerification("missing kid".into()))?;
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| AttestationError::JwksKidNotFound(kid.to_string()))?;

    let verifying_key = es384_verifying_key_from_jwks_entry(key, now)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| AttestationError::JwsVerification(format!("sig b64: {e}")))?;
    let signature = p384::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| AttestationError::JwsVerification(format!("ES384 sig parse: {e}")))?;
    {
        use p384::ecdsa::signature::Verifier as _;
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|e| AttestationError::JwsVerification(format!("ES384 verify: {e}")))?;
    }

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AttestationError::JwsVerification(format!("payload b64: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| AttestationError::JwsVerification(format!("payload json: {e}")))?;

    enforce_time_claims(&claims, now)?;

    Ok(claims)
}

/// Enforce the RFC 7519 time-based claims on a JWT body.
///
/// `exp` is REQUIRED and must be numeric: a missing or non-numeric `exp` would
/// otherwise fail open, accepting a token with no expiry that is replayable
/// indefinitely (and, combined with submodule binding, a foreign submodule that
/// never ages out). `nbf` is optional but enforced when present.
///
/// RFC 7519 permits fractional NumericDate values, which `as_i64` rejects, so we
/// parse via `as_f64`. We `floor` `exp` and `ceil` `nbf` so a fractional second
/// never widens the validity window past the whole-second boundary.
///
/// `now` is the evaluation time in Unix seconds.
fn enforce_time_claims(claims: &serde_json::Value, now: i64) -> Result<()> {
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| {
            AttestationError::JwsVerification("JWT missing or non-numeric exp".into())
        })?;
    if now > exp.floor() as i64 {
        return Err(AttestationError::JwsVerification(
            "JWT has expired (exp)".into(),
        ));
    }

    if let Some(nbf) = claims.get("nbf") {
        let nbf = nbf.as_f64().ok_or_else(|| {
            AttestationError::JwsVerification("JWT nbf is present but non-numeric".into())
        })?;
        if now < nbf.ceil() as i64 {
            return Err(AttestationError::JwsVerification(
                "JWT is not yet valid (nbf)".into(),
            ));
        }
    }

    Ok(())
}

fn es384_verifying_key_from_jwks_entry(
    key: &crate::platforms::nvidia_gpu::provider::JwksKey,
    now: i64,
) -> Result<p384::ecdsa::VerifyingKey> {
    // The signing key MUST come from an x5c chain that validates up to the
    // pinned NVIDIA trust anchor. The raw JWK `(x, y)` coordinates carry no
    // chain and no pin, so accepting them would degrade trust to WebPKI TLS for
    // the JWKS host (which is itself overridable via `NV_NRAS_GPU_URL`): a MITM
    // serving a JWKS of attacker-chosen coordinates could forge every EAT. We
    // therefore require x5c and never fall back to bare coordinates.
    match &key.x5c {
        Some(chain) if !chain.is_empty() => verify_x5c_chain_and_extract_key(chain, now),
        _ => Err(AttestationError::JwsVerification(
            "JWKS entry has no x5c chain; raw (x,y) coordinates are not accepted \
             because they bypass the pinned NVIDIA trust anchor"
                .into(),
        )),
    }
}

/// SHA-256 hashes of trusted NRAS intermediate CA Subject Public Key Info (SPKI).
/// The topmost certificate in the x5c chain must have an SPKI matching one of these.
///
/// GPU/Switch Intermediate 004 — valid 2025-12-08 to 2029-12-08
/// Subject: CN=NVIDIA Attestation Service GPU Intermediate 004
/// Issuer:  CN=NVIDIA Attestation Service CA 001
const NRAS_TRUSTED_SPKI_SHA256: &[&str] =
    &["fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896"];

/// Validate the x5c certificate chain and return the leaf's P-384 verifying key.
///
/// Checks, for a leaf-first chain:
/// - every cert is within its validity period;
/// - cert[i] is signed by cert[i+1] (EC or RSA);
/// - each issuer (cert[i+1]) is a CA permitted to sign cert[i]: basicConstraints
///   cA=TRUE, pathLenConstraint satisfied, keyUsage (when present) includes
///   keyCertSign, and its subject matches cert[i]'s issuer (RFC 5280 §6.1 name
///   chaining);
/// - the topmost cert's SPKI matches a pinned NVIDIA trust anchor.
///
/// This is the load-bearing trust check: there is no raw-coordinate fallback
/// (see `es384_verifying_key_from_jwks_entry`), so every accepted signing key
/// chains to the pinned anchor through these constraints.
fn verify_x5c_chain_and_extract_key(
    chain: &[String],
    now: i64,
) -> Result<p384::ecdsa::VerifyingKey> {
    use sha2::Digest;
    use spki::DecodePublicKey;
    use x509_cert::der::Decode;

    if chain.is_empty() {
        return Err(AttestationError::JwsVerification(
            "x5c chain is empty".into(),
        ));
    }

    let certs: Vec<(Vec<u8>, x509_cert::Certificate)> = chain
        .iter()
        .enumerate()
        .map(|(i, b64)| {
            let der = STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| AttestationError::JwsVerification(format!("x5c[{i}] b64: {e}")))?;
            let cert = x509_cert::Certificate::from_der(&der).map_err(|e| {
                AttestationError::JwsVerification(format!("x5c[{i}] cert parse: {e}"))
            })?;
            Ok((der, cert))
        })
        .collect::<Result<Vec<_>>>()?;

    // Enforce certificate validity periods at the evaluation time.
    {
        let now_secs = now;
        for (i, (_der, cert)) in certs.iter().enumerate() {
            let validity = &cert.tbs_certificate.validity;
            let nb_unix: i64 = validity
                .not_before
                .to_date_time()
                .unix_duration()
                .as_secs()
                .try_into()
                .map_err(|_| {
                    AttestationError::JwsVerification(format!("x5c[{i}] not_before overflow"))
                })?;
            if now_secs < nb_unix {
                return Err(AttestationError::JwsVerification(format!(
                    "x5c[{i}] certificate not yet valid"
                )));
            }
            let na_unix: i64 = validity
                .not_after
                .to_date_time()
                .unix_duration()
                .as_secs()
                .try_into()
                .map_err(|_| {
                    AttestationError::JwsVerification(format!("x5c[{i}] not_after overflow"))
                })?;
            if now_secs > na_unix {
                return Err(AttestationError::JwsVerification(format!(
                    "x5c[{i}] certificate has expired"
                )));
            }
        }
    }

    // Verify chain signatures and RFC 5280 path constraints: cert[i] must be
    // signed by cert[i+1], and cert[i+1] must be a CA permitted to issue it.
    // The chain is leaf-first, so cert[i+1] is the issuer of cert[i].
    for i in 0..certs.len().saturating_sub(1) {
        verify_cert_signature(&certs[i].1, &certs[i + 1].1, i)?;
        // `i` intermediate certs sit between this issuer and the leaf (cert[0]),
        // i.e. the issuer is at path depth `i`. RFC 5280 pathLenConstraint on
        // the issuer must allow at least that many subordinate CA certs.
        check_issuer_is_ca(&certs[i + 1].1, &certs[i].1, i + 1, i)?;
    }

    // Pin the topmost cert against trusted SPKI hashes instead of requiring
    // self-signature (the NRAS intermediate is signed by an offline root CA
    // that is not included in the x5c chain).
    let top = &certs[certs.len() - 1].1;
    let top_spki_der = spki::der::Encode::to_der(&top.tbs_certificate.subject_public_key_info)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c top spki encode: {e}")))?;
    let top_spki_hash = hex::encode(sha2::Sha256::digest(&top_spki_der));
    if !NRAS_TRUSTED_SPKI_SHA256.contains(&top_spki_hash.as_str()) {
        return Err(AttestationError::JwsVerification(format!(
            "x5c chain root SPKI not in trusted set (got {top_spki_hash})"
        )));
    }

    // Extract leaf public key.
    let leaf_spki = &certs[0].1.tbs_certificate.subject_public_key_info;
    let leaf_spki_der = spki::der::Encode::to_der(leaf_spki)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c leaf spki encode: {e}")))?;
    p384::ecdsa::VerifyingKey::from_public_key_der(&leaf_spki_der)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c leaf ES384 key: {e}")))
}

/// Enforce the RFC 5280 §4.2.1 constraints that make `issuer` eligible to sign
/// `subject` as a CA: basicConstraints cA=TRUE (and present), pathLenConstraint
/// satisfied for the number of intermediates below it, keyUsage keyCertSign when
/// the extension is present, and issuer-subject name chaining.
///
/// `issuer_index` / `subject_index` are positions in the leaf-first chain, used
/// for error messages. `intermediates_below` is the count of CA certs between
/// `issuer` and the leaf (RFC 5280's path length for `issuer`).
fn check_issuer_is_ca(
    issuer: &x509_cert::Certificate,
    subject: &x509_cert::Certificate,
    issuer_index: usize,
    intermediates_below: usize,
) -> Result<()> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

    // basicConstraints must be present with cA=TRUE for any cert that issues
    // another. Absent basicConstraints means "not a CA" (RFC 5280 §4.2.1.9).
    let bc = issuer
        .tbs_certificate
        .get::<BasicConstraints>()
        .map_err(|e| {
            AttestationError::JwsVerification(format!(
                "x5c[{issuer_index}] basicConstraints decode: {e}"
            ))
        })?;
    let Some((_critical, bc)) = bc else {
        return Err(AttestationError::JwsVerification(format!(
            "x5c[{issuer_index}] is not a CA (no basicConstraints) but signs x5c[{subject_index}]",
            subject_index = issuer_index - 1
        )));
    };
    if !bc.ca {
        return Err(AttestationError::JwsVerification(format!(
            "x5c[{issuer_index}] basicConstraints cA=FALSE but it signs another certificate"
        )));
    }
    // pathLenConstraint, when present, bounds the number of non-self-issued
    // intermediate CA certs that may follow this one in a valid path.
    if let Some(max_path_len) = bc.path_len_constraint {
        if intermediates_below as u32 > u32::from(max_path_len) {
            return Err(AttestationError::JwsVerification(format!(
                "x5c[{issuer_index}] pathLenConstraint {max_path_len} exceeded \
                 ({intermediates_below} intermediate CA(s) below it)"
            )));
        }
    }

    // keyUsage, when present, must assert keyCertSign for a cert-signing CA.
    let ku = issuer.tbs_certificate.get::<KeyUsage>().map_err(|e| {
        AttestationError::JwsVerification(format!("x5c[{issuer_index}] keyUsage decode: {e}"))
    })?;
    if let Some((_critical, ku)) = ku {
        if !ku.key_cert_sign() {
            return Err(AttestationError::JwsVerification(format!(
                "x5c[{issuer_index}] keyUsage lacks keyCertSign but it signs a certificate"
            )));
        }
    }

    // Name chaining: issuer.subject must equal subject.issuer. Compare canonical
    // DER encodings of the Name structures.
    let issuer_subject_der = spki::der::Encode::to_der(&issuer.tbs_certificate.subject)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c subject name encode: {e}")))?;
    let subject_issuer_der = spki::der::Encode::to_der(&subject.tbs_certificate.issuer)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c issuer name encode: {e}")))?;
    if issuer_subject_der != subject_issuer_der {
        return Err(AttestationError::JwsVerification(format!(
            "x5c[{issuer_index}] subject does not match issuer of x5c[{subject_index}] \
             (broken name chain)",
            subject_index = issuer_index - 1
        )));
    }

    Ok(())
}

/// Verify that `cert` was signed by `issuer`, dispatching on the certificate's
/// `signatureAlgorithm` OID. Supports the algorithms NRAS uses today:
/// ECDSA with SHA-256/SHA-384 and RSA PKCS#1 v1.5 with SHA-256/SHA-384.
fn verify_cert_signature(
    cert: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
    index: usize,
) -> Result<()> {
    use der::oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, SHA_256_WITH_RSA_ENCRYPTION,
        SHA_384_WITH_RSA_ENCRYPTION,
    };

    let issuer_spki_der = spki::der::Encode::to_der(
        &issuer.tbs_certificate.subject_public_key_info,
    )
    .map_err(|e| AttestationError::JwsVerification(format!("x5c issuer spki encode: {e}")))?;
    let tbs_der = spki::der::Encode::to_der(&cert.tbs_certificate)
        .map_err(|e| AttestationError::JwsVerification(format!("x5c[{index}] tbs encode: {e}")))?;
    let sig_bytes = cert.signature.raw_bytes();
    let sig_alg = cert.signature_algorithm.oid;

    let verified = match sig_alg {
        ECDSA_WITH_SHA_384 => verify_ecdsa_p384(&issuer_spki_der, &tbs_der, sig_bytes),
        ECDSA_WITH_SHA_256 => verify_ecdsa_p256(&issuer_spki_der, &tbs_der, sig_bytes),
        SHA_256_WITH_RSA_ENCRYPTION => verify_rsa_sha256(&issuer_spki_der, &tbs_der, sig_bytes),
        SHA_384_WITH_RSA_ENCRYPTION => verify_rsa_sha384(&issuer_spki_der, &tbs_der, sig_bytes),
        other => {
            return Err(AttestationError::JwsVerification(format!(
                "x5c[{index}] unsupported signatureAlgorithm: {other}"
            )));
        }
    };
    if verified {
        Ok(())
    } else {
        Err(AttestationError::JwsVerification(format!(
            "x5c[{index}] not signed by x5c[{}]",
            index + 1
        )))
    }
}

fn verify_ecdsa_p384(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use p384::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = p384::ecdsa::VerifyingKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let Ok(sig) = p384::ecdsa::DerSignature::from_bytes(sig_bytes) else {
        return false;
    };
    key.verify(tbs, &sig).is_ok()
}

fn verify_ecdsa_p256(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = p256::ecdsa::VerifyingKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::DerSignature::from_bytes(sig_bytes) else {
        return false;
    };
    key.verify(tbs, &sig).is_ok()
}

fn verify_rsa_sha256(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key);
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) else {
        return false;
    };
    verifier.verify(tbs, &sig).is_ok()
}

fn verify_rsa_sha384(issuer_spki: &[u8], tbs: &[u8], sig_bytes: &[u8]) -> bool {
    use signature::Verifier as _;
    use spki::DecodePublicKey as _;
    let Ok(key) = rsa::RsaPublicKey::from_public_key_der(issuer_spki) else {
        return false;
    };
    let verifier = rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key);
    let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) else {
        return false;
    };
    verifier.verify(tbs, &sig).is_ok()
}

/// Bind one submodule to the attestation session by checking its `eat_nonce`
/// against the derived SPDM nonce. NRAS encodes `eat_nonce` as a hex string
/// (see the overall-token DEVIATION note); we hex-decode and compare in
/// constant time. A missing, non-string, non-hex, or mismatched nonce fails
/// closed — this is what stops a valid-but-foreign submodule from being spliced
/// into the response.
fn check_submodule_nonce(
    name: &str,
    sub_claims: &serde_json::Value,
    nonce_bytes: &[u8],
) -> Result<()> {
    let ok = sub_claims
        .get("eat_nonce")
        .and_then(|v| v.as_str())
        .and_then(|n| hex::decode(n).ok())
        .map(|decoded| {
            use subtle::ConstantTimeEq;
            decoded.ct_eq(nonce_bytes).into()
        })
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(AttestationError::NvidiaGpuSubmoduleNonceMismatch {
            name: name.to_string(),
        })
    }
}

/// The device's SPDM report must have been produced for this session's nonce
/// (`x-nvidia-gpu-attestation-report-nonce-match`); otherwise it could be a
/// replay, so the evidence is not genuine.
fn check_device_report_nonce(name: &str, dc: &NvidiaGpuDeviceClaims) -> Result<()> {
    if dc.nonce_match == Some(true) {
        Ok(())
    } else {
        Err(AttestationError::NvidiaGpuSubmoduleNonceMismatch {
            name: name.to_string(),
        })
    }
}

/// Check per-device policy against a submodule's claims, independent of NRAS's
/// opaque overall boolean. Each gate fails closed by default (see
/// [`crate::types::NvidiaGpuDevicePolicy`]). A claim that is absent when its
/// gate is enabled counts as a failure — we do not trust a device whose state
/// we cannot read.
fn device_policy_holds(
    name: &str,
    dc: &NvidiaGpuDeviceClaims,
    policy: &crate::types::NvidiaGpuDevicePolicy,
) -> bool {
    let failed = if !policy.allow_debug && dc.dbgstat.as_deref() != Some("disabled") {
        Some("dbgstat is not \"disabled\"")
    } else if policy.require_secboot && dc.secboot != Some(true) {
        Some("secboot is not true")
    } else if policy.require_measres_success && dc.measres.as_deref() != Some("success") {
        Some("measres is not \"success\"")
    } else {
        None
    };
    if let Some(reason) = failed {
        log::warn!("GPU device {name} failed policy: {reason}");
    }
    failed.is_none()
}

/// Decode a single GPU submodule JWT body into [`NvidiaGpuDeviceClaims`].
fn device_claims_from_submodule(body: &serde_json::Value) -> NvidiaGpuDeviceClaims {
    let s = |k: &str| body.get(k).and_then(|v| v.as_str()).map(String::from);
    let b = |k: &str| body.get(k).and_then(|v| v.as_bool());

    NvidiaGpuDeviceClaims {
        arch: body
            .get("hwmodel")
            .and_then(|v| v.as_str())
            .and_then(arch_from_hwmodel),
        ueid: s("ueid"),
        hwmodel: s("hwmodel"),
        measres: s("measres"),
        secboot: b("secboot"),
        dbgstat: s("dbgstat"),
        driver_version: s("x-nvidia-gpu-driver-version"),
        vbios_version: s("x-nvidia-gpu-vbios-version"),
        arch_check: b("x-nvidia-gpu-arch-check"),
        nonce_match: b("x-nvidia-gpu-attestation-report-nonce-match"),
        report_signature_verified: b("x-nvidia-gpu-attestation-report-signature-verified"),
        driver_rim_fetched: b("x-nvidia-gpu-driver-rim-fetched"),
        vbios_rim_fetched: b("x-nvidia-gpu-vbios-rim-fetched"),
        raw: body.clone(),
    }
}

fn arch_from_hwmodel(s: &str) -> Option<NvidiaGpuArch> {
    let up = s.to_ascii_uppercase();
    if up.contains("HOPPER") || up.starts_with("GH100") {
        Some(NvidiaGpuArch::Hopper)
    } else if up.contains("BLACKWELL") || up.starts_with("GB") {
        Some(NvidiaGpuArch::Blackwell)
    } else if up.contains("LS10") || up.contains("SWITCH") {
        Some(NvidiaGpuArch::Ls10)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::nvidia_gpu::provider::JwksKey;
    use crate::platforms::nvidia_gpu::MIN_GPU_USER_NONCE_LEN;
    use crate::types::{
        NvidiaGpuArch, NvidiaGpuBinding, NvidiaGpuDeviceClaims, NvidiaGpuDeviceEvidence,
        NvidiaGpuEvidenceBundle, NvidiaGpuParams,
    };

    fn one_device_bundle() -> NvidiaGpuEvidenceBundle {
        NvidiaGpuEvidenceBundle {
            devices: vec![NvidiaGpuDeviceEvidence {
                arch: NvidiaGpuArch::Blackwell,
                uuid: "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
                evidence_b64: String::new(),
                cert_chain_b64: String::new(),
            }],
            binding: NvidiaGpuBinding::default(),
        }
    }

    /// Real bug this catches: removing the `check_user_nonce_len(user_nonce)?`
    /// call site from `verify_bundle` (verify.rs:40). The helper would
    /// still exist, the unit-level branch would still work, but a short nonce
    /// would silently flow into the NRAS request. A held-only store records
    /// every document it was asked for, so the rejection is shown to come
    /// first.
    #[tokio::test]
    async fn gather_bundle_rejects_short_user_nonce_before_any_fetch() {
        let too_short = vec![0u8; MIN_GPU_USER_NONCE_LEN - 1];
        let bundle = one_device_bundle();
        let params = NvidiaGpuParams {
            user_nonce: Some(too_short.clone()),
            ..Default::default()
        };

        let ctx = crate::context::Context::held([]);
        let result = gather_bundle(&bundle, &params, ctx.store(), 0)
            .await
            .map(|_| ());
        assert!(ctx.store().missing().is_empty());

        match result {
            Err(AttestationError::NvidiaGpuNonceTooShort(n)) => {
                assert_eq!(n, too_short.len());
            }
            other => panic!("expected NvidiaGpuNonceTooShort, got {other:?}"),
        }
    }

    #[test]
    fn split_eat_parses_valid_detached_eat() {
        let v = serde_json::json!([
            ["JWT", "overall.jwt.sig"],
            { "GPU-0": "gpu0.jwt.sig", "GPU-1": "gpu1.jwt.sig" }
        ]);
        let (overall, mut subs) = split_eat_response(&v).expect("valid EAT must parse");
        assert_eq!(overall, "overall.jwt.sig");
        subs.sort();
        assert_eq!(
            subs,
            vec![
                ("GPU-0".to_string(), "gpu0.jwt.sig".to_string()),
                ("GPU-1".to_string(), "gpu1.jwt.sig".to_string()),
            ]
        );
    }

    /// A bare JWT string carries no per-device submodules. It used to parse to
    /// zero submodules and fail later as a `DeviceCountMismatch`; now it errors
    /// at the parse site with a precise message.
    #[test]
    fn split_eat_rejects_bare_jwt_string() {
        let v = serde_json::json!("just.a.jwt");
        assert!(matches!(
            split_eat_response(&v),
            Err(AttestationError::NrasResponseParse(_))
        ));
    }

    /// A submodule entry whose value is not a string is malformed and must be
    /// reported as a parse error, not silently dropped (which would surface as
    /// a misleading count mismatch).
    #[test]
    fn split_eat_rejects_non_string_submodule() {
        let v = serde_json::json!([
            ["JWT", "overall.jwt.sig"],
            { "GPU-0": "gpu0.jwt.sig", "GPU-1": 42 }
        ]);
        assert!(matches!(
            split_eat_response(&v),
            Err(AttestationError::NrasResponseParse(_))
        ));
    }

    /// RFC 7515 §4.1.11: a JWS carrying a critical (`crit`) header extension we
    /// don't understand must be rejected. The check must fire before key
    /// lookup, so an empty JWKS still yields the crit error (not a kid miss).
    #[test]
    fn verify_jws_rejects_crit_header() {
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "alg": "ES384", "kid": "k1", "crit": ["exp"] }).to_string(),
        );
        let token = format!("{header}.eyJhIjoxfQ.c2ln");
        let jwks = Jwks { keys: vec![] };
        // The `crit` check must fire before key lookup: with an empty JWKS, a
        // kid miss would surface as `JwksKidNotFound`, so getting the
        // `JwsVerification` variant proves the crit rejection ran first.
        assert!(matches!(
            verify_jws_es384(&token, &jwks, now()),
            Err(AttestationError::JwsVerification(_))
        ));
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    // SEC-1: the raw-coordinate JWKS path is gone; only x5c is accepted.

    #[test]
    fn jwks_entry_without_usable_x5c_is_rejected() {
        // A well-formed P-384 (x, y) entry that pre-SEC-1 would have been
        // accepted with no chain validation and no pin. Both a missing chain
        // and an empty one must now fail closed.
        for x5c in [None, Some(vec![])] {
            let key = JwksKey {
                kid: "k1".into(),
                kty: "EC".into(),
                alg: Some("ES384".into()),
                crv: Some("P-384".into()),
                x: Some(URL_SAFE_NO_PAD.encode([1u8; 48])),
                y: Some(URL_SAFE_NO_PAD.encode([2u8; 48])),
                x5c,
            };
            assert!(
                es384_verifying_key_from_jwks_entry(&key, now()).is_err(),
                "raw (x,y) without an x5c chain must be rejected"
            );
        }
    }

    // SEC-5: exp required + numeric (fractional ok); nbf enforced when present.
    // `enforce_time_claims` is the load-bearing logic, tested directly so we do
    // not need a JWKS that chains to the pinned anchor.

    #[test]
    fn time_claims_reject_missing_or_non_numeric_exp() {
        // No exp, or an exp that is not a number, must fail closed (no fail-open
        // "accept a token with no expiry").
        assert!(enforce_time_claims(&serde_json::json!({ "foo": 1 }), now()).is_err());
        assert!(enforce_time_claims(&serde_json::json!({ "exp": "not-a-number" }), now()).is_err());
    }

    #[test]
    fn time_claims_reject_expired() {
        let claims = serde_json::json!({ "exp": now() - 60 });
        assert!(enforce_time_claims(&claims, now()).is_err());
    }

    #[test]
    fn time_claims_accept_fractional_future_exp() {
        // RFC 7519 permits a fractional NumericDate; `as_i64` would reject it.
        let claims = serde_json::json!({ "exp": (now() + 3600) as f64 + 0.5 });
        enforce_time_claims(&claims, now()).expect("fractional future exp must be accepted");
    }

    #[test]
    fn time_claims_reject_not_yet_valid_nbf() {
        let claims = serde_json::json!({ "exp": now() + 3600, "nbf": now() + 600 });
        assert!(enforce_time_claims(&claims, now()).is_err());
    }

    #[test]
    fn time_claims_accept_past_nbf_and_future_exp() {
        let claims = serde_json::json!({ "exp": now() + 3600, "nbf": now() - 600 });
        enforce_time_claims(&claims, now()).expect("past nbf with valid exp must be accepted");
    }

    // SEC-3: per-submodule eat_nonce binding.

    #[test]
    fn submodule_nonce_matches_derived() {
        let nonce = [9u8; 32];
        let claims = serde_json::json!({ "eat_nonce": hex::encode(nonce) });
        check_submodule_nonce("GPU-0", &claims, &nonce).expect("matching nonce must pass");
    }

    #[test]
    fn submodule_nonce_mismatch_is_rejected() {
        let nonce = [9u8; 32];
        let other = [8u8; 32];
        let claims = serde_json::json!({ "eat_nonce": hex::encode(other) });
        match check_submodule_nonce("GPU-1", &claims, &nonce) {
            Err(AttestationError::NvidiaGpuSubmoduleNonceMismatch { name }) => {
                assert_eq!(name, "GPU-1");
            }
            other => panic!("expected submodule nonce mismatch, got {other:?}"),
        }
    }

    #[test]
    fn submodule_missing_nonce_is_rejected() {
        let nonce = [9u8; 32];
        let claims = serde_json::json!({ "foo": 1 });
        assert!(matches!(
            check_submodule_nonce("GPU-2", &claims, &nonce),
            Err(AttestationError::NvidiaGpuSubmoduleNonceMismatch { .. })
        ));
    }

    // SEC-3: per-device policy gates.

    fn compliant_device() -> NvidiaGpuDeviceClaims {
        NvidiaGpuDeviceClaims {
            secboot: Some(true),
            dbgstat: Some("disabled".into()),
            measres: Some("success".into()),
            nonce_match: Some(true),
            ..Default::default()
        }
    }

    #[test]
    fn device_policy_accepts_compliant_device() {
        let policy = crate::types::NvidiaGpuDevicePolicy::default();
        assert!(
            device_policy_holds("GPU-0", &compliant_device(), &policy),
            "fully compliant device must pass default policy"
        );
    }

    /// Each default gate must reject a device that violates it (including the
    /// absent-claim case, which must fail closed). One mutation per gate.
    #[test]
    fn device_policy_rejects_each_gate_violation() {
        let policy = crate::types::NvidiaGpuDevicePolicy::default();
        let mutate: &[fn(&mut NvidiaGpuDeviceClaims)] = &[
            |dc| dc.dbgstat = Some("enabled".into()),
            |dc| dc.dbgstat = None,
            |dc| dc.secboot = Some(false),
            |dc| dc.secboot = None,
            |dc| dc.measres = Some("failure".into()),
            |dc| dc.measres = None,
        ];
        for (i, m) in mutate.iter().enumerate() {
            let mut dc = compliant_device();
            m(&mut dc);
            assert!(
                !device_policy_holds("GPU-0", &dc, &policy),
                "mutation #{i} should have been rejected by default policy"
            );
        }
    }

    #[test]
    fn device_report_nonce_mismatch_is_an_error() {
        check_device_report_nonce("GPU-0", &compliant_device()).expect("matching nonce");
        for nonce_match in [Some(false), None] {
            let dc = NvidiaGpuDeviceClaims {
                nonce_match,
                ..compliant_device()
            };
            assert!(matches!(
                check_device_report_nonce("GPU-0", &dc),
                Err(AttestationError::NvidiaGpuSubmoduleNonceMismatch { .. })
            ));
        }
    }

    #[test]
    fn gpu_result_passes_only_when_every_rule_holds() {
        let passing = || NvidiaGpuResult {
            claims: NvidiaGpuClaims {
                overall_ok: true,
                ..Default::default()
            },
            archs_allowed: Some(true),
            device_count_match: true,
            device_policy_met: true,
        };
        assert!(passing().passed());
        let failing: &[fn(&mut NvidiaGpuResult)] = &[
            |r| r.claims.overall_ok = false,
            |r| r.archs_allowed = Some(false),
            |r| r.device_count_match = false,
            |r| r.device_policy_met = false,
        ];
        for (i, f) in failing.iter().enumerate() {
            let mut r = passing();
            f(&mut r);
            assert!(!r.passed(), "rule #{i} must fail passed()");
        }
    }

    #[test]
    fn device_policy_allows_debug_when_opted_in() {
        let policy = crate::types::NvidiaGpuDevicePolicy {
            allow_debug: true,
            ..Default::default()
        };
        let mut dc = compliant_device();
        dc.dbgstat = Some("enabled".into());
        assert!(
            device_policy_holds("GPU-0", &dc, &policy),
            "debug-enabled device must pass when allow_debug is set"
        );
    }

    // SEC-4: x5c RFC 5280 path validation. These negative tests mutate a real
    // NRAS chain captured from production
    // (`test_data/nvidia_gpu/nras_gpu_x5c_chain.json`: [leaf GPU cert,
    // Intermediate 004], intermediate = pinned anchor) to confirm each rejection
    // branch fires. The positive (valid-chain-accepted) case is deliberately not
    // a unit test: the captured leaf has a ~2-day validity window, so asserting
    // acceptance would make the test fail once the cert ages out. It was
    // validated once live during development.

    fn nras_x5c_fixture() -> Vec<String> {
        let raw = include_str!("../../../test_data/nvidia_gpu/nras_gpu_x5c_chain.json");
        let v: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        v["x5c"]
            .as_array()
            .expect("x5c array")
            .iter()
            .map(|c| c.as_str().expect("x5c entry is a string").to_string())
            .collect()
    }

    #[test]
    fn x5c_reversed_chain_breaks_name_linkage() {
        // Swapping leaf and intermediate breaks both the signature linkage and
        // the issuer<->subject name chain; either way it must be rejected.
        let mut chain = nras_x5c_fixture();
        chain.reverse();
        match verify_x5c_chain_and_extract_key(&chain, now()) {
            Err(AttestationError::JwsVerification(_)) => {}
            other => panic!("reversed chain must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn x5c_single_leaf_only_is_rejected() {
        // Leaf alone: no intermediate, so the topmost SPKI is the leaf's, which
        // is not in the pinned trusted set. (If the captured leaf has aged out,
        // the validity check rejects it first — either way it must not pass.)
        let chain = vec![nras_x5c_fixture()[0].clone()];
        match verify_x5c_chain_and_extract_key(&chain, now()) {
            Err(AttestationError::JwsVerification(_)) => {}
            other => panic!("leaf-only chain must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn device_policy_gates_are_independently_disablable() {
        // With every gate off, even a fully non-compliant device passes.
        let policy = crate::types::NvidiaGpuDevicePolicy {
            allow_debug: true,
            require_secboot: false,
            require_measres_success: false,
        };
        let dc = NvidiaGpuDeviceClaims::default();
        assert!(
            device_policy_holds("GPU-0", &dc, &policy),
            "all-gates-off policy must accept any device"
        );
    }
}
