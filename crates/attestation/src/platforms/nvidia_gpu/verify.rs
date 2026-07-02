//! Verify a [`NvidiaGpuEvidenceBundle`] using NRAS.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::{AttestationError, Result};
use crate::platforms::nvidia_gpu::provider::{Jwks, NrasEvidenceEntry, NrasProvider, NrasRequest};
use crate::platforms::nvidia_gpu::{gpu_nonce, switch_nonce};
use crate::types::{
    NvidiaGpuArch, NvidiaGpuClaims, NvidiaGpuDeviceClaims, NvidiaGpuEvidenceBundle, VerifyParams,
};

/// Verify a GPU bundle end-to-end:
/// - Group devices by arch (NRAS requires one arch per request).
/// - Derive the SPDM nonce from `params.nvidia_gpu.user_nonce` per `bundle.binding`.
/// - POST evidence to NRAS, JWS-verify the response, check `eat_nonce` and
///   `x-nvidia-overall-att-result`.
///
/// Returns aggregated [`NvidiaGpuClaims`]. Caller is responsible for asserting any
/// `claims.platform_data` ↔ `claims.gpu` semantic coupling (e.g. the same
/// `user_nonce` was used).
pub async fn verify_bundle(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &VerifyParams,
    provider: &dyn NrasProvider,
) -> Result<NvidiaGpuClaims> {
    let user_nonce = check_preconditions(bundle, params)?;

    let mut aggregated = NvidiaGpuClaims {
        overall_ok: true,
        eat_nonce: None,
        nonce_binding_ok: true,
        devices: Vec::with_capacity(bundle.devices.len()),
        overall_raw: serde_json::Value::Null,
    };

    for (arch, devices) in group_by_arch(bundle) {
        let group = verify_arch_group(arch, &devices, user_nonce, bundle, params, provider).await?;
        fold_arch_group(&mut aggregated, group);
    }

    final_checks(&aggregated, bundle.devices.len())?;
    log::info!(
        "NVIDIA GPU attestation passed: {} device(s), nonce_binding_ok=true",
        aggregated.devices.len()
    );
    Ok(aggregated)
}

const MAX_GPU_DEVICES: usize = 32;

/// Validate bundle and params before any network or crypto work. Returns the
/// validated `user_nonce` slice on success.
fn check_preconditions<'a>(
    bundle: &NvidiaGpuEvidenceBundle,
    params: &'a VerifyParams,
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
        .nvidia_gpu
        .user_nonce
        .as_deref()
        .ok_or(AttestationError::NvidiaGpuUserNonceMissing)?;
    super::check_user_nonce_len(user_nonce)?;

    // Enforce allowed binding algorithms. Default: only Concat { Sha256 }.
    let default_allowed = [crate::types::NvidiaGpuBinding::default()];
    let allowed = params
        .nvidia_gpu
        .allowed_bindings
        .as_deref()
        .unwrap_or(&default_allowed);
    if !allowed.contains(&bundle.binding) {
        return Err(AttestationError::NvidiaGpuBindingNotAllowed);
    }

    if let Some(whitelist) = &params.nvidia_gpu.expected_archs {
        for dev in &bundle.devices {
            if !whitelist.contains(&dev.arch) {
                return Err(AttestationError::NvidiaGpuArchNotAllowed(
                    dev.arch.to_string(),
                ));
            }
        }
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
    nonce_binding_ok: bool,
    overall_raw: serde_json::Value,
    devices: Vec<crate::types::NvidiaGpuDeviceClaims>,
}

/// Build the NRAS request, attest, JWS-verify the overall + each submodule,
/// and check the eat_nonce binding against the derived SPDM nonce.
async fn verify_arch_group(
    arch: NvidiaGpuArch,
    devices: &[&crate::types::NvidiaGpuDeviceEvidence],
    user_nonce: &[u8],
    bundle: &NvidiaGpuEvidenceBundle,
    params: &VerifyParams,
    provider: &dyn NrasProvider,
) -> Result<ArchGroupResult> {
    let nonce_bytes = match arch {
        NvidiaGpuArch::Ls10 => switch_nonce(user_nonce, &bundle.binding),
        _ => gpu_nonce(user_nonce, &bundle.binding),
    };
    let nonce_hex = hex::encode(nonce_bytes);

    let request = NrasRequest {
        nonce: nonce_hex.clone(),
        evidence_list: devices
            .iter()
            .map(|d| NrasEvidenceEntry {
                evidence: d.evidence_b64.clone(),
                certificate: d.cert_chain_b64.clone(),
            })
            .collect(),
        arch,
        claims_version: provider.claims_version().to_string(),
    };

    let response = provider.attest(&request).await?;
    let (overall_jwt, submodule_jwts) = split_eat_response(&response)?;
    let mut jwks = provider.jwks(arch).await?;

    let overall_claims =
        verify_jws_with_kid_rotation(&overall_jwt, &mut jwks, arch, provider).await?;
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
        .map(|decoded| {
            use subtle::ConstantTimeEq;
            decoded.ct_eq(&nonce_bytes).into()
        })
        .unwrap_or(false);

    let mut device_claims = Vec::with_capacity(submodule_jwts.len());
    for (name, sub_jwt) in submodule_jwts {
        let sub_claims = verify_jws_with_kid_rotation(&sub_jwt, &mut jwks, arch, provider).await?;
        // Bind this submodule to the session: its `eat_nonce` must equal the
        // SPDM nonce we derived. The overall token's `eat_nonce` alone does not
        // cover the submodule JWTs (NRAS's RFC 9711 `submods` DIGEST is computed
        // over an intermediate that excludes the issued JWT's time claims, so it
        // is not byte-verifiable against the returned compact JWS — see the
        // module docs). Per-submodule `eat_nonce` is the cheaper, robust subset:
        // a submodule spliced from another session carries a different nonce and
        // is rejected here.
        check_submodule_nonce(&name, &sub_claims, &nonce_bytes)?;
        let mut dc = device_claims_from_submodule(&sub_claims);
        if dc.arch.is_none() {
            dc.arch = Some(arch);
        }
        apply_device_policy(&name, &dc, &params.nvidia_gpu.device_policy)?;
        device_claims.push(dc);
    }

    Ok(ArchGroupResult {
        overall_ok,
        eat_nonce,
        nonce_binding_ok,
        overall_raw: overall_claims,
        devices: device_claims,
    })
}

/// Merge a per-arch result into the running aggregate. `overall_raw` overwrites
/// each iteration — fine for v1, where multiple arches in one bundle is rare.
fn fold_arch_group(aggregated: &mut NvidiaGpuClaims, group: ArchGroupResult) {
    aggregated.overall_ok &= group.overall_ok;
    aggregated.nonce_binding_ok &= group.nonce_binding_ok;
    if aggregated.eat_nonce.is_none() {
        aggregated.eat_nonce = group.eat_nonce;
    }
    aggregated.overall_raw = group.overall_raw;
    aggregated.devices.extend(group.devices);
}

/// Post-aggregation invariants: every device produced claims, overall passed,
/// and the eat_nonce bound to our derived SPDM nonce.
fn final_checks(aggregated: &NvidiaGpuClaims, expected_devices: usize) -> Result<()> {
    if aggregated.devices.len() != expected_devices {
        log::warn!(
            "NVIDIA GPU attestation: device count mismatch (expected {}, got {})",
            expected_devices,
            aggregated.devices.len()
        );
        return Err(AttestationError::NvidiaGpuDeviceCountMismatch {
            expected: expected_devices,
            got: aggregated.devices.len(),
        });
    }
    if !aggregated.overall_ok {
        log::warn!("NVIDIA GPU attestation: NRAS overall result is false");
        return Err(AttestationError::NrasOverallFailed);
    }
    if !aggregated.nonce_binding_ok {
        log::warn!("NVIDIA GPU attestation: nonce binding mismatch");
        return Err(AttestationError::NvidiaGpuBindingMismatch);
    }
    Ok(())
}

/// Verify a JWS, transparently refetching the JWKS once on `kid` miss.
///
/// NRAS rotates signing keys without coordination. Both the overall and
/// per-submodule JWTs in a single response may reference a kid that wasn't
/// in our cached JWKS at the time of fetch. On miss, force-refresh once and
/// retry. After the refetch, `*jwks` reflects the new key set so subsequent
/// calls (e.g. for submodule JWTs after the overall has rotated) use the
/// refreshed material without an extra round-trip.
async fn verify_jws_with_kid_rotation(
    token: &str,
    jwks: &mut Jwks,
    arch: NvidiaGpuArch,
    provider: &dyn NrasProvider,
) -> Result<serde_json::Value> {
    match verify_jws_es384(token, jwks) {
        Err(AttestationError::JwksKidNotFound(_)) => {
            *jwks = provider.jwks_force(arch).await?;
            verify_jws_es384(token, jwks)
        }
        other => other,
    }
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

/// Verify an ES384-signed compact JWS against a JWKS, returning the decoded
/// claims body.
pub fn verify_jws_es384(token: &str, jwks: &Jwks) -> Result<serde_json::Value> {
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

    let verifying_key = es384_verifying_key_from_jwks_entry(key)?;

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

    enforce_time_claims(&claims)?;

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
/// Runs on all targets including wasm32: `chrono::Utc::now()` works on wasm via
/// the `wasmbind` feature (see Cargo.toml), unlike `SystemTime`, which traps on
/// wasm32-unknown-unknown.
fn enforce_time_claims(claims: &serde_json::Value) -> Result<()> {
    let now = chrono::Utc::now().timestamp();

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
) -> Result<p384::ecdsa::VerifyingKey> {
    // The signing key MUST come from an x5c chain that validates up to the
    // pinned NVIDIA trust anchor. The raw JWK `(x, y)` coordinates carry no
    // chain and no pin, so accepting them would degrade trust to WebPKI TLS for
    // the JWKS host (which is itself overridable via `NV_NRAS_GPU_URL`): a MITM
    // serving a JWKS of attacker-chosen coordinates could forge every EAT. We
    // therefore require x5c and never fall back to bare coordinates.
    match &key.x5c {
        Some(chain) if !chain.is_empty() => verify_x5c_chain_and_extract_key(chain),
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
fn verify_x5c_chain_and_extract_key(chain: &[String]) -> Result<p384::ecdsa::VerifyingKey> {
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

    // Enforce certificate validity periods on all targets, including wasm32.
    // `chrono::Utc::now()` works on wasm (unlike `SystemTime`, which we used to
    // cfg out — silently accepting expired NRAS signing certs in the browser).
    {
        let now_secs = chrono::Utc::now().timestamp();
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

/// Enforce per-device policy against a submodule's claims, independent of NRAS's
/// opaque overall boolean. Each gate fails closed by default (see
/// [`crate::types::NvidiaGpuDevicePolicy`]). A claim that is absent when its gate
/// is enabled is treated as a failure — we do not trust a device whose state we
/// cannot read.
fn apply_device_policy(
    name: &str,
    dc: &NvidiaGpuDeviceClaims,
    policy: &crate::types::NvidiaGpuDevicePolicy,
) -> Result<()> {
    let fail = |reason: String| {
        Err(AttestationError::NvidiaGpuDevicePolicyFailed {
            name: name.to_string(),
            reason,
        })
    };

    if !policy.allow_debug {
        // `dbgstat` must be present and equal to "disabled".
        match dc.dbgstat.as_deref() {
            Some("disabled") => {}
            Some(other) => return fail(format!("dbgstat is \"{other}\", expected \"disabled\"")),
            None => return fail("dbgstat claim missing".into()),
        }
    }
    if policy.require_secboot && dc.secboot != Some(true) {
        return fail(format!("secboot is {:?}, expected true", dc.secboot));
    }
    if policy.require_nonce_match && dc.nonce_match != Some(true) {
        return fail(format!(
            "attestation-report-nonce-match is {:?}, expected true",
            dc.nonce_match
        ));
    }
    if policy.require_measres_success {
        match dc.measres.as_deref() {
            Some("success") => {}
            Some(other) => return fail(format!("measres is \"{other}\", expected \"success\"")),
            None => return fail("measres claim missing".into()),
        }
    }
    Ok(())
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
        NvidiaGpuEvidenceBundle, NvidiaGpuParams, VerifyParams,
    };

    /// `NrasProvider` whose methods panic on call. Used to prove `verify_bundle`
    /// short-circuits on bad input before reaching the network/FFI.
    struct PanicProvider;

    #[async_trait::async_trait]
    impl NrasProvider for PanicProvider {
        fn url_for(&self, _arch: NvidiaGpuArch) -> &str {
            "https://invalid.test/should-not-be-called"
        }
        async fn attest(&self, _request: &NrasRequest) -> Result<serde_json::Value> {
            panic!("verify_bundle reached provider.attest() with invalid input");
        }
        async fn jwks(&self, _arch: NvidiaGpuArch) -> Result<Jwks> {
            panic!("verify_bundle reached provider.jwks() with invalid input");
        }
    }

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
    /// would silently flow into the NRAS request. The `PanicProvider` exists
    /// to assert the rejection happens *before* any network call.
    #[tokio::test]
    async fn verify_bundle_rejects_short_user_nonce_before_provider_call() {
        let too_short = vec![0u8; MIN_GPU_USER_NONCE_LEN - 1];
        let bundle = one_device_bundle();
        let params = VerifyParams {
            nvidia_gpu: NvidiaGpuParams {
                user_nonce: Some(too_short.clone()),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = verify_bundle(&bundle, &params, &PanicProvider).await;

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
            verify_jws_es384(&token, &jwks),
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
                es384_verifying_key_from_jwks_entry(&key).is_err(),
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
        assert!(enforce_time_claims(&serde_json::json!({ "foo": 1 })).is_err());
        assert!(enforce_time_claims(&serde_json::json!({ "exp": "not-a-number" })).is_err());
    }

    #[test]
    fn time_claims_reject_expired() {
        let claims = serde_json::json!({ "exp": now() - 60 });
        assert!(enforce_time_claims(&claims).is_err());
    }

    #[test]
    fn time_claims_accept_fractional_future_exp() {
        // RFC 7519 permits a fractional NumericDate; `as_i64` would reject it.
        let claims = serde_json::json!({ "exp": (now() + 3600) as f64 + 0.5 });
        enforce_time_claims(&claims).expect("fractional future exp must be accepted");
    }

    #[test]
    fn time_claims_reject_not_yet_valid_nbf() {
        let claims = serde_json::json!({ "exp": now() + 3600, "nbf": now() + 600 });
        assert!(enforce_time_claims(&claims).is_err());
    }

    #[test]
    fn time_claims_accept_past_nbf_and_future_exp() {
        let claims = serde_json::json!({ "exp": now() + 3600, "nbf": now() - 600 });
        enforce_time_claims(&claims).expect("past nbf with valid exp must be accepted");
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
        apply_device_policy("GPU-0", &compliant_device(), &policy)
            .expect("fully compliant device must pass default policy");
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
            |dc| dc.nonce_match = Some(false),
            |dc| dc.nonce_match = None,
            |dc| dc.measres = Some("failure".into()),
            |dc| dc.measres = None,
        ];
        for (i, m) in mutate.iter().enumerate() {
            let mut dc = compliant_device();
            m(&mut dc);
            assert!(
                matches!(
                    apply_device_policy("GPU-0", &dc, &policy),
                    Err(AttestationError::NvidiaGpuDevicePolicyFailed { .. })
                ),
                "mutation #{i} should have been rejected by default policy"
            );
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
        apply_device_policy("GPU-0", &dc, &policy)
            .expect("debug-enabled device must pass when allow_debug is set");
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
        match verify_x5c_chain_and_extract_key(&chain) {
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
        match verify_x5c_chain_and_extract_key(&chain) {
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
            require_nonce_match: false,
            require_measres_success: false,
        };
        let dc = NvidiaGpuDeviceClaims::default();
        apply_device_policy("GPU-0", &dc, &policy)
            .expect("all-gates-off policy must accept any device");
    }
}
