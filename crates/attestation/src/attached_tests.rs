//! Evidence that carries its collateral: attached where the evidence is made,
//! verified with nothing but the compiled-in roots.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::collateral::{Source, VersionFloors, GRACE};
use crate::context::HeldResponse;
use crate::testing::{self, NOW};
use crate::{AttestationError, Context, Policies, Verified, Verifier};

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/");

fn read(file: &str) -> Vec<u8> {
    std::fs::read(format!("{DATA}{file}")).unwrap()
}

fn envelope(platform: &str, evidence: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "platform": platform, "evidence": evidence })).unwrap()
}

fn tdx() -> Vec<u8> {
    envelope(
        "tdx",
        serde_json::json!({ "quote": BASE64.encode(read("tdx_quote_00a06d080000.dat")) }),
    )
}

/// The live Genoa evidence without its VCEK, so the VCEK is attached too.
fn snp() -> Vec<u8> {
    let mut e: serde_json::Value =
        serde_json::from_slice(&read("snp/live-evidence-genoa.json")).unwrap();
    e["evidence"].as_object_mut().unwrap().remove("cert_chain");
    serde_json::to_vec(&e).unwrap()
}

fn gcp_tdx() -> Vec<u8> {
    envelope(
        "gcp-tdx",
        serde_json::json!({ "quote": BASE64.encode(read("gcp_tdx/boot-quote.dat")) }),
    )
}

fn gcp_snp() -> Vec<u8> {
    let mut e: serde_json::Value =
        serde_json::from_slice(&read("gcp_snp/evidence-boot1.json")).unwrap();
    e["platform"] = "gcp-snp".into();
    serde_json::to_vec(&e).unwrap()
}

/// Every vendor response the fixtures can answer for the URLs a verifier of
/// `envelope` asks for.
async fn vendor_for(envelope: &[u8]) -> Vec<HeldResponse> {
    let probe = Verifier::new(testing::context(testing::intel()));
    let _ = probe.verify(envelope, &Policies::all()).await;
    let mut held = testing::intel();
    for url in probe.context().store().missing() {
        let body = if url.ends_with("/Genoa/crl") {
            read("collateral/2026-10-14/amd_crl_genoa.der")
        } else if url.ends_with("/Milan/crl") {
            read("collateral/2026-10-14/amd_crl_milan.der")
        } else if url.contains("kdsintf.amd.com") {
            read("snp/live-vcek-genoa.der")
        } else if url.contains("gcp_tdx") || url.contains("/tdx/") {
            read("gcp_tdx/endorsement-c1ee9c16.binarypb")
        } else {
            read("gcp_snp/endorsement-0e017d2f.binarypb")
        };
        held.push((url, body, None));
    }
    held
}

/// `envelope` with its collateral attached by an attester whose store holds
/// the vendor responses.
async fn attached(envelope: &[u8]) -> Vec<u8> {
    let attester = Verifier::new(testing::context(vendor_for(envelope).await));
    attester.attach_collateral(envelope, &[]).await.unwrap()
}

/// A verifier with no network, no cache and nothing held, at `at`.
fn roots_only(at: i64) -> Verifier {
    Verifier::new(Context::held([]).at(at).unwrap())
}

async fn verify_at(envelope: &[u8], policies: &Policies, at: i64) -> crate::Result<Verified> {
    let verifier = roots_only(at);
    let verified = verifier.verify(envelope, policies).await;
    // A piece that does not pass is listed for the caller to fetch.
    let passed = verified.as_ref().map_or(true, |v| v.passed());
    assert_eq!(verifier.context().store().missing().is_empty(), passed);
    verified
}

#[tokio::test]
async fn every_platform_verifies_with_roots_only_from_attached_collateral() {
    for (platform, evidence) in [
        ("tdx", tdx()),
        ("snp", snp()),
        ("gcp-tdx", gcp_tdx()),
        ("gcp-snp", gcp_snp()),
    ] {
        let err = roots_only(NOW)
            .verify(&evidence, &Policies::all())
            .await
            .unwrap_err();
        assert!(err.is_retryable(), "{platform}: {err}");

        let with = attached(&evidence).await;
        let verified = verify_at(&with, &Policies::all(), NOW).await.unwrap();
        assert!(verified.passed(), "{platform}");
        assert!(!verified.collateral.is_empty());
        assert!(verified
            .collateral
            .iter()
            .all(|c| c.from == Source::Attached));
    }
}

#[tokio::test]
async fn attached_collateral_carries_no_root_and_each_chain_once() {
    let with = attached(&tdx()).await;
    let envelope: crate::AttestationEvidence = serde_json::from_slice(&with).unwrap();
    let chains: Vec<&String> = envelope
        .collateral
        .iter()
        .filter_map(|c| c.issuer_chain.as_ref())
        .collect();
    // TCB Info and QE Identity share the TCB Signing chain; the PCK CRL has
    // the PCK Platform CA's.
    assert_eq!((envelope.collateral.len(), chains.len()), (4, 2));
    for chain in chains {
        let certs = ::pem::parse_many(chain).unwrap();
        assert_eq!(certs.len(), 1);
        assert_ne!(
            certs[0].contents(),
            crate::platforms::tdx::dcap::INTEL_SGX_ROOT_CA
        );
    }
}

#[tokio::test]
async fn attached_collateral_is_checked_like_any_other() {
    let mut envelope: serde_json::Value = serde_json::from_slice(&attached(&tdx()).await).unwrap();
    for piece in envelope["collateral"].as_array_mut().unwrap() {
        if piece["url"].as_str().unwrap().contains("/tcb?") {
            let mut body = BASE64.decode(piece["body"].as_str().unwrap()).unwrap();
            let text = String::from_utf8(body.clone()).unwrap();
            body = text.replacen("UpToDate", "OutOfDate", 1).into_bytes();
            piece["body"] = BASE64.encode(body).into();
        }
    }
    let err = roots_only(NOW)
        .verify(&serde_json::to_vec(&envelope).unwrap(), &Policies::all())
        .await
        .unwrap_err();
    assert!(matches!(err, AttestationError::CertChainError(_)), "{err}");
    assert!(!err.is_retryable());
}

/// The TDX evidence with its collateral, the QE Identity replaced by `file`.
async fn tdx_with_qe_identity(file: &str) -> Vec<u8> {
    let mut envelope: crate::AttestationEvidence =
        serde_json::from_slice(&attached(&tdx()).await).unwrap();
    let mut held = envelope.held_collateral();
    for (url, body, _) in &mut held {
        if url.ends_with("/qe/identity") {
            *body = read(&format!("collateral/2026-10-14/{file}"));
        }
    }
    envelope.attach(held);
    serde_json::to_vec(&envelope).unwrap()
}

fn qe_identity(verified: &Verified) -> &crate::CollateralUsed {
    verified
        .collateral
        .iter()
        .find(|c| c.name == "qe-identity")
        .unwrap()
}

#[tokio::test]
async fn an_older_valid_copy_passes_only_at_or_above_the_floor() {
    let older = tdx_with_qe_identity("td_qe_identity_eval21.json").await;
    let newest = tdx_with_qe_identity("td_qe_identity_early.json").await;

    let verified = verify_at(&older, &Policies::all(), NOW).await.unwrap();
    assert_eq!(qe_identity(&verified).version, Some(21));
    assert_eq!(qe_identity(&verified).floor, Some(20));
    assert!(verified.passed());

    let raised = Policies {
        floors: VersionFloors {
            intel_qe_identity: 22,
            ..Default::default()
        },
        ..Policies::all()
    };
    let verifier = roots_only(NOW);
    let verified = verifier
        .verify(&older, &raised)
        .await
        .expect("below the floor is a value");
    assert_eq!(qe_identity(&verified).version, Some(21));
    assert_eq!(qe_identity(&verified).floor, Some(22));
    assert!(verified.platform.passed());
    assert!(!verified.passed());
    // Listed, so a held-only caller (the WASM wrapper) fetches a newer one.
    let missing = verifier.context().store().missing();
    assert!(missing.len() == 1 && missing[0].ends_with("/qe/identity"));
    assert!(verify_at(&newest, &raised, NOW).await.unwrap().passed());
}

#[tokio::test]
async fn the_amd_crl_floor_applies_per_generation() {
    let with = attached(&snp()).await;
    let raised = Policies {
        floors: VersionFloors {
            amd_crl_genoa: 12,
            ..Default::default()
        },
        ..Policies::all()
    };
    let verified = verify_at(&with, &raised, NOW).await.unwrap();
    let crl = verified
        .collateral
        .iter()
        .find(|c| c.name.starts_with("amd-crl"))
        .unwrap();
    assert_eq!((crl.version, crl.floor), (Some(11), Some(12)));
    assert!(!verified.passed());
    let milan_raised = Policies {
        floors: VersionFloors {
            amd_crl_milan: 99,
            ..Default::default()
        },
        ..Policies::all()
    };
    assert!(verify_at(&with, &milan_raised, NOW).await.unwrap().passed());
}

#[tokio::test]
async fn past_next_update_passes_stale_for_the_grace_period_then_fails() {
    let with = attached(&tdx()).await;
    let verified = verify_at(&with, &Policies::all(), NOW).await.unwrap();
    let expiring: Vec<i64> = verified
        .collateral
        .iter()
        .filter_map(|c| c.next_update)
        .filter(|n| *n < NOW + 60 * 86400)
        .collect();
    let (first, last) = (
        *expiring.iter().min().unwrap(),
        *expiring.iter().max().unwrap(),
    );
    assert!(last - first < GRACE - 86400);

    let inside = verify_at(&with, &Policies::all(), last + 3600)
        .await
        .unwrap();
    assert!(inside.collateral.iter().any(|c| c.stale && !c.current));
    assert!(inside.collateral.iter().all(|c| c.current || c.stale));
    assert!(inside.passed());

    let after = verify_at(&with, &Policies::all(), first + GRACE + 1)
        .await
        .unwrap();
    assert!(after.collateral.iter().any(|c| !c.current && !c.stale));
    assert!(after.platform.passed());
    assert!(!after.passed());
}

/// The TDX evidence with its collateral, the platform PCK CRL replaced by
/// `file`.
async fn tdx_with_pck_crl(file: &str) -> Vec<u8> {
    let mut envelope: crate::AttestationEvidence =
        serde_json::from_slice(&attached(&tdx()).await).unwrap();
    let mut held = envelope.held_collateral();
    for (url, body, _) in &mut held {
        if url.contains("/pckcrl?ca=platform") {
            *body = read(&format!("collateral/2026-10-14/{file}"));
        }
    }
    envelope.attach(held);
    serde_json::to_vec(&envelope).unwrap()
}

/// [`testing::intel`] with the QE Identity replaced by `file`.
fn intel_with_qe_identity(file: &str) -> Vec<HeldResponse> {
    let mut held = testing::intel();
    for (url, body, _) in &mut held {
        if url.ends_with("/qe/identity") {
            *body = read(&format!("collateral/2026-10-14/{file}"));
        }
    }
    held
}

fn piece<'a>(verified: &'a Verified, prefix: &str) -> &'a crate::CollateralUsed {
    verified
        .collateral
        .iter()
        .find(|c| c.name.starts_with(prefix))
        .unwrap()
}

#[tokio::test]
async fn an_older_attached_piece_never_replaces_a_newer_held_one() {
    let older = tdx_with_qe_identity("td_qe_identity_eval21.json").await;
    let verifier = Verifier::new(testing::context(intel_with_qe_identity(
        "td_qe_identity_early.json",
    )));
    let verified = verifier.verify(&older, &Policies::all()).await.unwrap();
    let qe = qe_identity(&verified);
    assert_eq!((qe.version, qe.from), (Some(22), Source::Held));

    // Same CRL Number, older thisUpdate.
    let older = tdx_with_pck_crl("pck_crl_platform_2026-03-16_expired.der").await;
    let verifier = Verifier::new(testing::context(testing::intel()));
    let verified = verifier.verify(&older, &Policies::all()).await.unwrap();
    let crl = piece(&verified, "pck-crl");
    assert_eq!(crl.from, Source::Held);
    assert!(crl.current);
    assert!(verified.passed());
}

#[tokio::test]
async fn a_newer_attached_piece_replaces_an_older_held_one() {
    let newer = tdx_with_qe_identity("td_qe_identity_eval21.json").await;
    let verifier = Verifier::new(testing::context(testing::intel()));
    let verified = verifier.verify(&newer, &Policies::all()).await.unwrap();
    let qe = qe_identity(&verified);
    assert_eq!((qe.version, qe.from), (Some(21), Source::Attached));
}

#[tokio::test]
async fn an_older_attached_piece_never_replaces_a_newer_cached_one() {
    let dir = tempfile::tempdir().unwrap();
    let (url, body, chain) = intel_with_qe_identity("td_qe_identity_early.json")
        .into_iter()
        .find(|(url, ..)| url.ends_with("/qe/identity"))
        .unwrap();
    crate::collateral::save_to_cache_dir(dir.path(), &url, &body, chain.as_deref());
    let verifier = Verifier::new(
        Context::offline()
            .with_cache_dir(dir.path())
            .at(NOW)
            .unwrap(),
    );
    let older = tdx_with_qe_identity("td_qe_identity_eval21.json").await;
    let verified = verifier.verify(&older, &Policies::all()).await.unwrap();
    let qe = qe_identity(&verified);
    assert_eq!((qe.version, qe.from), (Some(22), Source::Disk));
}

#[cfg(feature = "nvidia-gpu")]
#[tokio::test]
async fn gpu_collateral_is_attached_and_used_without_network() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let quote = read("tdx_quote_00a06d080000.dat");
    let report_data = crate::platforms::tdx::verify::parse_tdx_quote(&quote)
        .unwrap()
        .body
        .report_data
        .to_vec();
    let bundle = crate::types::NvidiaGpuEvidenceBundle {
        devices: vec![crate::types::NvidiaGpuDeviceEvidence {
            arch: crate::types::NvidiaGpuArch::Hopper,
            uuid: "GPU-0".into(),
            evidence_b64: String::new(),
            cert_chain_b64: String::new(),
        }],
        binding: Default::default(),
    };
    let mut envelope: serde_json::Value = serde_json::from_slice(&tdx()).unwrap();
    envelope["nvidia_gpu"] = serde_json::to_value(&bundle).unwrap();
    let envelope = serde_json::to_vec(&envelope).unwrap();

    // NRAS's answer, as NRAS would send it for this nonce, under a key it
    // publishes. The signature is not NVIDIA's: no NVIDIA-signed token is
    // available as a fixture.
    let jwks = read("collateral/2026-10-14/nras_jwks.json");
    let set: serde_json::Value = serde_json::from_slice(&jwks).unwrap();
    let kid = set["keys"][0]["kid"].as_str().unwrap().to_string();
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES384","kid":"{kid}"}}"#));
    let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, NOW + 60));
    let token = format!("{header}.{claims}.{}", URL_SAFE_NO_PAD.encode([0u8; 96]));
    let answer = serde_json::json!([["JWT", token], { "GPU-0": token }]);
    let nonce = hex::encode(crate::platforms::nvidia_gpu::gpu_nonce(
        &report_data,
        &bundle.binding,
    ));
    let nras = crate::platforms::nvidia_gpu::provider::NRAS_GPU_URL;
    let jwks_url = crate::platforms::nvidia_gpu::jwks_url_for_endpoint(nras).unwrap();
    let mut held = vendor_for(&tdx()).await;
    held.push((
        format!("{nras}#nonce={nonce}"),
        serde_json::to_vec(&answer).unwrap(),
        None,
    ));
    held.push((jwks_url.clone(), jwks.clone(), None));

    let mut rotated = held.clone();
    let mut other_keys = set.clone();
    for key in other_keys["keys"].as_array_mut().unwrap() {
        key["kid"] = "unrelated".into();
    }
    rotated.iter_mut().find(|(u, ..)| *u == jwks_url).unwrap().1 =
        serde_json::to_vec(&other_keys).unwrap();
    let partial = Verifier::new(testing::context(rotated))
        .attach_collateral(&envelope, &report_data)
        .await
        .unwrap();
    let partial_envelope: crate::AttestationEvidence = serde_json::from_slice(&partial).unwrap();
    assert!(!partial_envelope
        .collateral
        .iter()
        .any(|c| c.url == jwks_url));
    let partial_policies = Policies {
        gpu: Some(crate::NvidiaGpuParams {
            user_nonce: Some(report_data.clone()),
            ..Default::default()
        }),
        ..Policies::all().with_report_data(&report_data)
    };
    assert!(roots_only(NOW)
        .verify(&partial, &partial_policies)
        .await
        .unwrap_err()
        .is_retryable());

    let attester = Verifier::new(testing::context(held));
    let with = attester
        .attach_collateral(&envelope, &report_data)
        .await
        .unwrap();
    let attached: crate::AttestationEvidence = serde_json::from_slice(&with).unwrap();
    let keys = attached
        .collateral
        .iter()
        .find(|c| c.url == jwks_url)
        .map(|c| serde_json::from_slice::<serde_json::Value>(&c.body).unwrap())
        .unwrap();
    assert_eq!(keys["keys"].as_array().unwrap().len(), 1);
    assert_eq!(keys["keys"][0]["kid"], kid.as_str());

    let policies = Policies {
        gpu: Some(crate::NvidiaGpuParams {
            user_nonce: Some(report_data.clone()),
            ..Default::default()
        }),
        ..Policies::all().with_report_data(&report_data)
    };
    let verifier = roots_only(NOW);
    let err = verifier.verify(&with, &policies).await.unwrap_err();
    assert!(verifier.context().store().missing().is_empty());
    assert!(matches!(err, AttestationError::JwsVerification(_)), "{err}");

    // An attached key set without the tokens' key: not genuine, as a retry
    // gets the same set.
    let mut renamed: serde_json::Value = serde_json::from_slice(&with).unwrap();
    for piece in renamed["collateral"].as_array_mut().unwrap() {
        if piece["url"] == jwks_url.as_str() {
            let mut keys: serde_json::Value =
                serde_json::from_slice(&BASE64.decode(piece["body"].as_str().unwrap()).unwrap())
                    .unwrap();
            keys["keys"][0]["kid"] = "another".into();
            piece["body"] = BASE64.encode(serde_json::to_vec(&keys).unwrap()).into();
        }
    }
    let renamed = serde_json::to_vec(&renamed).unwrap();
    let err = roots_only(NOW)
        .verify(&renamed, &policies)
        .await
        .unwrap_err();
    assert!(!err.is_retryable(), "{err}");
}

#[cfg(feature = "nvidia-gpu")]
#[tokio::test]
async fn an_expired_attached_nras_answer_is_not_used() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let quote = read("tdx_quote_00a06d080000.dat");
    let report_data = crate::platforms::tdx::verify::parse_tdx_quote(&quote)
        .unwrap()
        .body
        .report_data
        .to_vec();
    let bundle = crate::types::NvidiaGpuEvidenceBundle {
        devices: vec![crate::types::NvidiaGpuDeviceEvidence {
            arch: crate::types::NvidiaGpuArch::Hopper,
            uuid: "GPU-0".into(),
            evidence_b64: String::new(),
            cert_chain_b64: String::new(),
        }],
        binding: Default::default(),
    };
    let jwks = read("collateral/2026-10-14/nras_jwks.json");
    let set: serde_json::Value = serde_json::from_slice(&jwks).unwrap();
    let kid = set["keys"][0]["kid"].as_str().unwrap();
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES384","kid":"{kid}"}}"#));
    let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, NOW - 1));
    let token = format!("{header}.{claims}.{}", URL_SAFE_NO_PAD.encode([0u8; 96]));
    let live = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, NOW + 60));
    let overall = format!("{header}.{live}.{}", URL_SAFE_NO_PAD.encode([0u8; 96]));
    let answer = serde_json::json!([["JWT", overall], { "GPU-0": token }]);
    let nonce = hex::encode(crate::platforms::nvidia_gpu::gpu_nonce(
        &report_data,
        &bundle.binding,
    ));
    let nras = crate::platforms::nvidia_gpu::provider::NRAS_GPU_URL;
    let jwks_url = crate::platforms::nvidia_gpu::jwks_url_for_endpoint(nras).unwrap();
    let mut envelope: crate::AttestationEvidence =
        serde_json::from_slice(&attached(&tdx()).await).unwrap();
    envelope.nvidia_gpu = Some(bundle);
    let mut held = envelope.held_collateral();
    held.push((
        format!("{nras}#nonce={nonce}"),
        serde_json::to_vec(&answer).unwrap(),
        None,
    ));
    held.push((jwks_url, jwks, None));
    envelope.attach(held);
    let envelope = serde_json::to_vec(&envelope).unwrap();
    let policies = Policies {
        gpu: Some(crate::NvidiaGpuParams {
            user_nonce: Some(report_data.clone()),
            ..Default::default()
        }),
        ..Policies::all().with_report_data(&report_data)
    };
    // NRAS is asked again, which a verifier without network cannot do.
    let err = roots_only(NOW)
        .verify(&envelope, &policies)
        .await
        .unwrap_err();
    assert!(err.is_retryable(), "{err}");
    // Before its exp the same answer is used (and its forged signature refused).
    let err = roots_only(NOW - 2)
        .verify(&envelope, &policies)
        .await
        .unwrap_err();
    assert!(matches!(err, AttestationError::JwsVerification(_)), "{err}");
}
