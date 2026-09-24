//! The profile path on real hardware: `attest_profile` on the machine, then
//! `appraise` under a policy, on every runner the confidential-e2e workflow
//! reaches. Tests are `#[ignore]`d and named `live_<runner>_*`; the workflow
//! selects them per runner, and a test on the wrong machine fails instead of
//! skipping, because a skipped-green run tests nothing.

#![cfg(all(feature = "attest", target_os = "linux"))]

use std::io::Read;

use attestation::profile::{
    Appraisal, AttesterClaims, Backing, BindingMode, Bytes, CollateralCheck, CollateralStatus,
    CpuClaims, DebugStatus, Digest, Evidence, HashAlg, Hosting, Identity, KeyBinding, KeyKind,
    Submod, Tier, VerifyPolicy, PROFILE_URI,
};
use attestation::{
    AttestOptions, AttestationError, CachePolicy, CollateralCache, DiskStore, Endpoints,
    HttpTimeouts, PlatformType, TdxTcbStatus, Verifier, VerifyParams,
};

/// Every live test on a runner shares one collateral store, so a VCEK is
/// fetched from AMD KDS once per run; KDS answers 429 to repeated fetches.
fn verifier() -> Verifier {
    Verifier::offline().with_collateral(std::sync::Arc::new(CollateralCache::new(
        CachePolicy::default(),
        &HttpTimeouts::default(),
        Endpoints::default(),
        Some(DiskStore::new(
            std::env::temp_dir().join("attestation-live-collateral"),
        )),
    )))
}

fn random(n: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(n);
    std::fs::File::open("/dev/urandom")
        .and_then(|f| f.take(n as u64).read_to_end(&mut buf))
        .expect("read /dev/urandom");
    assert_eq!(buf.len(), n, "short read from /dev/urandom");
    buf
}

/// Fail, never skip, on a machine that is not this test's runner.
fn require(device: &str, platform: PlatformType) {
    assert!(
        std::path::Path::new(device).exists(),
        "{device} is absent: this test belongs on the {platform} runner"
    );
    assert_eq!(
        attestation::detect().expect("detect the platform"),
        platform,
        "this machine is not {platform}"
    );
}

async fn attest(platform: PlatformType, nonce: &[u8], key: Option<KeyBinding>) -> Vec<u8> {
    attestation::attest_profile(platform, nonce, key, false, &AttestOptions::default())
        .await
        .unwrap_or_else(|e| panic!("attest_profile({platform}, {} bytes): {e}", nonce.len()))
}

fn with_nonce(envelope: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(envelope).unwrap();
    v["eat_nonce"] = serde_json::Value::String(Bytes(nonce.to_vec()).encode());
    serde_json::to_vec(&v).unwrap()
}

fn cpu(a: &Appraisal) -> &CpuClaims {
    match &a.submods["cpu"].ear_attester_claims {
        AttesterClaims::Cpu(c) => c,
        other => panic!("the cpu submodule carries {other:?}"),
    }
}

fn show(label: &str, a: &Appraisal) {
    eprintln!("== {label}\n{}", serde_json::to_string_pretty(a).unwrap());
}

fn checked(a: &Appraisal, check: CollateralCheck) {
    let outcome = a.submods["cpu"]
        .ear_verifier_claims
        .cvm_collateral
        .get(&check)
        .unwrap_or_else(|| panic!("no {check:?} outcome"));
    assert_eq!(outcome.status, CollateralStatus::Checked, "{check:?}");
}

/// Every Intel status short of Revoked, for a host whose TCB lags.
fn any_tdx_status(mut p: VerifyPolicy) -> VerifyPolicy {
    p.tcb.tdx_allowed_status = vec![
        TdxTcbStatus::UpToDate,
        TdxTcbStatus::SWHardeningNeeded,
        TdxTcbStatus::ConfigurationNeeded,
        TdxTcbStatus::ConfigurationAndSWHardeningNeeded,
        TdxTcbStatus::OutOfDate,
        TdxTcbStatus::OutOfDateConfigurationNeeded,
    ];
    p
}

/// What every platform shares: a key binding reaches the result, another
/// eat_nonce is refused, and the pre-profile envelope still works both ways.
async fn common(platform: PlatformType, verifier: &Verifier, policy: &VerifyPolicy, n: usize) {
    let nonce = random(n);
    let key = KeyBinding {
        kind: KeyKind::SpkiSha256,
        value: Bytes(random(32)),
    };
    let envelope = attest(platform, &nonce, Some(key.clone())).await;
    let a = verifier
        .appraise_json(&envelope, policy)
        .await
        .expect("key-bound evidence appraises");
    assert_eq!(cpu(&a).cvm_freshness.key.as_ref(), Some(&key));

    let err = verifier
        .appraise_json(&with_nonce(&envelope, &random(n)), policy)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AttestationError::ReportDataMismatch),
        "another eat_nonce must fail the binding: {err}"
    );

    let legacy = attestation::attest(platform, &nonce, &AttestOptions::default())
        .await
        .expect("attest the old envelope");
    verifier
        .appraise_legacy_json(&legacy, &nonce, None, policy)
        .await
        .expect("the old envelope appraises through section 9");
    let old = verifier
        .verify(
            &legacy,
            &VerifyParams {
                expected_report_data: Some(nonce.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("the old verify path");
    assert!(old.signature_valid);
    assert_eq!(old.report_data_match, Some(true));
}

#[tokio::test]
#[ignore = "needs the SEV-SNP metal runner"]
async fn live_snp_metal_profile() {
    require("/dev/sev-guest", PlatformType::Snp);
    let verifier = verifier();
    let strict = VerifyPolicy::default();

    let nonce = random(32);
    let envelope = attest(PlatformType::Snp, &nonce, None).await;
    let evidence = Evidence::from_json(&envelope).expect("the envelope parses");
    assert_eq!(evidence.eat_profile, PROFILE_URI);
    assert_eq!(evidence.eat_nonce.as_slice(), nonce.as_slice());
    let a = verifier
        .appraise(&evidence, &strict)
        .await
        .expect("strict defaults accept the SNP metal runner");
    show("snp metal, strict defaults", &a);
    assert!(a.ear_all_submods_bound.is_true());
    assert_ne!(a.submods["cpu"].ear_status, Tier::Contraindicated);
    let c = cpu(&a);
    assert_eq!(c.cvm_freshness.mode, BindingMode::ReportData);
    assert!(matches!(c.cvm_identity, Identity::Snp { .. }));
    assert!(c.cvm_platform.generation.is_some());
    assert_eq!(c.dbgstat, DebugStatus::DisabledSinceBoot);
    checked(&a, CollateralCheck::SnpCrl);

    // The gate's width: a 64-byte nonce fills report_data exactly.
    let wide = attest(PlatformType::Snp, &random(64), None).await;
    verifier
        .appraise_json(&wide, &strict)
        .await
        .expect("a 64-byte nonce appraises");

    common(PlatformType::Snp, &verifier, &strict, 32).await;
}

#[tokio::test]
#[ignore = "needs the TDX metal runner"]
async fn live_tdx_metal_profile() {
    require("/dev/tdx_guest", PlatformType::Tdx);
    let verifier = verifier();

    let nonce = random(32);
    let envelope = attest(PlatformType::Tdx, &nonce, None).await;
    let evidence = Evidence::from_json(&envelope).expect("the envelope parses");
    let Some(Submod::Cpu(carried)) = evidence.submods.get("cpu") else {
        panic!("no cpu submodule")
    };
    assert!(
        carried.cvm_log.is_some(),
        "the TDX runner exposes its CCEL, so the envelope must carry it"
    );

    // Strict defaults may refuse the host's Intel TCB status and nothing else.
    match verifier.appraise(&evidence, &VerifyPolicy::default()).await {
        Ok(a) => show("tdx metal, strict defaults", &a),
        Err(AttestationError::TcbMismatch(m)) => {
            eprintln!("strict defaults refuse the host TCB: {m}")
        }
        Err(e) => panic!("strict defaults refused for a reason other than the TCB status: {e}"),
    }
    let policy = any_tdx_status(VerifyPolicy::default());
    let a = verifier
        .appraise(&evidence, &policy)
        .await
        .expect("any non-revoked status accepts the TDX metal runner");
    show("tdx metal, any non-revoked status", &a);
    assert!(a.ear_all_submods_bound.is_true());
    let c = cpu(&a);
    assert_eq!(c.cvm_freshness.mode, BindingMode::ReportData);
    assert!(matches!(c.cvm_identity, Identity::Tdx { .. }));
    let replayed: Vec<bool> = c
        .cvm_registers
        .as_ref()
        .expect("RTMRs")
        .iter()
        .map(|r| r.replayed)
        .collect();
    assert_eq!(
        replayed,
        [true, true, true, false],
        "the CCEL replays RTMR 0 to 2"
    );
    for check in [
        CollateralCheck::TdxPckCrl,
        CollateralCheck::TdxRootCrl,
        CollateralCheck::TdxTcbInfo,
        CollateralCheck::TdxQeIdentity,
    ] {
        checked(&a, check);
    }

    let wide = attest(PlatformType::Tdx, &random(64), None).await;
    verifier
        .appraise_json(&wide, &policy)
        .await
        .expect("a 64-byte nonce appraises");

    common(PlatformType::Tdx, &verifier, &policy, 32).await;
}

/// The launch measurement of the envelope's hardware report, as a pin.
fn launch_pin(evidence: &Evidence) -> Digest {
    let Some(Submod::Cpu(cpu)) = evidence.submods.get("cpu") else {
        panic!("cpu submodule")
    };
    let raw = cpu.cvm_report.value.as_slice();
    let value = if cpu.cvm_platform.tee == attestation::profile::Tee::Tdx {
        attestation::platforms::tdx::verify::parse_tdx_quote(raw)
            .unwrap()
            .body
            .mr_td
            .to_vec()
    } else {
        attestation::platforms::snp::verify::parse_report(raw)
            .unwrap()
            .measurement
            .to_vec()
    };
    Digest {
        alg: HashAlg::Sha384,
        value: Bytes(value),
    }
}

async fn azure(platform: PlatformType, mut policy: VerifyPolicy) {
    let verifier = verifier();
    let nonce = random(32);
    let envelope = attest(platform, &nonce, None).await;
    let evidence = Evidence::from_json(&envelope).expect("the envelope parses");
    assert!(evidence.submods.contains_key("vtpm"));

    // Section 9.4.4: without the paravisor pinned, vtpm-extradata is refused.
    let err = verifier
        .appraise(&evidence, &VerifyPolicy::default())
        .await
        .unwrap_err();
    assert_eq!(
        err.refusal_code(),
        Some(attestation::RefusalCode::BindingMismatch),
        "{err}"
    );
    // Pinned, strict defaults refuse the vTPM's privileged-service registers.
    let pin = launch_pin(&evidence);
    policy.reference.launch_measurement = vec![pin.clone()];
    let mut strict = VerifyPolicy::default();
    strict.reference.launch_measurement = vec![pin.clone()];
    let err = verifier.appraise(&evidence, &strict).await.unwrap_err();
    assert!(
        err.to_string().contains("backed by"),
        "strict defaults on Azure should refuse the vTPM backing: {err}"
    );
    // With only the backing relaxed, report what Intel says of the host.
    let mut backing_only = VerifyPolicy {
        min_backing: Backing::PrivilegedService,
        ..Default::default()
    };
    backing_only.reference.launch_measurement = vec![pin];
    match verifier.appraise(&evidence, &backing_only).await {
        Ok(_) => eprintln!("default TCB policy accepts {platform}"),
        Err(e) => eprintln!("default TCB policy refuses {platform}: {e}"),
    }

    let a = verifier
        .appraise(&evidence, &policy)
        .await
        .expect("the Azure runner policy accepts");
    show(&format!("{platform}"), &a);
    assert!(a.ear_all_submods_bound.is_true());
    let c = cpu(&a);
    assert_eq!(c.cvm_freshness.mode, BindingMode::VtpmExtradata);
    assert_eq!(c.cvm_platform.hosting, Hosting::Azure);
    let AttesterClaims::Vtpm(v) = &a.submods["vtpm"].ear_attester_claims else {
        panic!("vtpm claims")
    };
    assert!(!v.cvm_registers.is_empty());
    assert!(v
        .cvm_registers
        .iter()
        .all(|r| r.backing == Backing::PrivilegedService));
    assert_eq!(a.submods["vtpm"].ear_status, Tier::None);

    // A matching PCR pin earns executables; a wrong one fails.
    let pcr0 = v
        .cvm_registers
        .iter()
        .find(|r| r.index == 0)
        .expect("PCR 0")
        .value
        .clone();
    let mut pinned = policy.clone();
    pinned.reference.pcrs.insert(
        0,
        vec![Digest {
            alg: HashAlg::Sha256,
            value: pcr0,
        }],
    );
    // PCR pins earn executables only beside the launch measurement pin.
    pinned.reference.launch_measurement = vec![Digest {
        alg: c.cvm_launch_measurement.alg,
        value: c.cvm_launch_measurement.value.clone(),
    }];
    let a = verifier
        .appraise(&evidence, &pinned)
        .await
        .expect("a matching PCR pin");
    assert_eq!(
        a.submods["vtpm"].ear_trustworthiness_vector.executables,
        Some(2)
    );
    pinned.reference.pcrs.insert(
        0,
        vec![Digest {
            alg: HashAlg::Sha256,
            value: Bytes(vec![0; 32]),
        }],
    );
    assert!(verifier.appraise(&evidence, &pinned).await.is_err());

    // The anchor rides in the TPM quote's qualifying data: 50 bytes fit.
    let fifty = attest(platform, &random(50), None).await;
    verifier
        .appraise_json(&fifty, &policy)
        .await
        .expect("a 50-byte nonce appraises");
    match attestation::attest_profile(
        platform,
        &random(64),
        None,
        false,
        &AttestOptions::default(),
    )
    .await
    {
        Ok(env) => {
            eprintln!("a 64-byte nonce attests on {platform}");
            verifier
                .appraise_json(&env, &policy)
                .await
                .expect("a 64-byte nonce that attests must appraise");
        }
        Err(e) => {
            eprintln!("a 64-byte nonce is refused on {platform}: {e}");
            assert!(
                matches!(e, AttestationError::ReportDataTooLarge { max: 50 }),
                "refused before the TPM, with the limit: {e}"
            );
        }
    }

    common(platform, &verifier, &policy, 32).await;
}

#[tokio::test]
#[ignore = "needs the Azure SEV-SNP runner"]
async fn live_azure_snp_profile() {
    require("/dev/tpmrm0", PlatformType::AzSnp);
    azure(
        PlatformType::AzSnp,
        VerifyPolicy {
            min_backing: Backing::PrivilegedService,
            ..Default::default()
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "needs the Azure TDX runner"]
async fn live_azure_tdx_profile() {
    require("/dev/tpmrm0", PlatformType::AzTdx);
    azure(
        PlatformType::AzTdx,
        any_tdx_status(VerifyPolicy {
            min_backing: Backing::PrivilegedService,
            ..Default::default()
        }),
    )
    .await;
}
