use attestation_api::token::issuer::TokenIssuer;

#[test]
fn config_parse_explicit_values() {
    let toml_str = r#"
        [server]
        bind = "0.0.0.0:9000"

        [auth]
        api_keys = ["key1", "key2"]

        [certs]
        cache_max_entries = 512
        vcek_ttl_hours = 12

        [token]
        enabled = true
        issuer = "my-service"
        duration_minutes = 10

        [attestation]
        enabled = false
    "#;

    let config: attestation_api::config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(config.server.bind, "0.0.0.0:9000");
    assert_eq!(config.auth.api_keys.len(), 2);
    assert!(!config.attestation.enabled);
    assert_eq!(config.certs.cache_max_entries, 512);
    assert_eq!(config.certs.vcek_ttl_hours, 12);
    assert!(config.token.enabled);
    assert_eq!(config.token.issuer, "my-service");
    assert_eq!(config.token.duration_minutes, 10);
    // Omitted fields should be filled with defaults (not asserting specific values)
    assert!(config.certs.chain_ttl_hours > 0);
}

#[test]
fn config_rejects_unknown_attestation_platform() {
    let mut config = attestation_api::config::Config::default();
    config.attestation.platforms = vec!["snp".to_string(), "not-a-platform".to_string()];

    let err = config.validate().unwrap_err();
    assert!(err.contains("unknown platform"));
    assert!(err.contains("not-a-platform"));
}

#[test]
fn token_issuer_produces_valid_jwt() {
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let issuer = TokenIssuer::new(
        signing_key,
        "test-issuer".to_string(),
        std::time::Duration::from_secs(600),
    )
    .unwrap();

    let result = attestation::VerificationResult {
        platform: attestation::PlatformType::Snp,
        signature_valid: true,
        claims: attestation::Claims {
            launch_digest: String::new(),
            report_data: vec![],
            signed_data: vec![],
            init_data: vec![],
            tcb: attestation::TcbInfo::Snp {
                bootloader: 0,
                tee: 0,
                snp: 0,
                microcode: 0,
                fmc: None,
            },
            platform_data: serde_json::json!({}),
        },
        report_data_match: Some(true),
        init_data_match: None,
        collateral_verified: false,
        tcb_status: None,
        mrtd_match: None,
        rtmr0_match: None,
        rtmr1_match: None,
        rtmr2_match: None,
        rtmr3_match: None,
        launch_digest_match: None,
    };

    let token = issuer.issue(&result).unwrap();

    // Decode JWT parts and verify structure + signature
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Verify header
    let header_json: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header_json["alg"], "ES256");
    assert_eq!(header_json["typ"], "JWT");

    // Verify claims
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], "test-issuer");
    assert_eq!(claims["signature_valid"], true);
    assert_eq!(claims["report_data_match"], true);
    assert_eq!(claims["collateral_verified"], false);
    assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());

    // Verify kid in header matches JWKS
    let jwks = issuer.jwks();
    let jwks_kid = jwks["keys"][0]["kid"].as_str().unwrap();
    assert_eq!(
        header_json["kid"].as_str().unwrap(),
        jwks_kid,
        "JWT header kid must match JWKS kid"
    );

    // Verify ES256 signature with the public key
    use p256::ecdsa::{signature::Verifier, Signature};
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    verifying_key
        .verify(message.as_bytes(), &sig)
        .expect("JWT signature must verify against signing key");
}
