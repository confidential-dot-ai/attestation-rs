use attestation_api::token::issuer::{PassedVerification, TokenIssuer};

#[test]
fn config_parse_explicit_values() {
    let toml_str = r#"
        [server]
        bind = "0.0.0.0:9000"

        [auth]
        api_keys = ["key1", "key2"]

        [nras]
        gpu_url = "https://nras.example/v3/attest/gpu"

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
    assert_eq!(config.nras.gpu_url, "https://nras.example/v3/attest/gpu");
    assert!(config.token.enabled);
    assert_eq!(config.token.issuer, "my-service");
    assert_eq!(config.token.duration_minutes, 10);
    assert!(config.nras.switch_url.is_empty());
}

#[test]
fn config_rejects_unknown_attestation_platform() {
    let mut config = attestation_api::config::Config::default();
    config.attestation.platforms = vec!["snp".to_string()];
    config.validate().expect("a known platform validates");

    config
        .attestation
        .platforms
        .push("not-a-platform".to_string());
    assert!(config.validate().is_err());
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

    let mut verified_json = serde_json::json!({
        "platform": "snp",
        "claims": {
            "launch_digest": "",
            "report_data": "",
            "signed_data": "",
            "init_data": "",
            "tcb": { "type": "Snp", "bootloader": 0, "tee": 0, "snp": 0, "microcode": 0 },
            "platform_data": {},
        },
        "report_data_match": true,
        "host_data_match": null,
        "launch_digest_match": null,
        "debug": false,
        "allow_debug": false,
        "vmpl": 0,
        "max_vmpl": 0,
        "reported_tcb": { "bootloader": 0, "tee": 0, "snp": 0, "microcode": 0 },
        "min_tcb_met": null,
    });
    let verified: attestation::Verified = serde_json::from_value(verified_json.clone()).unwrap();
    let passed = PassedVerification::new(&verified).expect("verification passed");
    let token = issuer
        .issue(&passed, &attestation::Policies::default())
        .unwrap();

    verified_json["report_data_match"] = false.into();
    let failed: attestation::Verified = serde_json::from_value(verified_json).unwrap();
    assert!(PassedVerification::new(&failed).is_none());

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
    assert_eq!(claims["platform"], "snp");
    assert_eq!(claims["result"]["report_data_match"], true);
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
