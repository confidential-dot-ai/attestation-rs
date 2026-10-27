//! A PKCS#8 PEM signing key loads, publishes its public key as the JWKS with
//! the RFC 7638 thumbprint as kid, and signs ES256 tokens that verify against
//! it. The key is generated per run; no private key is checked in.

mod common;

use attestation_api::token::issuer::{PassedVerification, TokenIssuer};
use attestation_api::token::keys::load_or_generate;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use sha2::{Digest, Sha256};
use std::io::Write;

#[test]
fn a_pkcs8_pem_key_publishes_its_jwks_and_signs_verifiable_tokens() {
    let generated = SigningKey::generate();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(generated.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    let key = load_or_generate(file.path().to_str().unwrap()).unwrap();
    let public = *generated.verifying_key();
    assert_eq!(
        *key.verifying_key(),
        public,
        "the file's key is the one loaded"
    );

    let issuer = TokenIssuer::new(key, "iss".into(), std::time::Duration::from_secs(60)).unwrap();

    // The JWKS shape and RFC 7638 thumbprint kid.
    let point = public.to_sec1_point(false);
    let x64 = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y64 = URL_SAFE_NO_PAD.encode(point.y().unwrap());
    let thumbprint = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x64}","y":"{y64}"}}"#);
    let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint.as_bytes()));
    assert_eq!(
        issuer.jwks(),
        serde_json::json!({ "keys": [{
            "kty": "EC", "crv": "P-256", "x": x64, "y": y64,
            "use": "sig", "alg": "ES256", "kid": kid,
        }]}),
    );

    // A token verifies with the key the JWKS publishes.
    let verified: attestation::Verified =
        serde_json::from_value(common::passed_snp_json()).unwrap();
    let token = issuer
        .issue(
            &PassedVerification::new(&verified).unwrap(),
            &attestation::Policies::default(),
        )
        .unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], kid.as_str());
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    assert_eq!(sig.len(), 64, "ES256 is r || s");
    let published = [
        &[0x04][..],
        &URL_SAFE_NO_PAD.decode(&x64).unwrap(),
        &URL_SAFE_NO_PAD.decode(&y64).unwrap(),
    ]
    .concat();
    VerifyingKey::from_sec1_bytes(&published)
        .unwrap()
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_slice(&sig).unwrap(),
        )
        .unwrap();
}

#[test]
fn a_key_file_that_is_not_pkcs8_is_refused() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(b"not a PEM key\n").unwrap();
    assert!(load_or_generate(file.path().to_str().unwrap()).is_err());
}
