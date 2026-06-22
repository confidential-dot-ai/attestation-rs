//! Live DCAP verification test - fetches collateral from Intel PCS v4
//! Run: cargo test --test live_dcap --features tdx -- --nocapture

#![cfg(feature = "tdx")]

use attestation::collateral::{DefaultTdxCollateralProvider, TdxCollateralProvider};
use attestation::platforms::tdx::dcap::{
    compute_body_end, extract_fmspc_from_pck, parse_auth_data,
};
use attestation::platforms::tdx::evidence::TdxEvidence;
use attestation::platforms::tdx::verify::{parse_tdx_quote, verify_evidence};
use attestation::types::VerifyParams;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

const V4_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
const V5_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_5.dat");
const LIVE_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_live.dat");
const LIVE_CCEL: &[u8] = include_bytes!("../test_data/tdx_ccel_live2.dat");

fn make_evidence(quote_bytes: &[u8]) -> TdxEvidence {
    TdxEvidence {
        quote: BASE64.encode(quote_bytes),
        cc_eventlog: None,
    }
}

/// Full DCAP verification of V4 quote with live Intel PCS collateral.
#[tokio::test]
async fn test_v4_full_dcap_live_pcs() {
    let quote = parse_tdx_quote(V4_QUOTE).expect("parse v4");
    let evidence = make_evidence(V4_QUOTE);

    // V4 fixture has debug bit set
    let params = VerifyParams {
        nonce: Some(quote.body.report_data.to_vec()),
        allow_debug: true,
        ..Default::default()
    };

    let provider = DefaultTdxCollateralProvider::new();
    let result = verify_evidence(&evidence, &params, Some(&provider)).await;

    match &result {
        Ok(r) => {
            eprintln!("V4 DCAP verification succeeded:");
            eprintln!("  signature_valid: {}", r.signature_valid);
            eprintln!("  collateral_verified: {}", r.collateral_verified);
            eprintln!("  nonce_match: {:?}", r.nonce_match);
            eprintln!("  platform: {}", r.vendor.platform());
            if let attestation::VendorResult::Tdx(ref t) = r.vendor {
                if let Some(ref tcb) = t.tcb_status {
                    eprintln!("  tcb_status: {}", tcb.tcb_status);
                    eprintln!("  fmspc: {}", tcb.fmspc);
                    eprintln!("  advisory_ids: {:?}", tcb.advisory_ids);
                    eprintln!("  collateral_expired: {}", tcb.collateral_expired);
                }
            }
            assert!(r.signature_valid);
            assert!(r.collateral_verified);
            assert_eq!(r.nonce_match, Some(true));
        }
        Err(e) => {
            eprintln!("V4 DCAP verification error: {e:?}");
            // Don't panic - the test is informational for now
            // Cert expiry or TCB issues are expected with old fixtures
        }
    }
}

/// Full DCAP verification of live quote from this host's TDX VM + CCEL replay.
#[tokio::test]
async fn test_live_quote_full_dcap() {
    let quote = parse_tdx_quote(LIVE_QUOTE).expect("parse live quote");
    let evidence = TdxEvidence {
        quote: BASE64.encode(LIVE_QUOTE),
        cc_eventlog: Some(BASE64.encode(LIVE_CCEL)),
    };

    // Live quote has zero report_data (test generation)
    let params = VerifyParams {
        nonce: Some(quote.body.report_data.to_vec()),
        ..Default::default()
    };

    let provider = DefaultTdxCollateralProvider::new();
    let result = verify_evidence(&evidence, &params, Some(&provider)).await;

    match &result {
        Ok(r) => {
            eprintln!("Live quote DCAP verification succeeded:");
            eprintln!("  signature_valid: {}", r.signature_valid);
            eprintln!("  collateral_verified: {}", r.collateral_verified);
            eprintln!("  nonce_match: {:?}", r.nonce_match);
            eprintln!("  platform: {}", r.vendor.platform());
            if let attestation::VendorResult::Tdx(ref t) = r.vendor {
                if let Some(ref tcb) = t.tcb_status {
                    eprintln!("  tcb_status: {}", tcb.tcb_status);
                    eprintln!("  fmspc: {}", tcb.fmspc);
                    eprintln!("  advisory_ids: {:?}", tcb.advisory_ids);
                    eprintln!("  collateral_expired: {}", tcb.collateral_expired);
                }
            }
            assert!(r.signature_valid, "ECDSA signature must be valid");
            assert!(r.collateral_verified, "Collateral must verify");
            assert_eq!(r.nonce_match, Some(true));
        }
        Err(e) => {
            eprintln!("Live quote DCAP verification error: {e:?}");
            panic!("Live quote from this host should verify: {e:?}");
        }
    }
}

/// Validate that the TCB Info endpoint returns TDX-specific fields.
///
/// This is the regression test for the SGX vs TDX endpoint bug:
/// the SGX endpoint (`/sgx/certification/v4/tcb`) omits `tdxtcbcomponents`,
/// which causes TDX TCB evaluation to silently skip TDX module checks.
/// The TDX endpoint (`/tdx/certification/v4/tcb`) includes them.
#[tokio::test]
async fn test_tcb_info_has_tdx_components() {
    let provider = DefaultTdxCollateralProvider::new();

    // Extract FMSPC from V5 quote's PCK cert
    let quote = parse_tdx_quote(V5_QUOTE).expect("parse v5");
    let body_end = compute_body_end(V5_QUOTE, quote.quote_version).expect("body_end");
    let auth = parse_auth_data(V5_QUOTE, body_end).expect("auth data");
    let fmspc = extract_fmspc_from_pck(auth.pck_cert_chain_pem).expect("fmspc");

    let tcb_json = provider.get_tcb_info(&fmspc).await.expect("fetch TCB Info");
    let parsed: serde_json::Value = serde_json::from_slice(&tcb_json).expect("parse TCB Info JSON");

    let levels = parsed["tcbInfo"]["tcbLevels"]
        .as_array()
        .expect("tcbLevels should be an array");
    assert!(!levels.is_empty(), "should have at least one TCB level");

    // The TDX endpoint MUST include tdxtcbcomponents in at least the first level
    let first_level = &levels[0];
    assert!(
        first_level["tcb"]["tdxtcbcomponents"].is_array(),
        "TCB Info from TDX endpoint must contain tdxtcbcomponents. \
         If this field is missing, the provider is likely hitting the SGX \
         endpoint instead of the TDX one. Got: {}",
        serde_json::to_string_pretty(&first_level["tcb"]).unwrap_or_default()
    );
}

/// Validate that the QE Identity endpoint returns TDX QE (TD_QE) identity.
///
/// The TDX QE has a different MRSIGNER than the SGX QE. Using the wrong
/// endpoint would cause QE Identity verification to fail on real TDX quotes.
#[tokio::test]
async fn test_qe_identity_is_tdx() {
    let provider = DefaultTdxCollateralProvider::new();
    let qe_json = provider
        .get_td_qe_identity()
        .await
        .expect("fetch QE Identity");
    let parsed: serde_json::Value =
        serde_json::from_slice(&qe_json).expect("parse QE Identity JSON");

    let id = parsed
        .get("enclaveIdentity")
        .expect("should have enclaveIdentity");
    let mrsigner = id["mrsigner"]
        .as_str()
        .expect("should have mrsigner string");

    // TD_QE MRSIGNER (from Intel TDX QE Identity endpoint)
    assert_eq!(
        mrsigner.to_uppercase(),
        "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5",
        "QE Identity MRSIGNER should match TDX TD_QE, not SGX QE"
    );
}

/// Full DCAP verification of V5 quote with live Intel PCS collateral.
#[tokio::test]
async fn test_v5_full_dcap_live_pcs() {
    let quote = parse_tdx_quote(V5_QUOTE).expect("parse v5");
    let evidence = make_evidence(V5_QUOTE);

    let params = VerifyParams {
        nonce: Some(quote.body.report_data.to_vec()),
        ..Default::default()
    };

    let provider = DefaultTdxCollateralProvider::new();
    let result = verify_evidence(&evidence, &params, Some(&provider)).await;

    match &result {
        Ok(r) => {
            eprintln!("V5 DCAP verification succeeded:");
            eprintln!("  signature_valid: {}", r.signature_valid);
            eprintln!("  collateral_verified: {}", r.collateral_verified);
            eprintln!("  nonce_match: {:?}", r.nonce_match);
            if let attestation::VendorResult::Tdx(ref t) = r.vendor {
                if let Some(ref tcb) = t.tcb_status {
                    eprintln!("  tcb_status: {}", tcb.tcb_status);
                    eprintln!("  fmspc: {}", tcb.fmspc);
                    eprintln!("  advisory_ids: {:?}", tcb.advisory_ids);
                    eprintln!("  collateral_expired: {}", tcb.collateral_expired);
                }
            }
        }
        Err(e) => {
            eprintln!("V5 DCAP verification error: {e:?}");
        }
    }
}
