//! Live DCAP verification test - fetches collateral from Intel PCS v4
//! Run: cargo test --test live_dcap --features tdx -- --nocapture

#![cfg(feature = "tdx")]

use attestation::platforms::tdx::verify::parse_tdx_quote;
use attestation::{Context, PlatformResult, Policies, TdxParams, Verifier};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

const V4_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_4.dat");
const LIVE_QUOTE: &[u8] = include_bytes!("../test_data/tdx_quote_live.dat");
const LIVE_CCEL: &[u8] = include_bytes!("../test_data/tdx_ccel_live2.dat");

/// Full DCAP verification with live Intel PCS collateral.
#[tokio::test]
async fn quotes_verify_with_live_pcs_collateral() {
    let verifier = Verifier::new(Context::new());
    for (quote, ccel, allow_debug) in [(V4_QUOTE, None, true), (LIVE_QUOTE, Some(LIVE_CCEL), false)]
    {
        let parsed = parse_tdx_quote(quote).expect("parse quote");
        let envelope = serde_json::json!({
            "platform": "tdx",
            "evidence": {
                "quote": BASE64.encode(quote),
                "cc_eventlog": ccel.map(|c| BASE64.encode(c)),
            },
        });
        let mut policies = Policies::all();
        policies.tdx = Some(TdxParams {
            report_data: Some(parsed.body.report_data.to_vec()),
            allow_debug,
            ..Default::default()
        });
        let verified = verifier
            .verify(envelope.to_string().as_bytes(), &policies)
            .await
            .expect("verifies with PCS collateral");
        #[allow(irrefutable_let_patterns)]
        let PlatformResult::Tdx(r) = verified.platform
        else {
            panic!("not verified as tdx");
        };
        assert_eq!(r.crl_ok, Some(true));
        assert_eq!(r.report_data_match, Some(true));
        assert!(r.tcb_status.is_some());
    }
}
