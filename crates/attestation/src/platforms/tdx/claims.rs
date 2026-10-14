use crate::types::{Claims, TcbInfo};
use crate::utils::strip_trailing_nulls;

use super::verify::TdxQuote;

/// Parse TD attributes bitflags into named booleans.
fn parse_td_attributes(raw: &[u8; 8]) -> serde_json::Value {
    let bits = u64::from_le_bytes(*raw);
    serde_json::json!({
        "debug": bits & (1 << 0) != 0,
        "septve_disable": bits & (1 << 28) != 0,
        "protection_keys": bits & (1 << 30) != 0,
        "key_locker": bits & (1 << 31) != 0,
        "perfmon": bits & (1 << 63) != 0,
    })
}

/// Extract normalized claims from a parsed TDX quote.
pub fn extract_claims(quote: &TdxQuote) -> Claims {
    let mut platform_data = serde_json::json!({
        "quote_version": format!("{:?}", quote.quote_version),
        "tee_type": format!("0x{:x}", quote.header.tee_type),
        "mr_seam": hex::encode(quote.body.mr_seam),
        "mrsigner_seam": hex::encode(quote.body.mrsigner_seam),
        "seam_attributes": hex::encode(quote.body.seam_attributes),
        "td_attributes": hex::encode(quote.body.td_attributes),
        "td_attributes_parsed": parse_td_attributes(&quote.body.td_attributes),
        "xfam": hex::encode(quote.body.xfam),
        "mr_config_id": hex::encode(quote.body.mr_config_id),
        "mr_owner": hex::encode(quote.body.mr_owner),
        "mr_owner_config": hex::encode(quote.body.mr_owner_config),
        "rtmr_0": hex::encode(quote.body.rtmr_0),
        "rtmr_1": hex::encode(quote.body.rtmr_1),
        "rtmr_2": hex::encode(quote.body.rtmr_2),
        "rtmr_3": hex::encode(quote.body.rtmr_3),
    });

    // TDX 1.5 extra fields
    if let Some(svn2) = &quote.body.tee_tcb_svn2 {
        platform_data["tee_tcb_svn2"] = serde_json::Value::String(hex::encode(svn2));
    }
    if let Some(svc) = &quote.body.mr_servicetd {
        platform_data["mr_servicetd"] = serde_json::Value::String(hex::encode(svc));
    }

    Claims {
        launch_digest: hex::encode(quote.body.mr_td),
        report_data: quote.body.report_data.to_vec(),
        signed_data: strip_trailing_nulls(&quote.body.report_data).to_vec(),
        init_data: quote.body.mr_config_id.to_vec(),
        tcb: TcbInfo::Tdx {
            tcb_svn: quote.body.tee_tcb_svn.to_vec(),
        },
        platform_data,
    }
}

#[cfg(test)]
mod tests {
    use super::super::verify::parse_tdx_quote;
    use super::*;

    const V4_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_4.dat");
    const V5_QUOTE: &[u8] = include_bytes!("../../../test_data/tdx_quote_5.dat");

    #[test]
    fn test_claim_extraction_from_v4() {
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        let claims = extract_claims(&quote);

        // launch_digest is hex of mr_td
        assert_eq!(claims.launch_digest, hex::encode(quote.body.mr_td));
        assert!(!claims.launch_digest.is_empty());
        // mr_td starts with 0x70, 0x5e => "705e..."
        assert!(
            claims.launch_digest.starts_with("705e"),
            "launch_digest should start with 705e, got: {}",
            &claims.launch_digest[..8]
        );

        // report_data should be 64 bytes
        assert_eq!(claims.report_data.len(), 64);
        assert_eq!(claims.report_data[0], 0x7c);
        assert_eq!(claims.report_data[1], 0x71);

        // init_data is mr_config_id (48 bytes, all zeroes in v4 fixture)
        assert_eq!(claims.init_data.len(), 48);
        assert!(claims.init_data.iter().all(|&b| b == 0));

        // TCB should be Tdx variant with 16-byte tcb_svn
        match &claims.tcb {
            TcbInfo::Tdx { tcb_svn } => {
                assert_eq!(tcb_svn.len(), 16);
                assert_eq!(tcb_svn[0], 0x03);
                assert_eq!(tcb_svn[2], 0x05);
            }
            other => panic!("expected TcbInfo::Tdx, got: {other:?}"),
        }

        // Platform data checks
        assert_eq!(
            claims.platform_data["quote_version"].as_str().unwrap(),
            "V4"
        );
        assert_eq!(claims.platform_data["tee_type"].as_str().unwrap(), "0x81");

        // RTMR values should be present as hex strings
        let rtmr0 = claims.platform_data["rtmr_0"].as_str().unwrap();
        assert_eq!(rtmr0.len(), 96); // 48 bytes = 96 hex chars
        assert!(rtmr0.starts_with("e940"));

        let rtmr1 = claims.platform_data["rtmr_1"].as_str().unwrap();
        assert_eq!(rtmr1.len(), 96);
        assert!(rtmr1.starts_with("559c"));

        // RTMR 2 and 3 should be all zeroes
        let rtmr2 = claims.platform_data["rtmr_2"].as_str().unwrap();
        assert!(rtmr2.chars().all(|c| c == '0'));

        let rtmr3 = claims.platform_data["rtmr_3"].as_str().unwrap();
        assert!(rtmr3.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_claim_extraction_from_v5() {
        let quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");
        let claims = extract_claims(&quote);

        // launch_digest is hex of mr_td
        assert_eq!(claims.launch_digest, hex::encode(quote.body.mr_td));
        // mr_td starts with 0xdf, 0xba => "dfba..."
        assert!(
            claims.launch_digest.starts_with("dfba"),
            "launch_digest should start with dfba, got: {}",
            &claims.launch_digest[..8]
        );

        // report_data should be 64 bytes
        assert_eq!(claims.report_data.len(), 64);
        assert_eq!(claims.report_data[0], 0x6d);
        assert_eq!(claims.report_data[1], 0x6a);

        // init_data is mr_config_id (48 bytes)
        assert_eq!(claims.init_data.len(), 48);

        // TCB
        match &claims.tcb {
            TcbInfo::Tdx { tcb_svn } => {
                assert_eq!(tcb_svn.len(), 16);
                assert_eq!(tcb_svn[0], 0x05);
                assert_eq!(tcb_svn[1], 0x01);
                assert_eq!(tcb_svn[2], 0x02);
            }
            other => panic!("expected TcbInfo::Tdx, got: {other:?}"),
        }

        // V5 TDX 1.5 quote version
        assert_eq!(
            claims.platform_data["quote_version"].as_str().unwrap(),
            "V5Tdx15"
        );
        assert_eq!(claims.platform_data["tee_type"].as_str().unwrap(), "0x81");
    }

    #[test]
    fn test_v4_v5_claims_have_same_structure() {
        let v4_quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        let v5_quote = parse_tdx_quote(V5_QUOTE).expect("failed to parse v5 quote");

        let v4_claims = extract_claims(&v4_quote);
        let v5_claims = extract_claims(&v5_quote);

        // Both TCBs should be Tdx variant
        assert!(matches!(v4_claims.tcb, TcbInfo::Tdx { .. }));
        assert!(matches!(v5_claims.tcb, TcbInfo::Tdx { .. }));

        // Both should have all expected platform_data keys
        for key in &[
            "quote_version",
            "tee_type",
            "mr_seam",
            "mrsigner_seam",
            "seam_attributes",
            "td_attributes",
            "xfam",
            "mr_config_id",
            "mr_owner",
            "mr_owner_config",
            "rtmr_0",
            "rtmr_1",
            "rtmr_2",
            "rtmr_3",
        ] {
            assert!(
                v4_claims.platform_data.get(*key).is_some(),
                "v4 claims missing key: {key}"
            );
            assert!(
                v5_claims.platform_data.get(*key).is_some(),
                "v5 claims missing key: {key}"
            );
        }
    }

    #[test]
    fn test_td_attributes_parsed_in_claims() {
        let quote = parse_tdx_quote(V4_QUOTE).expect("failed to parse v4 quote");
        let claims = extract_claims(&quote);

        let parsed = &claims.platform_data["td_attributes_parsed"];
        assert!(
            parsed.is_object(),
            "td_attributes_parsed should be an object"
        );
        assert!(parsed.get("debug").is_some(), "should have debug field");
        assert!(parsed.get("septve_disable").is_some());
        assert!(parsed.get("protection_keys").is_some());
        assert!(parsed.get("key_locker").is_some());
        assert!(parsed.get("perfmon").is_some());
    }

    #[test]
    fn test_td_attributes_debug_flag() {
        // Parse raw td_attributes and check debug bit
        let td_attrs: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0]; // bit 0 set = DEBUG
        let parsed = parse_td_attributes(&td_attrs);
        assert_eq!(parsed["debug"], true);
        assert_eq!(parsed["septve_disable"], false);

        // No debug
        let td_attrs_no_debug: [u8; 8] = [0x00, 0, 0, 0, 0, 0, 0, 0];
        let parsed2 = parse_td_attributes(&td_attrs_no_debug);
        assert_eq!(parsed2["debug"], false);
    }
}
