use sev::firmware::guest::AttestationReport;

use crate::types::{Claims, TcbInfo};
use crate::utils::strip_trailing_nulls;

/// Extract normalized claims from a parsed SNP attestation report.
pub fn extract_claims(report: &AttestationReport) -> Claims {
    let platform_data = serde_json::json!({
        "policy": {
            "abi_major": report.policy.abi_major(),
            "abi_minor": report.policy.abi_minor(),
            "smt_allowed": report.policy.smt_allowed(),
            "migrate_ma": report.policy.migrate_ma_allowed(),
            "debug_allowed": report.policy.debug_allowed(),
            "single_socket": report.policy.single_socket_required(),
        },
        "platform_info": {
            "tsme_enabled": report.plat_info.tsme_enabled(),
            "smt_enabled": report.plat_info.smt_enabled(),
        },
        "vmpl": report.vmpl,
        "chip_id": hex::encode(&report.chip_id[..]),
        "current_build": report.current.build,
        "current_minor": report.current.minor,
        "current_major": report.current.major,
        "committed_build": report.committed.build,
        "committed_minor": report.committed.minor,
        "committed_major": report.committed.major,
        "guest_svn": report.guest_svn,
        "signature_algo": report.sig_algo,
    });

    Claims {
        launch_digest: hex::encode(&report.measurement[..]),
        report_data: report.report_data[..].to_vec(),
        signed_data: strip_trailing_nulls(&report.report_data[..]).to_vec(),
        init_data: report.host_data[..].to_vec(),
        tcb: TcbInfo::Snp {
            bootloader: report.reported_tcb.bootloader,
            tee: report.reported_tcb.tee,
            snp: report.reported_tcb.snp,
            microcode: report.reported_tcb.microcode,
            fmc: report.reported_tcb.fmc,
        },
        platform_data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platforms::snp::verify::parse_report;

    const TEST_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-report.bin");
    const TEST_VLEK_REPORT: &[u8] = include_bytes!("../../../test_data/snp/test-vlek-report.bin");

    #[test]
    fn test_claim_extraction_from_real_report() {
        let report = parse_report(TEST_REPORT).expect("failed to parse report");
        let claims = extract_claims(&report);

        // launch_digest should be the hex encoding of the measurement
        assert_eq!(claims.launch_digest, hex::encode(&report.measurement[..]));
        assert_eq!(
            claims.launch_digest,
            "a1f3930413247bb38cfc171579ea3c12d5fe4901f0c792f63fd75d98f1ef827c23500644e0e692e6be917f9050d3d38c"
        );

        // report_data should be the raw 64-byte report_data
        assert_eq!(claims.report_data.len(), 64);
        assert_eq!(claims.report_data[0], 0xec);
        assert_eq!(claims.report_data[1], 0x6c);

        // init_data is host_data (32 bytes, all zeroes in test fixture)
        assert_eq!(claims.init_data.len(), 32);
        assert!(claims.init_data.iter().all(|&b| b == 0));

        // TCB should be SNP variant with correct values
        match &claims.tcb {
            TcbInfo::Snp {
                bootloader,
                tee,
                snp,
                microcode,
                ..
            } => {
                assert_eq!(*bootloader, 3);
                assert_eq!(*tee, 0);
                assert_eq!(*snp, 8);
                assert_eq!(*microcode, 115);
            }
            other => panic!("expected TcbInfo::Snp, got: {other:?}"),
        }

        // Platform data should contain policy fields
        let policy = &claims.platform_data["policy"];
        assert_eq!(policy["abi_minor"], 31);
        assert_eq!(policy["abi_major"], 0);
        assert_eq!(policy["smt_allowed"], true);
        assert_eq!(policy["debug_allowed"], false);
        assert_eq!(policy["migrate_ma"], false);
        assert_eq!(policy["single_socket"], false);

        // Platform info
        let plat_info = &claims.platform_data["platform_info"];
        assert_eq!(plat_info["smt_enabled"], true);
        assert_eq!(plat_info["tsme_enabled"], false);

        // Other platform_data fields
        assert_eq!(claims.platform_data["vmpl"], 0);
        assert_eq!(claims.platform_data["guest_svn"], 4);
        assert_eq!(claims.platform_data["signature_algo"], 1);

        // chip_id should be a valid hex string
        let chip_id_str = claims.platform_data["chip_id"].as_str().unwrap();
        assert_eq!(chip_id_str, "c38427a30d4c7af9d96f7a15b97269825a64cb76a2352ffd5d18115d89ad473f8e8c0bcd9a5d9286612bad4aadfb4426205a3b9e4fea82301135a170e477524e");
    }

    #[test]
    fn test_claim_extraction_from_vlek_report() {
        let report = parse_report(TEST_VLEK_REPORT).expect("failed to parse VLEK report");
        let claims = extract_claims(&report);

        // VLEK report has VMPL=1
        assert_eq!(claims.platform_data["vmpl"], 1);

        // Guest SVN is 0
        assert_eq!(claims.platform_data["guest_svn"], 0);

        // launch_digest should match the VLEK report measurement
        assert_eq!(claims.launch_digest, hex::encode(&report.measurement[..]));
        assert_eq!(
            claims.launch_digest,
            "8922ebbdd00ec2c541f36a6e7a82a8773a7accb451ed67bc94e740dbe92c93c4e8c9af857f5ceeb5a493df2a570d7bf0"
        );
    }
}
