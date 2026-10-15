//! Google's signed launch endorsements for GCE Confidential VM firmware.

use super::document::{Document, GceEndorsement, GceTee, Info, Raw};
use crate::platforms::gcp_endorsement::{check_endorsement, GoldenMeasurement};

impl Document for GceEndorsement {
    type Value = GoldenMeasurement;

    /// Signed by Google's `GCE-uefi-signer` under the bundled
    /// GCE-cc-tcb-root, and listing this measurement. Valid while the signing
    /// cert and the root are.
    fn check(&self, raw: &Raw) -> Result<(GoldenMeasurement, Info), String> {
        let (golden, (not_before, not_after)) = check_endorsement(&raw.body)?;
        let measurement =
            hex::decode(&self.measurement).map_err(|e| format!("measurement: {e}"))?;
        let endorsed = match self.tee {
            GceTee::Tdx => golden
                .tdx
                .as_ref()
                .is_some_and(|t| t.endorses(&measurement)),
            GceTee::SevSnp => golden
                .sev_snp
                .as_ref()
                .is_some_and(|s| s.endorses(&measurement)),
        };
        if !endorsed {
            return Err(format!("does not endorse {}", self.measurement));
        }
        Ok((
            golden,
            Info {
                this_update: Some(not_before),
                next_update: Some(not_after),
                version: None,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::document::Freshness;

    const TDX: &[u8] = include_bytes!("../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");
    const SNP: &[u8] = include_bytes!("../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");
    const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    const MEASUREMENT: &str = "0e017d2fba7c4964575fdd8c770061abf07f0753148d030f94e969a2d1fa5a5747ba0ced9174f2d44b5f6663fa2de00f";

    fn raw(body: &[u8]) -> Raw {
        Raw {
            body: body.to_vec(),
            issuer_chain: None,
        }
    }

    fn key(tee: GceTee, measurement: &str) -> GceEndorsement {
        GceEndorsement {
            tee,
            measurement: measurement.into(),
        }
    }

    #[test]
    fn an_endorsement_checks_for_the_measurement_it_lists() {
        let (golden, info) = key(GceTee::Tdx, MRTD).check(&raw(TDX)).unwrap();
        assert!(golden.tdx.is_some());
        // 2026-10-01: inside the signing cert's 2026-05-05..2031-05-05.
        assert_eq!(info.freshness(1_790_812_800), Freshness::Current);
        assert_eq!(info.freshness(1_938_124_800), Freshness::Expired);
        assert!(key(GceTee::SevSnp, MEASUREMENT).check(&raw(SNP)).is_ok());
    }

    #[test]
    fn an_endorsement_for_another_measurement_or_tee_is_refused() {
        assert!(key(GceTee::Tdx, MRTD).check(&raw(SNP)).is_err());
        assert!(key(GceTee::SevSnp, MRTD).check(&raw(TDX)).is_err());
        assert!(key(GceTee::SevSnp, MEASUREMENT).check(&raw(TDX)).is_err());
    }

    #[test]
    fn a_tampered_or_malformed_endorsement_is_refused() {
        let mut bad = TDX.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        for body in [bad, Vec::new(), TDX[..TDX.len() / 2].to_vec()] {
            assert!(key(GceTee::Tdx, MRTD).check(&raw(&body)).is_err());
        }
    }
}
