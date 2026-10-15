//! Google's signed launch endorsements for GCE Confidential VM firmware.

use super::{Dated, Dates, GceTee, Refused};
use crate::platforms::gcp_endorsement::{check_endorsement, GoldenMeasurement};

const GCE_TCB_INTEGRITY: &str = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm";

/// Google's signed launch endorsement for a GCE firmware build, named by the
/// launch measurement (MRTD or SEV-SNP measurement).
#[derive(Debug, Clone)]
pub struct GceEndorsement {
    pub golden: GoldenMeasurement,
    /// The signing certificate's (and root's) validity.
    pub not_before: i64,
    pub not_after: i64,
}

impl GceEndorsement {
    pub fn url(tee: GceTee, measurement: &[u8]) -> String {
        let dir = match tee {
            GceTee::Tdx => "tdx",
            GceTee::SevSnp => "sevsnp",
        };
        format!(
            "{GCE_TCB_INTEGRITY}/{dir}/{}.binarypb",
            hex::encode(measurement)
        )
    }

    /// Signed by Google's `GCE-uefi-signer` under the bundled
    /// GCE-cc-tcb-root, and listing `measurement` for `tee`.
    pub fn verify(bytes: &[u8], tee: GceTee, measurement: &[u8]) -> Result<Self, Refused> {
        let (golden, (not_before, not_after)) = check_endorsement(bytes)?;
        let endorsed = match tee {
            GceTee::Tdx => golden.tdx.as_ref().is_some_and(|t| t.endorses(measurement)),
            GceTee::SevSnp => golden
                .sev_snp
                .as_ref()
                .is_some_and(|s| s.endorses(measurement)),
        };
        if !endorsed {
            return Err(Refused(format!(
                "does not endorse {}",
                hex::encode(measurement)
            )));
        }
        Ok(Self {
            golden,
            not_before,
            not_after,
        })
    }
}

impl Dated for GceEndorsement {
    fn dates(&self) -> Dates {
        Dates {
            this_update: Some(self.not_before),
            next_update: Some(self.not_after),
            version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TDX: &[u8] = include_bytes!("../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");
    const SNP: &[u8] = include_bytes!("../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");
    const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    const MEASUREMENT: &str = "0e017d2fba7c4964575fdd8c770061abf07f0753148d030f94e969a2d1fa5a5747ba0ced9174f2d44b5f6663fa2de00f";

    fn verify(bytes: &[u8], tee: GceTee, measurement: &str) -> Result<GceEndorsement, Refused> {
        GceEndorsement::verify(bytes, tee, &hex::decode(measurement).unwrap())
    }

    #[test]
    fn an_endorsement_verifies_for_the_measurement_it_lists() {
        let e = verify(TDX, GceTee::Tdx, MRTD).unwrap();
        assert!(e.golden.tdx.is_some());
        // 2026-10-01: inside the signing cert's 2026-05-05..2031-05-05.
        assert!(e.not_before <= 1_790_812_800 && 1_790_812_800 <= e.not_after);
        assert!(e.not_after < 1_938_124_800);
        assert!(verify(SNP, GceTee::SevSnp, MEASUREMENT).is_ok());
    }

    #[test]
    fn an_endorsement_for_another_measurement_or_tee_is_refused() {
        assert!(verify(SNP, GceTee::Tdx, MRTD).is_err());
        assert!(verify(TDX, GceTee::SevSnp, MRTD).is_err());
        assert!(verify(TDX, GceTee::SevSnp, MEASUREMENT).is_err());
    }

    #[test]
    fn a_tampered_or_malformed_endorsement_is_refused() {
        let mut bad = TDX.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        for body in [bad, Vec::new(), TDX[..TDX.len() / 2].to_vec()] {
            assert!(verify(&body, GceTee::Tdx, MRTD).is_err());
        }
    }

    #[test]
    fn the_url_names_the_measurement() {
        assert_eq!(
            GceEndorsement::url(GceTee::SevSnp, &[0xab, 0x01]),
            "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/ab01.binarypb"
        );
    }
}
