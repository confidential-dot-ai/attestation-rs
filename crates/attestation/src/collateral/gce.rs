//! Google's signed launch endorsements for GCE Confidential VM firmware.

use super::{refused, Collateral, Dates};
use crate::error::Result;
use crate::platforms::gcp_endorsement::{check_endorsement, GoldenMeasurement};
use crate::types::PlatformType;

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

/// The endorsement directory Google uses for the platform's TEE.
fn dir(platform: PlatformType) -> &'static str {
    if platform == PlatformType::GcpTdx {
        "tdx"
    } else {
        "sevsnp"
    }
}

impl Collateral for GceEndorsement {
    /// `GcpTdx` or `GcpSnp`, and the launch measurement.
    type Id = (PlatformType, Vec<u8>);

    fn name((platform, m): &Self::Id) -> String {
        let m = &m[..m.len().min(8)];
        format!("gce-endorsement {} {}", dir(*platform), hex::encode(m))
    }

    fn url((platform, measurement): &Self::Id) -> String {
        format!(
            "{GCE_TCB_INTEGRITY}/{}/{}.binarypb",
            dir(*platform),
            hex::encode(measurement)
        )
    }

    /// Signed by Google's `GCE-uefi-signer` under the bundled
    /// GCE-cc-tcb-root, and listing the measurement for the platform's TEE.
    fn verify(bytes: &[u8], _: Option<&str>, (platform, measurement): &Self::Id) -> Result<Self> {
        let (golden, (not_before, not_after)) = check_endorsement(bytes).map_err(refused)?;
        let endorsed = if *platform == PlatformType::GcpTdx {
            golden.tdx.as_ref().is_some_and(|t| t.endorses(measurement))
        } else {
            golden
                .sev_snp
                .as_ref()
                .is_some_and(|s| s.endorses(measurement))
        };
        if !endorsed {
            return Err(refused(format!(
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

    fn dates(&self) -> Dates {
        Dates::window(self.not_before, self.not_after, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TDX: &[u8] = include_bytes!("../../test_data/gcp_tdx/endorsement-c1ee9c16.binarypb");
    const SNP: &[u8] = include_bytes!("../../test_data/gcp_snp/endorsement-0e017d2f.binarypb");
    const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    const MEASUREMENT: &str = "0e017d2fba7c4964575fdd8c770061abf07f0753148d030f94e969a2d1fa5a5747ba0ced9174f2d44b5f6663fa2de00f";

    fn verify(bytes: &[u8], tee: PlatformType, measurement: &str) -> Result<GceEndorsement> {
        GceEndorsement::verify(bytes, None, &(tee, hex::decode(measurement).unwrap()))
    }

    #[test]
    fn an_endorsement_verifies_for_the_measurement_it_lists() {
        let e = verify(TDX, PlatformType::GcpTdx, MRTD).unwrap();
        assert!(e.golden.tdx.is_some());
        // 2026-10-01: inside the signing cert's 2026-05-05..2031-05-05.
        assert!(e.not_before <= 1_790_812_800 && 1_790_812_800 <= e.not_after);
        assert!(e.not_after < 1_938_124_800);
        assert!(verify(SNP, PlatformType::GcpSnp, MEASUREMENT).is_ok());
    }

    #[test]
    fn an_endorsement_for_another_measurement_or_tee_is_refused() {
        assert!(verify(SNP, PlatformType::GcpTdx, MRTD).is_err());
        assert!(verify(TDX, PlatformType::GcpSnp, MRTD).is_err());
        assert!(verify(TDX, PlatformType::GcpSnp, MEASUREMENT).is_err());
    }

    #[test]
    fn a_tampered_or_malformed_endorsement_is_refused() {
        let mut bad = TDX.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        for body in [bad, Vec::new(), TDX[..TDX.len() / 2].to_vec()] {
            assert!(verify(&body, PlatformType::GcpTdx, MRTD).is_err());
        }
    }

    #[test]
    fn the_url_names_the_measurement() {
        assert_eq!(
            GceEndorsement::url(&(PlatformType::GcpSnp, vec![0xab, 0x01])),
            "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/sevsnp/ab01.binarypb"
        );
    }
}
