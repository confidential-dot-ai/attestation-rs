//! Fixtures shared by the unit tests: vendor documents to hold, and a
//! context that holds them.

#[cfg(feature = "snp")]
use crate::collateral::{AmdCrl, AmdSigner};
use crate::collateral::{DocKey, Raw};
#[cfg(feature = "tdx")]
use crate::collateral::{IntelPckCrl, IntelQeIdentity, IntelRootCrl, IntelTcbInfo, PckCa};
use crate::context::Context;
use crate::platform::Platform;
#[cfg(feature = "snp")]
use crate::types::ProcessorGeneration;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/collateral/");

/// 2026-10-16T00:00:00Z: every fixture document is current.
pub(crate) const NOW: i64 = 1_792_108_800;

pub(crate) fn raw(file: &str, chain: Option<&str>) -> Raw {
    let read = |f: &str| std::fs::read(format!("{DIR}{f}")).unwrap();
    Raw {
        body: read(file),
        issuer_chain: chain.map(|c| String::from_utf8(read(c)).unwrap()),
    }
}

/// AMD's CRL for VCEKs of `generation`, issued 2026-09-22.
#[cfg(feature = "snp")]
pub(crate) fn amd_crl(generation: ProcessorGeneration) -> (DocKey, Raw) {
    let file = match generation {
        ProcessorGeneration::Milan => "2026-10-14/amd_crl_milan.der",
        ProcessorGeneration::Genoa => "2026-10-14/amd_crl_genoa.der",
        ProcessorGeneration::Turin => "2026-10-14/amd_crl_turin.der",
    };
    let key = AmdCrl {
        generation,
        signer: AmdSigner::Ask,
    };
    (key.into(), raw(file, None))
}

/// Intel's collateral for every TDX quote in `test_data`: TCB Info for
/// their FMSPCs, issued 2026-10-15; the TD QE Identity and CRLs, issued
/// 2026-10-14.
#[cfg(feature = "tdx")]
pub(crate) fn intel() -> Vec<(DocKey, Raw)> {
    let chain = Some("2026-10-14/tcb_signing_chain.pem");
    let mut docs: Vec<(DocKey, Raw)> = [
        "00806f050000",
        "00a06d080000",
        "50806f000000",
        "90c06f000000",
        "b0c06f000000",
    ]
    .into_iter()
    .map(|fmspc| {
        let file = format!("2026-10-14/tcb_info_{fmspc}.json");
        let key = IntelTcbInfo {
            fmspc: fmspc.into(),
        };
        (key.into(), raw(&file, chain))
    })
    .collect();
    docs.extend([
        (
            IntelQeIdentity {}.into(),
            raw("2026-10-14/td_qe_identity.json", chain),
        ),
        (
            IntelPckCrl {
                ca: PckCa::Platform,
            }
            .into(),
            raw(
                "2026-10-14/pck_crl_platform.der",
                Some("2026-10-14/pck_crl_platform_chain.pem"),
            ),
        ),
        (
            IntelPckCrl {
                ca: PckCa::Processor,
            }
            .into(),
            raw(
                "2026-10-14/pck_crl_processor.pem",
                Some("2026-10-14/pck_crl_processor_chain.pem"),
            ),
        ),
        (
            IntelRootCrl {}.into(),
            raw("2026-10-14/root_ca_crl.der", None),
        ),
    ]);
    docs
}

/// A context that holds `documents` and nothing else, at [`NOW`].
pub(crate) fn context(documents: Vec<(DocKey, Raw)>) -> Context {
    Context::held(documents).at(NOW).unwrap()
}

/// Validate, gather from `documents` and verify, at [`NOW`].
pub(crate) async fn verify<P: Platform>(
    evidence: &P::Evidence,
    params: &P::Params,
    documents: Vec<(DocKey, Raw)>,
) -> crate::Result<P::Result> {
    P::validate(params)?;
    let ctx = context(documents);
    let collateral = P::gather(evidence, ctx.store(), NOW).await?;
    P::verify(evidence, params, &collateral, NOW)
}
