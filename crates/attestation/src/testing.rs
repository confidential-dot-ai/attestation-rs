//! Fixtures shared by the unit tests: vendor responses to hold, and a
//! context that holds them.

use crate::context::{Context, HeldResponse};
use crate::platform::Platform;
#[cfg(feature = "snp")]
use crate::types::ProcessorGeneration;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test_data/collateral/");

/// 2026-10-16T00:00:00Z: every fixture piece is current.
pub(crate) const NOW: i64 = 1_792_108_800;

/// A fixture body and its issuer chain.
pub(crate) fn raw(file: &str, chain: Option<&str>) -> (Vec<u8>, Option<String>) {
    let read = |f: &str| std::fs::read(format!("{DIR}{f}")).unwrap();
    (
        read(file),
        chain.map(|c| String::from_utf8(read(c)).unwrap()),
    )
}

fn held(url: String, file: &str, chain: Option<&str>) -> HeldResponse {
    let (body, chain) = raw(file, chain);
    (url, body, chain)
}

/// AMD's CRL for VCEKs of `generation`, issued 2026-09-22.
#[cfg(feature = "snp")]
pub(crate) fn amd_crl(generation: ProcessorGeneration) -> HeldResponse {
    let file = match generation {
        ProcessorGeneration::Milan => "2026-10-14/amd_crl_milan.der",
        ProcessorGeneration::Genoa => "2026-10-14/amd_crl_genoa.der",
        ProcessorGeneration::Turin => "2026-10-14/amd_crl_turin.der",
    };
    let url = <crate::collateral::AmdCrl as crate::collateral::Collateral>::url(&(
        generation,
        crate::collateral::AmdKey::Vcek,
    ));
    held(url, file, None)
}

/// Intel's collateral for every TDX quote in `test_data`: TCB Info for
/// their FMSPCs, issued 2026-10-15; the TD QE Identity and CRLs, issued
/// 2026-10-14.
#[cfg(feature = "tdx")]
pub(crate) fn intel() -> Vec<HeldResponse> {
    use crate::collateral::{Collateral, PckCa, PckCrl, QeIdentity, RootCrl, TcbInfo};
    let chain = Some("2026-10-14/tcb_signing_chain.pem");
    let mut pieces: Vec<HeldResponse> = [
        "00806f050000",
        "00a06d080000",
        "50806f000000",
        "90c06f000000",
        "b0c06f000000",
    ]
    .into_iter()
    .map(|fmspc| {
        let file = format!("2026-10-14/tcb_info_{fmspc}.json");
        let fmspc: crate::collateral::Fmspc = hex::decode(fmspc).unwrap().try_into().unwrap();
        held(TcbInfo::url(&fmspc), &file, chain)
    })
    .collect();
    pieces.extend([
        held(
            QeIdentity::url(&()),
            "2026-10-14/td_qe_identity.json",
            chain,
        ),
        held(
            PckCrl::url(&PckCa::Platform),
            "2026-10-14/pck_crl_platform.der",
            Some("2026-10-14/pck_crl_platform_chain.pem"),
        ),
        held(
            PckCrl::url(&PckCa::Processor),
            "2026-10-14/pck_crl_processor.pem",
            Some("2026-10-14/pck_crl_processor_chain.pem"),
        ),
        held(RootCrl::url(&()), "2026-10-14/root_ca_crl.der", None),
    ]);
    pieces
}

/// A context that holds `responses` and nothing else, at [`NOW`].
pub(crate) fn context(responses: Vec<HeldResponse>) -> Context {
    Context::held(responses).at(NOW).unwrap()
}

/// Validate, gather from `responses` and verify, at [`NOW`].
pub(crate) async fn verify<P: Platform>(
    evidence: &P::Evidence,
    params: &P::Params,
    responses: Vec<HeldResponse>,
) -> crate::Result<P::Result> {
    P::validate(params)?;
    let ctx = context(responses);
    let (collateral, _) = P::gather(evidence, ctx.store(), NOW).await?;
    P::verify(evidence, params, &collateral, NOW)
}
