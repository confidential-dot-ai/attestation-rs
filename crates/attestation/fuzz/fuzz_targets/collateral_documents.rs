#![no_main]

use attestation::collateral::{
    AmdCrl, AmdSigner, AmdVcek, Document, GceEndorsement, GceTee, IntelPckCrl, IntelQeIdentity,
    IntelRootCrl, IntelTcbInfo, NrasJwks, PckCa, Raw,
};
use attestation::types::{ProcessorGeneration, SnpTcb};
use libfuzzer_sys::fuzz_target;

const TCB_CHAIN: &str = include_str!("../../test_data/collateral/2026-10-14/tcb_signing_chain.pem");
const PCK_CHAIN: &str =
    include_str!("../../test_data/collateral/2026-10-14/pck_crl_platform_chain.pem");

/// The genuine documents a parser may accept (the seed corpus).
const GENUINE: &[&[u8]] = &[
    include_bytes!("../../test_data/collateral/2026-10-14/amd_crl_milan.der"),
    include_bytes!("../../test_data/collateral/2026-10-14/tcb_info_70a06d070000.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/tcb_info_70a06d070000_early.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/tcb_info_70a06d070000_eval21.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/td_qe_identity.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/td_qe_identity_early.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/td_qe_identity_eval21.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/td_qe_identity_2026-03-16_eval18_expired.json"),
    include_bytes!("../../test_data/collateral/2026-10-14/pck_crl_platform.pem"),
    include_bytes!("../../test_data/collateral/2026-10-14/pck_crl_platform.der"),
    include_bytes!("../../test_data/collateral/2026-10-14/pck_crl_platform_2026-03-16_expired.der"),
    include_bytes!("../../test_data/collateral/2026-10-14/root_ca_crl.der"),
];

/// The bytes are the genuine document, or encode the same signed content:
/// PEM whitespace, JSON whitespace outside the signed body, and the hex case
/// of an Intel signature are not signed.
fn same_signed_content(genuine: &[u8], data: &[u8]) -> bool {
    fn signed(json: &[u8]) -> Option<(String, Vec<u8>)> {
        let v: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_slice(json).ok()?;
        let body = v.get("tcbInfo").or(v.get("enclaveIdentity"))?.get().to_string();
        let sig: String = serde_json::from_str(v.get("signature")?.get()).ok()?;
        Some((body, hex::decode(sig).ok()?))
    }
    let der = |pem_bytes: &[u8]| pem::parse(pem_bytes).ok().map(|p| p.into_contents());
    genuine == data
        || signed(genuine).is_some_and(|g| signed(data) == Some(g))
        || der(genuine).is_some_and(|g| der(data) == Some(g))
}

// Every document parser over the same bytes, with and without a genuine
// issuer chain: none may panic, and none may accept bytes that are not a
// genuine document.
fuzz_target!(|data: &[u8]| {
    let raw = |chain: Option<&str>| Raw {
        body: data.to_vec(),
        issuer_chain: chain.map(str::to_string),
    };
    let tcb = SnpTcb {
        bootloader: 10,
        tee: 0,
        snp: 27,
        microcode: 28,
        fmc: None,
    };
    let refused = [
        AmdVcek {
            generation: ProcessorGeneration::Genoa,
            chip_id: "00".repeat(64),
            tcb,
        }
        .check(&raw(None))
        .is_err(),
        AmdCrl {
            generation: ProcessorGeneration::Milan,
            signer: AmdSigner::Ask,
        }
        .check(&raw(None))
        .is_err(),
        IntelTcbInfo {
            fmspc: "70a06d070000".into(),
        }
        .check(&raw(Some(TCB_CHAIN)))
        .is_err(),
        IntelQeIdentity {}.check(&raw(Some(TCB_CHAIN))).is_err(),
        IntelPckCrl { ca: PckCa::Platform }
            .check(&raw(Some(PCK_CHAIN)))
            .is_err(),
        IntelRootCrl {}.check(&raw(None)).is_err(),
        GceEndorsement {
            tee: GceTee::Tdx,
            measurement: "00".repeat(48),
        }
        .check(&raw(None))
        .is_err(),
    ];
    assert!(
        refused.iter().all(|r| *r) || GENUINE.iter().any(|g| same_signed_content(g, data)),
        "fuzzed bytes were accepted"
    );
    let _ = NrasJwks {}.check(&raw(None));
});
