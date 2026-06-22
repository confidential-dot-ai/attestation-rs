//! Vendor-precise verification pinning.
//!
//! This example shows how a library caller can pin vendor-specific fields
//! that the canonical anchors don't cover — MRTD and individual RTMRs on TDX,
//! `min_tcb` on SNP. Walk through the structure rather than running it: the
//! evidence loading is left abstract.
//!
//! Run a quick syntax check with:
//!   cargo build --example vendor_pinning

use attestation::{SnpTcb, VendorParams, VerifyParams, VerifySnp, VerifyTdx};

fn _example_tdx_pin(evidence_json: &[u8]) -> attestation::Result<()> {
    // Suppose `pinned_mrtd` and `pinned_rtmrs[1..]` came from a manifest the
    // operator published alongside the workload.
    let pinned_mrtd: [u8; 48] = [0u8; 48];
    let pinned_rtmr1: [u8; 48] = [0u8; 48];
    let pinned_rtmr2: [u8; 48] = [0u8; 48];

    // VerifyTdx is #[non_exhaustive], so external crates build it via Default
    // and then mutate the fields they care about. Internal callers can still
    // use struct literals.
    let mut tdx = VerifyTdx::default();
    tdx.mrtd = Some(pinned_mrtd);
    tdx.rtmrs = [
        None,               // RTMR0 = firmware; not pinning
        Some(pinned_rtmr1), // RTMR1 = OS measurements
        Some(pinned_rtmr2), // RTMR2 = OS measurements
        None,               // RTMR3 = runtime; not pinning at this layer
    ];

    let params = VerifyParams {
        nonce: Some(b"fresh-challenge".to_vec()),
        vendor: VendorParams::Tdx(tdx),
        ..Default::default()
    };

    // The verify_evidence path is async + needs a Tokio runtime in real use.
    // This example only documents the params shape.
    let _ = (evidence_json, params);
    Ok(())
}

fn _example_snp_min_tcb(evidence_json: &[u8]) -> attestation::Result<()> {
    let mut snp = VerifySnp::default();
    snp.min_tcb = Some(SnpTcb {
        bootloader: 4,
        tee: 0,
        snp: 23,
        microcode: 219,
        fmc: None,
    });

    let params = VerifyParams {
        nonce: Some(b"fresh-challenge".to_vec()),
        vendor: VendorParams::Snp(snp),
        ..Default::default()
    };
    let _ = (evidence_json, params);
    Ok(())
}

fn main() {
    eprintln!(
        "This example is a syntax demonstration of the new VendorParams API; \
         see crates/attestation/examples/{{tdx,snp}}.rs for end-to-end runs."
    );
}
