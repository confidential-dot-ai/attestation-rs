//! The `vtpm` submodule (section 4.4): a paravisor vTPM quote whose
//! attestation key the CPU report binds through the Azure HCL report.
//!
//! Trust chain: the CPU report (verified by its own appraiser) carries
//! `SHA-256(var_data)`; `var_data` carries the AK; the AK signs the TPM quote;
//! the quote carries the nonce in `extraData` and a digest over the PCRs it
//! selected. Only those PCRs are authenticated, so only those become
//! registers, and an envelope listing any other PCR is refused.

use super::vector::evaluate_backing;
use super::{invalid, Ctx, Outcome};
use crate::error::Result;
use crate::platforms::tpm_common::{
    parse_hcl_report, parse_quote_info, verify_tpm_nonce, verify_tpm_pcrs, verify_tpm_signature,
    HCL_REPORT_TYPE_SNP, HCL_REPORT_TYPE_TDX,
};
use crate::profile::{
    AttesterClaims, Backing, Binding, Freshness, ReferenceOutcome, RegisterSource, SubmodAppraisal,
    Tee, TpmAkMethod, TrustVector, VerifiedRegister, VerifierClaims, VtpmClaims, VtpmEvidence,
};
use crate::utils::constant_time_eq;
use std::collections::BTreeMap;

pub(crate) struct VtpmOutcome {
    /// The HCL `var_data`, which the CPU appraiser binds to its report.
    pub var_data: Vec<u8>,
    pub outcome: Outcome,
}

pub(crate) fn appraise(
    v: &VtpmEvidence,
    tee: Tee,
    binding: &Binding,
    ctx: &Ctx<'_>,
) -> Result<VtpmOutcome> {
    let policy = ctx.policy;
    let TpmAkMethod::HclReport = v.cvm_tpm_ak.method;
    let hcl = parse_hcl_report(v.cvm_tpm_ak.data.as_slice())?;
    let expected_type = match tee {
        Tee::SevSnp => HCL_REPORT_TYPE_SNP,
        Tee::Tdx => HCL_REPORT_TYPE_TDX,
        Tee::Cca => return Err(invalid("an HCL report never wraps a CCA token")),
    };
    if hcl.report_type != expected_type {
        return Err(invalid(format!(
            "HCL report type {} does not name the {tee:?} the platform claims",
            hcl.report_type
        )));
    }

    // The AK inside var_data signs the quote; the quote's digest covers the
    // selected PCRs; extraData is the anchor, exactly (section 4.5).
    let quote = &v.cvm_tpm_quote;
    let pcrs: Vec<Vec<u8>> = quote.pcrs.iter().map(|p| p.0.clone()).collect();
    verify_tpm_signature(
        quote.signature.as_slice(),
        quote.message.as_slice(),
        &hcl.var_data,
    )?;
    verify_tpm_pcrs(quote.message.as_slice(), &pcrs)?;
    verify_tpm_nonce(quote.message.as_slice(), &ctx.anchor)?;
    let (selected, _) = parse_quote_info(quote.message.as_slice())?;

    if let Some(log) = &v.cvm_log {
        return Err(invalid(format!(
            "vtpm event log format {:?} cannot be replayed by this release",
            log.format
        )));
    }

    // 7. Registers: the projected PCRs, each inside the signed selection and
    // equal to the quoted value (the parser checked equality; the selection
    // is what makes the value authenticated).
    let mut registers = Vec::with_capacity(v.cvm_registers.len());
    for r in &v.cvm_registers {
        let index = usize::from(r.index);
        if !selected.contains(&index) {
            return Err(invalid(format!(
                "PCR {index} is not in the quote's signed selection; its value is unauthenticated"
            )));
        }
        if !constant_time_eq(r.value.as_slice(), &pcrs[index]) {
            return Err(invalid(format!(
                "PCR {index} differs from the quoted value"
            )));
        }
        registers.push(VerifiedRegister {
            index: r.index,
            alg: r.alg,
            value: r.value.clone(),
            source: RegisterSource::VtpmPcr,
            backing: Backing::PrivilegedService,
            replayed: false,
            owner: None,
            purpose: None,
        });
    }
    registers.sort_by_key(|r| r.index);

    // 9. PCR pins, backing floor, vector.
    let mut pinned = BTreeMap::new();
    for (pcr, expected) in &policy.reference.pcrs {
        let Some(reg) = registers.iter().find(|r| r.index == *pcr) else {
            return Err(invalid(format!(
                "PCR {pcr} is pinned by policy but the evidence carries no such register"
            )));
        };
        let ok = expected.iter().any(|d| {
            d.alg == reg.alg && constant_time_eq(d.value.as_slice(), reg.value.as_slice())
        });
        if !ok {
            return Err(invalid(format!(
                "PCR {pcr} is not among its reference values"
            )));
        }
        pinned.insert(*pcr, true);
    }
    let backing_min = evaluate_backing(policy, &registers)?;
    // Section 5.2: `executables` is what pinned PCRs earn; the hardware,
    // configuration and runtime claims belong to the cpu submodule that
    // binds this AK, so a vtpm with nothing pinned makes no claim.
    let reference = (!pinned.is_empty()).then(|| ReferenceOutcome {
        launch_measurement: None,
        registers: pinned.clone(),
    });
    let vector = TrustVector {
        instance_identity: None,
        configuration: None,
        executables: (!pinned.is_empty()).then_some(2),
        file_system: None,
        hardware: None,
        runtime_opaque: None,
        storage_opaque: None,
        sourced_data: None,
    };
    let claims = VtpmClaims {
        cvm_registers: registers,
        cvm_freshness: Freshness {
            pattern: binding.pattern,
            mode: binding.mode,
            key: binding.key.clone(),
            not_before: None,
            not_after: None,
        },
        cvm_tpm_ak: v.cvm_tpm_ak.clone(),
        compat: BTreeMap::new(),
    };
    Ok(VtpmOutcome {
        var_data: hcl.var_data,
        outcome: Outcome {
            appraisal: SubmodAppraisal {
                ear_status: vector.status(),
                ear_trustworthiness_vector: vector,
                ear_appraisal_policy_ids: vec![crate::profile::PROFILE_URI.to_string()],
                ear_attester_claims: AttesterClaims::Vtpm(Box::new(claims)),
                ear_verifier_claims: VerifierClaims {
                    cvm_collateral: BTreeMap::new(),
                    cvm_reference: reference,
                    cvm_backing_min: backing_min,
                },
            },
            bound: true,
        },
    })
}
