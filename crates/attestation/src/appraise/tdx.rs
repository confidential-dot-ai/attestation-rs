//! Intel TDX `cpu` submodule (section 6), over the primitives in `platforms::tdx`.

use super::inline::InlineCollateral;
use super::resolve_floor;
use super::vector::{cpu_vector, evaluate_backing, evaluate_reference, Assessment};
use super::{invalid, refuse, Ctx, Outcome};
use crate::collateral::TdxCollateralProvider;
use crate::error::{AttestationError, RefusalCode, Result};
use crate::platforms::tdx::dcap;
use crate::platforms::tdx::verify::{parse_tdx_quote, verify_quote_signature};
use crate::profile::cel;
use crate::profile::DebugStatus;
use crate::profile::{
    AttesterClaims, Backing, BindingMode, Bytes, CollateralCheck, CollateralOutcome,
    CollateralStatus, CpuClaims, CpuEvidence, Digest, FixedBytes, Freshness, HashAlg, HostData,
    HostDataSemantics, Identity, LogFormat, Owner, PolicyBits, RegisterSource, SubmodAppraisal,
    Tcb, TdxTcb, VerifiedPlatform, VerifiedRegister, VerifierClaims,
};
use crate::types::TdxTcbStatus;
use crate::utils::constant_time_eq;
use std::collections::BTreeMap;

/// TD attribute bits (TDX Module ABI 348551-007 Table 3.22, standard section
/// 9.2.5). `RESERVED_P` (22:18) may take any value; the reserved mask covers
/// bits 3:1, 15:7, 26:23 and 61:32.
const ATTR_SEPT_VE_DISABLE: u64 = 1 << 28;
const ATTR_MIGRATABLE: u64 = 1 << 29;
const ATTR_RESERVED_MASK: u64 = 0x3FFF_FFFF_0780_FF8E;

fn checked(next_update: Option<String>) -> CollateralOutcome {
    CollateralOutcome {
        status: CollateralStatus::Checked,
        reason: None,
        this_update: None,
        next_update,
        signed: Some(true),
    }
}

fn skipped(reason: &str) -> CollateralOutcome {
    CollateralOutcome {
        status: CollateralStatus::Skipped,
        reason: Some(reason.to_string()),
        this_update: None,
        next_update: None,
        signed: None,
    }
}

fn pcs_next_update(body: &[u8], object: &str) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get(object)?
        .get("nextUpdate")?
        .as_str()
        .map(str::to_string)
}

pub(crate) async fn appraise(
    cpu: &CpuEvidence,
    ctx: &Ctx<'_>,
    collateral: &InlineCollateral<'_>,
) -> Result<Outcome> {
    let policy = ctx.policy;
    let quote_bytes = cpu.cvm_report.value.as_slice();
    crate::utils::check_field_size("cvm_report", quote_bytes.len())?;
    let quote = parse_tdx_quote(quote_bytes)?;

    // 3. Signature, then the DCAP chain to the embedded Intel root.
    verify_quote_signature(quote_bytes, &quote)?;
    dcap::verify_dcap_chain_at(quote_bytes, quote.quote_version, None, ctx.now)?;
    let body_end = dcap::compute_body_end(quote_bytes, quote.quote_version)?;
    let auth = dcap::parse_auth_data(quote_bytes, body_end)?;
    let pck_pem = auth.pck_cert_chain_pem;
    let fmspc = dcap::extract_fmspc_from_pck(pck_pem)?.to_ascii_lowercase();
    // Section 4.2: a hint that contradicts the signed data is an error.
    if let Some(hint) = &cpu.cvm_platform.generation {
        if *hint != fmspc {
            return Err(invalid(format!(
                "cvm_platform.generation {hint:?} contradicts the PCK certificate's FMSPC {fmspc}"
            )));
        }
    }
    let ppid = dcap::extract_ppid_from_pck(pck_pem)?;
    let pck = dcap::pck_tcb_from_pem(pck_pem)?;

    // 4. Guest policy, matching Intel's quote verification policy.
    let attrs = u64::from_le_bytes(quote.body.td_attributes);
    let debug = crate::platforms::tdx::verify::td_attributes_debug(&quote.body.td_attributes);
    // TD attributes are fixed at build, so debug is off since boot or on.
    let dbgstat = if debug {
        DebugStatus::Enabled
    } else {
        DebugStatus::DisabledSinceBoot
    };
    if cpu
        .dbgstat
        .is_some_and(|hint| hint.is_disabled() != dbgstat.is_disabled())
    {
        return Err(invalid("dbgstat contradicts the TD's DEBUG attribute"));
    }
    let sept_ve_disable = attrs & ATTR_SEPT_VE_DISABLE != 0;
    let migratable = attrs & ATTR_MIGRATABLE != 0;
    let reserved_zero = attrs & ATTR_RESERVED_MASK == 0;
    let service_td = quote.body.mr_servicetd.map(|m| m.iter().any(|b| *b != 0));
    let bits = &policy.policy_bits;
    if debug && !bits.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }
    if migratable && !bits.allow_migration {
        return Err(refuse(
            RefusalCode::GuestPolicy,
            "TD is migratable and policy does not allow it",
        ));
    }
    if bits.require_sept_ve_disable && !sept_ve_disable {
        return Err(refuse(
            RefusalCode::GuestPolicy,
            "TD attributes lack SEPT_VE_DISABLE",
        ));
    }
    if bits.require_zero_reserved_attributes && !reserved_zero {
        return Err(refuse(
            RefusalCode::GuestPolicy,
            format!("TD attributes carry reserved bits: {attrs:#018x}"),
        ));
    }
    if service_td == Some(true) && !bits.allow_service_td {
        return Err(refuse(
            RefusalCode::GuestPolicy,
            "a migration service TD is bound and policy does not allow it",
        ));
    }

    // A pin nothing in a TD quote can meet: the ID key is SEV-SNP's.
    if policy.owner.is_some() {
        return Err(refuse(
            RefusalCode::ReferenceMismatch,
            "owner.id_key_digests pins an SEV-SNP ID key, which a TD quote does not carry",
        ));
    }

    if let Some(expected) = &policy.reference.host_data {
        let padded = crate::utils::pad_report_data(expected.as_slice(), 48)?;
        if !constant_time_eq(&quote.body.mr_config_id, &padded) {
            return Err(AttestationError::InitDataMismatch);
        }
    }

    // Identity, floor.
    let (floor, instance_identity) = resolve_floor(policy, &ppid)?;
    let tdx_floor = floor.and_then(|f| f.tdx.as_ref());
    if let Some(min) = tdx_floor.and_then(|f| f.min_tee_tcb_svn.as_ref()) {
        if quote
            .body
            .tee_tcb_svn
            .iter()
            .zip(min.0.iter())
            .any(|(have, want)| have < want)
        {
            return Err(AttestationError::TcbMismatch(
                "TEE TCB SVN is below the policy floor".to_string(),
            ));
        }
    }

    // 6. Collateral: revocation, TCB status, QE identity, each signed.
    let mut outcomes = BTreeMap::new();
    let (status, advisories, hardware) =
        if collateral.tdx().is_some() || collateral.has("tdx.tcb_info") {
            collateral.check_pck_revocation(pck_pem).await?;
            outcomes.insert(CollateralCheck::TdxPckCrl, checked(None));
            outcomes.insert(CollateralCheck::TdxRootCrl, checked(None));
            // Every source (fetched, inline, held, custom) passes through the
            // same binding and shape checks here.
            let root_crl = collateral.get_root_ca_crl().await?;
            let tcb_info = collateral.get_tcb_info(&fmspc).await?;
            let info = dcap::verify_tdx_tcb_info_at(
                &tcb_info.body,
                &tcb_info.signing_chain,
                &root_crl,
                ctx.now,
            )?;
            if info.next_update <= ctx.now {
                return Err(refuse(
                    RefusalCode::CollateralInvalid,
                    "TCB Info nextUpdate has passed",
                ));
            }
            let qe = collateral.get_td_qe_identity().await?;
            let qe_level = dcap::verify_qe_identity_at(
                auth.qe_report_body,
                &qe.body,
                &qe.signing_chain,
                &root_crl,
                ctx.now,
            )?;
            if qe_level.next_update <= ctx.now {
                return Err(refuse(
                    RefusalCode::CollateralInvalid,
                    "QE Identity nextUpdate has passed",
                ));
            }
            let evaluated = dcap::evaluate_tdx_tcb(&info, &quote.body, &pck, &qe_level)?;
            if evaluated.tcb_status == TdxTcbStatus::Revoked {
                return Err(AttestationError::TcbMismatch(
                    "TDX TCB status is Revoked".into(),
                ));
            }
            if !policy
                .tcb
                .tdx_allowed_status
                .contains(&evaluated.tcb_status)
            {
                return Err(AttestationError::TcbMismatch(format!(
                    "TDX TCB status {} is not accepted by policy",
                    evaluated.tcb_status
                )));
            }
            if let Some(min) = tdx_floor.and_then(|f| f.min_tcb_evaluation_data_number) {
                let have = info.tcb_evaluation_data_number;
                if have < min {
                    return Err(AttestationError::TcbMismatch(format!(
                        "tcbEvaluationDataNumber {have} is below the policy floor {min}"
                    )));
                }
            }
            outcomes.insert(
                CollateralCheck::TdxTcbInfo,
                checked(pcs_next_update(&tcb_info.body, "tcbInfo")),
            );
            outcomes.insert(
                CollateralCheck::TdxQeIdentity,
                checked(pcs_next_update(&qe.body, "enclaveIdentity")),
            );
            let hardware = if evaluated.tcb_status == TdxTcbStatus::UpToDate {
                2
            } else {
                32
            };
            (
                Some(evaluated.tcb_status),
                evaluated.advisory_ids,
                Some(hardware),
            )
        } else {
            if policy.tcb.require_revocation || policy.tcb.require_signed_collateral {
                return Err(AttestationError::CertFetchError(
                    "policy requires TDX collateral checks and the verifier has no provider"
                        .to_string(),
                ));
            }
            for check in [
                CollateralCheck::TdxPckCrl,
                CollateralCheck::TdxRootCrl,
                CollateralCheck::TdxTcbInfo,
                CollateralCheck::TdxQeIdentity,
            ] {
                outcomes.insert(
                    check,
                    skipped("no provider and policy does not require collateral"),
                );
            }
            (None, Vec::new(), None)
        };

    // 5. Freshness.
    let bound = match cpu.cvm_binding.mode {
        BindingMode::ReportData => {
            let expected = ctx.expected_report_data();
            if !constant_time_eq(&quote.body.report_data, &expected) {
                return Err(AttestationError::ReportDataMismatch);
            }
            true
        }
        #[cfg(feature = "az-tdx")]
        BindingMode::VtpmExtradata => {
            let var_data = ctx.vtpm_var_data.as_deref().ok_or_else(|| {
                invalid("vtpm-extradata binding without a verified vtpm submodule")
            })?;
            crate::platforms::tpm_common::verify_hcl_var_data_binding(
                &quote.body.report_data,
                var_data,
            )?;
            true
        }
        other => {
            return Err(invalid(format!(
                "binding mode {other:?} on a TDX cpu submodule"
            )))
        }
    };

    // 7. Registers: the RTMRs in the signed quote are authoritative.
    let rtmrs = [
        quote.body.rtmr_0,
        quote.body.rtmr_1,
        quote.body.rtmr_2,
        quote.body.rtmr_3,
    ];
    if let Some(claimed) = &cpu.cvm_registers {
        for r in claimed {
            if r.source != RegisterSource::TdxRtmr
                || usize::from(r.index) >= rtmrs.len()
                || !constant_time_eq(r.value.as_slice(), &rtmrs[usize::from(r.index)])
            {
                return Err(refuse(
                    RefusalCode::RegisterMismatch,
                    format!(
                        "cvm_registers entry {} differs from the signed RTMR",
                        r.index
                    ),
                ));
            }
        }
    }
    // 8. Replay the log when present. The CCEL must reproduce RTMR 0 to 2;
    // RTMR 3 takes runtime extends the firmware log does not carry, and counts
    // as replayed only when every one was logged (the attestation agent's
    // records appended to the CCEL are).
    let mut replayed = [false; 4];
    if let Some(log) = &cpu.cvm_log {
        match log.format {
            LogFormat::TdxCcel => {
                let rtmr3 = crate::platforms::tdx::ccel::verify_ccel_against_rtmrs(
                    log.data.as_slice(),
                    &rtmrs[0],
                    &rtmrs[1],
                    &rtmrs[2],
                    &rtmrs[3],
                )?;
                replayed = [true, true, true, rtmr3];
            }
            LogFormat::TcgCelCbor | LogFormat::TcgCelJson | LogFormat::DstackJson => {
                // Runtime logs replay from zero into the RTMRs they name,
                // which must reproduce the signed values.
                let records = match log.format {
                    LogFormat::TcgCelCbor => cel::parse_cbor(log.data.as_slice())?,
                    LogFormat::TcgCelJson => cel::parse_json(log.data.as_slice())?,
                    _ => cel::parse_dstack_json(log.data.as_slice())?,
                };
                let out = cel::replay(&records, |i| (i < 4).then_some([0u8; 48]), false)?;
                // Every RTMR the log extends must reproduce. One it never
                // extends is accounted for exactly when it is still zero, as
                // the CCEL counts RTMR 3 (section 4.8).
                for (index, rtmr) in rtmrs.iter().enumerate() {
                    let slot = out.slots.get(&(index as u16)).filter(|s| s.extended > 0);
                    replayed[index] = match slot {
                        Some(s) if constant_time_eq(&s.value, rtmr) => true,
                        Some(_) => {
                            return Err(AttestationError::EventlogIntegrityFailed(format!(
                                "RTMR[{index}] does not replay to the signed value"
                            )))
                        }
                        None => rtmr.iter().all(|&b| b == 0),
                    };
                }
            }
            other => {
                return Err(refuse(
                    RefusalCode::Unsupported,
                    format!("event log format {other:?} cannot be replayed by this release"),
                ))
            }
        }
    }
    if !policy.reference.slot_owners.is_empty() {
        return Err(refuse(
            RefusalCode::ReferenceMismatch,
            "policy pins slot owners but a TDX cpu submodule has no workload slots",
        ));
    }
    let registers: Vec<VerifiedRegister> = rtmrs
        .iter()
        .enumerate()
        .map(|(i, v)| VerifiedRegister {
            index: i as u16,
            alg: HashAlg::Sha384,
            value: Bytes(v.to_vec()),
            source: RegisterSource::TdxRtmr,
            backing: Backing::Hardware,
            replayed: replayed[i],
            owner: None,
            purpose: None,
        })
        .collect();

    // 9. References, backing, vector.
    let assessment = Assessment {
        launch_alg: HashAlg::Sha384,
        launch: &quote.body.mr_td,
        registers: &registers,
        hardware,
    };
    let (reference, executables) = evaluate_reference(policy, &assessment)?;
    let backing_min = evaluate_backing(policy, &registers)?;
    let configuration = if debug { 96 } else { 2 };
    let vector = cpu_vector(
        instance_identity,
        executables,
        assessment.hardware,
        configuration,
        debug,
    );

    let mut compat = BTreeMap::new();
    for (name, value) in [
        ("tdx_mrtd", hex::encode(quote.body.mr_td)),
        ("tdx_rtmr0", hex::encode(quote.body.rtmr_0)),
        ("tdx_rtmr1", hex::encode(quote.body.rtmr_1)),
        ("tdx_rtmr2", hex::encode(quote.body.rtmr_2)),
        ("tdx_rtmr3", hex::encode(quote.body.rtmr_3)),
        ("tdx_mrconfigid", hex::encode(quote.body.mr_config_id)),
        ("tdx_mrowner", hex::encode(quote.body.mr_owner)),
        ("tdx_mrownerconfig", hex::encode(quote.body.mr_owner_config)),
        ("tdx_td_attributes", hex::encode(quote.body.td_attributes)),
        ("tdx_tee_tcb_svn", hex::encode(quote.body.tee_tcb_svn)),
        ("tdx_xfam", hex::encode(quote.body.xfam)),
        ("tdx_mrseam", hex::encode(quote.body.mr_seam)),
        ("tdx_mrsignerseam", hex::encode(quote.body.mrsigner_seam)),
    ] {
        compat.insert(name.to_string(), serde_json::Value::String(value));
    }
    let claims = CpuClaims {
        cvm_platform: VerifiedPlatform {
            vendor: cpu.cvm_platform.vendor,
            tee: cpu.cvm_platform.tee,
            generation: Some(fmspc.clone()),
            hosting: cpu.cvm_platform.hosting,
        },
        cvm_launch_measurement: Digest {
            alg: HashAlg::Sha384,
            value: Bytes(quote.body.mr_td.to_vec()),
        },
        cvm_registers: Some(registers),
        cvm_freshness: Freshness {
            pattern: cpu.cvm_binding.pattern,
            mode: cpu.cvm_binding.mode,
            key: cpu.cvm_binding.key.clone(),
            not_before: None,
            not_after: None,
        },
        cvm_host_data: Some(HostData {
            semantics: HostDataSemantics::TdxMrconfigid,
            value: Bytes(quote.body.mr_config_id.to_vec()),
        }),
        cvm_owner: Some(Owner::Tdx {
            mr_owner: FixedBytes(quote.body.mr_owner),
            mr_owner_config: FixedBytes(quote.body.mr_owner_config),
        }),
        cvm_policy: PolicyBits {
            debug,
            migratable,
            smt: None,
            single_socket: None,
            vmpl: None,
            sept_ve_disable: Some(sept_ve_disable),
            service_td,
            reserved_bits_zero: Some(reserved_zero),
        },
        dbgstat,
        cvm_tcb: Tcb::Tdx(Box::new(TdxTcb {
            tee_tcb_svn: FixedBytes(quote.body.tee_tcb_svn),
            pck_tcb: FixedBytes(pck.cpusvn),
            pcesvn: pck.pcesvn,
            fmspc,
            status,
            advisories,
        })),
        cvm_identity: Identity::Tdx {
            ppid: FixedBytes(ppid),
        },
        cvm_chain: None,
        bootseed: None,
        compat,
    };
    let vector_status = vector.status();
    Ok(Outcome {
        appraisal: SubmodAppraisal {
            ear_status: vector_status,
            ear_trustworthiness_vector: vector,
            ear_appraisal_policy_ids: Vec::new(),
            ear_attester_claims: AttesterClaims::Cpu(Box::new(claims)),
            ear_verifier_claims: VerifierClaims {
                cvm_collateral: outcomes,
                cvm_reference: reference,
                cvm_backing_min: backing_min,
                ear_nvidia_evidence: None,
            },
        },
        bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_mask_is_the_abi_reserved_bits() {
        // 3:1, 15:7, 26:23 and 61:32 (TDX Module ABI 348551-007 Table 3.22).
        let reserved = (1..=3).chain(7..=15).chain(23..=26).chain(32..=61);
        let mut mask = 0u64;
        for bit in reserved {
            mask |= 1 << bit;
        }
        assert_eq!(ATTR_RESERVED_MASK, mask);
    }

    #[test]
    fn permitted_attributes_pass_the_reserved_check() {
        // DEBUG and profiling (0, 4 to 6), ICSSD, SERVTD_EXT, RESERVED_P, LASS,
        // SEPT_VE_DISABLE, MIGRATABLE, PKS, KL, TPA, PERFMON.
        for bit in [
            0, 4, 5, 6, 16, 17, 18, 19, 20, 21, 22, 27, 28, 29, 30, 31, 62, 63,
        ] {
            assert_eq!(ATTR_RESERVED_MASK & (1 << bit), 0, "bit {bit}");
        }
        for bit in [1, 2, 3, 7, 15, 23, 26, 32, 61] {
            assert_ne!(ATTR_RESERVED_MASK & (1 << bit), 0, "bit {bit}");
        }
    }
}
