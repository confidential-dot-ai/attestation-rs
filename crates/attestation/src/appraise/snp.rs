//! SEV-SNP `cpu` submodule (section 6), over the primitives in `platforms::snp`.

use super::inline::InlineCollateral;
use super::vector::{cpu_vector, evaluate_backing, evaluate_reference, resolve_floor, Assessment};
use super::{invalid, Ctx, Outcome};
use crate::collateral::CertProvider;
use crate::error::{AttestationError, Result};
use crate::platforms::snp::verify::{
    check_vcek_not_revoked, enforce_min_tcb, is_vlek_cert, parse_report, verify_cert_chain,
    verify_vcek_tcb, verify_vek_validity_period, MAX_REPORT_VERSION, MIN_REPORT_VERSION,
};
use crate::profile::registers::{commit, report_data as commitment_report_data, REG_COUNT};
use crate::profile::{
    AttesterClaims, Backing, BindingMode, Bytes, CollateralCheck, CollateralOutcome,
    CollateralStatus, CpuClaims, CpuEvidence, Digest, FixedBytes, Freshness, HashAlg, HostData,
    HostDataSemantics, Identity, Owner, PolicyBits, RegisterSource, SnpTcbSet, SubmodAppraisal,
    Tcb, VerifiedPlatform, VerifiedRegister, VerifierClaims,
};
use crate::types::{ProcessorGeneration, SnpTcb};
use crate::utils::constant_time_eq;
use sev::certs::snp::{Certificate, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use std::collections::BTreeMap;

fn tcb(v: &TcbVersion) -> SnpTcb {
    SnpTcb {
        bootloader: v.bootloader,
        tee: v.tee,
        snp: v.snp,
        microcode: v.microcode,
        fmc: v.fmc,
    }
}

fn generation(report: &AttestationReport) -> Result<ProcessorGeneration> {
    let (fam, model) = match (report.cpuid_fam_id, report.cpuid_mod_id) {
        (Some(f), Some(m)) => (f, m),
        _ if report.version >= 3 => {
            return Err(AttestationError::QuoteParseFailed(
                "v3+ SNP report missing CPUID family or model".to_string(),
            ))
        }
        _ => (0, 0),
    };
    ProcessorGeneration::from_cpuid(fam, model).ok_or_else(|| {
        AttestationError::QuoteParseFailed(format!(
            "unknown processor: family=0x{fam:02X}, model=0x{model:02X}"
        ))
    })
}

pub(crate) async fn appraise(
    cpu: &CpuEvidence,
    ctx: &Ctx<'_>,
    collateral: &InlineCollateral<'_>,
) -> Result<Outcome> {
    let policy = ctx.policy;
    let report_bytes = cpu.cvm_report.value.as_slice();
    crate::utils::check_field_size("cvm_report", report_bytes.len())?;
    let report = parse_report(report_bytes)?;
    if report.version < MIN_REPORT_VERSION || report.version > MAX_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: MIN_REPORT_VERSION,
            max: MAX_REPORT_VERSION,
        });
    }
    let generation = generation(&report)?;

    // 3. Hardware chain and signature.
    let reported = tcb(&report.reported_tcb);
    let vek_der = if collateral.has("snp.vek") || !report.chip_id.iter().all(|&b| b == 0) {
        collateral
            .get_snp_vcek(generation, &report.chip_id, &reported)
            .await?
    } else {
        return Err(AttestationError::CertFetchError(
            "chip_id is masked (all zero) and the envelope carries no VEK".to_string(),
        ));
    };
    let is_vlek = is_vlek_cert(&vek_der)?;
    let ark_der = crate::platforms::snp::certs::get_ark(generation);
    let intermediate = if is_vlek {
        crate::platforms::snp::certs::get_asvk(generation)
    } else {
        crate::platforms::snp::certs::get_ask(generation)
    };
    verify_cert_chain(ark_der, intermediate, &vek_der)?;
    verify_vek_validity_period(&vek_der)?;
    let mut collateral_outcomes = BTreeMap::new();
    match collateral.get_snp_crl(generation).await? {
        Some(crl) => {
            check_vcek_not_revoked(&vek_der, &crl, ark_der)?;
            collateral_outcomes.insert(
                CollateralCheck::SnpCrl,
                CollateralOutcome {
                    status: CollateralStatus::Checked,
                    reason: None,
                    this_update: None,
                    next_update: None,
                    signed: Some(true),
                },
            );
        }
        None if policy.tcb.require_revocation => {
            return Err(AttestationError::CertFetchError(
                "policy requires revocation checking and no SNP CRL is available".to_string(),
            ))
        }
        None => {
            collateral_outcomes.insert(
                CollateralCheck::SnpCrl,
                CollateralOutcome {
                    status: CollateralStatus::Skipped,
                    reason: Some("no CRL available and policy does not require one".to_string()),
                    this_update: None,
                    next_update: None,
                    signed: None,
                },
            );
        }
    }
    let vek = Certificate::from_der(&vek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK to sev Certificate: {e}")))?;
    (&vek, &report)
        .verify()
        .map_err(|e| AttestationError::SignatureVerificationFailed(format!("{e}")))?;
    verify_vcek_tcb(&report, &vek_der, generation)?;

    // 4. Guest policy.
    if policy.policy_bits.require_vmpl0 && report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(report.vmpl));
    }
    let debug = report.policy.debug_allowed();
    if debug && !policy.policy_bits.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }
    let migratable = report.policy.migrate_ma_allowed();
    if migratable && !policy.policy_bits.allow_migration {
        return Err(invalid("guest policy allows migration and policy does not"));
    }
    if let Some(owner) = &policy.owner {
        if !owner
            .id_key_digests
            .iter()
            .any(|d| constant_time_eq(&d.0, &report.id_key_digest))
        {
            return Err(invalid(
                "id_key_digest is not among the owner keys policy accepts",
            ));
        }
    }

    // Identity, floor.
    let (floor, instance_identity) = resolve_floor(policy, &report.chip_id)?;
    if let Some(min) = floor.and_then(|f| f.snp.as_ref()) {
        enforce_min_tcb(&report.reported_tcb, min)?;
    }

    // 5 and 7. Freshness, and the registers it establishes in commitment mode.
    let mut registers: Vec<VerifiedRegister> = Vec::new();
    let mut chain = None;
    let mut bootseed = None;
    let bound = match cpu.cvm_binding.mode {
        BindingMode::ReportData => {
            let expected = ctx.expected_report_data();
            if !constant_time_eq(&report.report_data, &expected) {
                return Err(AttestationError::ReportDataMismatch);
            }
            true
        }
        BindingMode::Commitment => {
            let regs = cpu
                .cvm_registers
                .as_ref()
                .ok_or_else(|| invalid("commitment mode without registers"))?;
            let mut bank = [[0u8; 48]; REG_COUNT];
            for r in regs {
                let value: [u8; 48] = r
                    .value
                    .as_slice()
                    .try_into()
                    .map_err(|_| invalid("register value is not 48 bytes"))?;
                bank[usize::from(r.index)] = value;
            }
            let chain_len = cpu
                .cvm_chain
                .ok_or_else(|| invalid("commitment mode without cvm_chain"))?
                .chain_len;
            let caller_data = ctx.expected_report_data();
            let c = commit(&bank, chain_len, &caller_data);
            let expected = commitment_report_data(&policy.commitment.header16.0, &c);
            if !constant_time_eq(&report.report_data, &expected) {
                return Err(AttestationError::ReportDataMismatch);
            }
            // The commitment binds the values. Backing is what the pinned image
            // establishes; until that table exists it is `virtualized`
            // (section 10), never what the envelope claims.
            for r in regs {
                registers.push(VerifiedRegister {
                    index: r.index,
                    alg: r.alg,
                    value: r.value.clone(),
                    source: RegisterSource::SnpVmr,
                    backing: Backing::Virtualized.min(r.backing),
                    replayed: false,
                    owner: None,
                    purpose: None,
                });
            }
            registers.sort_by_key(|r| r.index);
            chain = cpu.cvm_chain;
            bootseed = cpu.bootseed;
            true
        }
        other => {
            return Err(invalid(format!(
                "binding mode {other:?} on an SNP cpu submodule"
            )))
        }
    };

    // 9. References, backing, vector.
    let assessment = Assessment {
        launch_alg: HashAlg::Sha384,
        launch: &report.measurement,
        registers: &registers,
        hardware: Some(2),
    };
    let (reference, executables) = evaluate_reference(policy, &assessment)?;
    let backing_min = evaluate_backing(policy, &registers)?;
    let vector = cpu_vector(instance_identity, executables, assessment.hardware);

    let tcb_set = SnpTcbSet {
        reported,
        committed: tcb(&report.committed_tcb),
        current: tcb(&report.current_tcb),
        launch: tcb(&report.launch_tcb),
    };
    let mut compat = BTreeMap::new();
    compat.insert(
        "snp".to_string(),
        serde_json::json!({
            "policy_abi_major": report.policy.abi_major(),
            "policy_abi_minor": report.policy.abi_minor(),
            "policy_smt_allowed": report.policy.smt_allowed(),
            "policy_migrate_ma": migratable,
            "policy_debug_allowed": debug,
            "policy_single_socket": report.policy.single_socket_required(),
            "reported_tcb_bootloader": reported.bootloader,
            "reported_tcb_tee": reported.tee,
            "reported_tcb_snp": reported.snp,
            "reported_tcb_microcode": reported.microcode,
            "platform_tsme_enabled": report.plat_info.tsme_enabled(),
            "platform_smt_enabled": report.plat_info.smt_enabled(),
            "measurement": hex::encode(report.measurement),
            "report_data": hex::encode(report.report_data),
            "init_data": hex::encode(report.host_data),
            "chip_id": hex::encode(report.chip_id),
        }),
    );
    let claims = CpuClaims {
        cvm_platform: VerifiedPlatform {
            vendor: cpu.cvm_platform.vendor,
            tee: cpu.cvm_platform.tee,
            generation: Some(generation.product_name().to_string()),
            hosting: cpu.cvm_platform.hosting,
        },
        cvm_launch_measurement: Digest {
            alg: HashAlg::Sha384,
            value: Bytes(report.measurement.to_vec()),
        },
        cvm_registers: (!registers.is_empty()).then_some(registers),
        cvm_freshness: Freshness {
            pattern: cpu.cvm_binding.pattern,
            mode: cpu.cvm_binding.mode,
            key: cpu.cvm_binding.key.clone(),
            not_before: None,
            not_after: None,
        },
        cvm_host_data: Some(HostData {
            semantics: HostDataSemantics::SnpHostData,
            value: Bytes(report.host_data.to_vec()),
        }),
        cvm_owner: Some(Owner::Snp {
            family_id: FixedBytes(report.family_id),
            image_id: FixedBytes(report.image_id),
            id_key_digest: FixedBytes(report.id_key_digest),
            author_key_digest: FixedBytes(report.author_key_digest),
        }),
        cvm_policy: PolicyBits {
            debug,
            migratable,
            smt: Some(report.policy.smt_allowed()),
            single_socket: Some(report.policy.single_socket_required()),
            vmpl: u8::try_from(report.vmpl).ok(),
            sept_ve_disable: None,
            service_td: None,
            reserved_bits_zero: None,
        },
        dbgstat: if debug { 0 } else { 2 },
        cvm_tcb: Tcb::Snp(Box::new(tcb_set)),
        cvm_identity: Identity::Snp {
            chip_id: FixedBytes(report.chip_id),
        },
        cvm_chain: chain,
        bootseed,
        compat,
    };
    let status = vector.status();
    Ok(Outcome {
        appraisal: SubmodAppraisal {
            ear_status: status,
            ear_trustworthiness_vector: vector,
            ear_appraisal_policy_ids: vec![crate::profile::PROFILE_URI.to_string()],
            ear_attester_claims: AttesterClaims::Cpu(Box::new(claims)),
            ear_verifier_claims: VerifierClaims {
                cvm_collateral: collateral_outcomes,
                cvm_reference: reference,
                cvm_backing_min: backing_min,
            },
        },
        bound,
    })
}
