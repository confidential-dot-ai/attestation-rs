//! SEV-SNP `cpu` submodule (section 6), over the primitives in `platforms::snp`.

use super::inline::InlineCollateral;
use super::resolve_floor;
use super::vector::{cpu_vector, evaluate_backing, evaluate_reference, Assessment};
use super::{invalid, refuse, Ctx, Outcome};
use crate::collateral::CertProvider;
use crate::error::{AttestationError, RefusalCode, Result};
use crate::platforms::snp::verify::{
    check_chain_not_revoked_at, parse_report, report_signing_key, verify_report_signature,
    verify_vcek_tcb, verify_vek_chain_at, SigningKey, MAX_REPORT_VERSION, MIN_REPORT_VERSION,
};
#[cfg(feature = "az-snp")]
use crate::platforms::tpm_common::verify_hcl_var_data_binding;
use crate::profile::registers::{
    commit, genesis, report_data as commitment_report_data, BOOT_SLOT, REG_COUNT,
};
use crate::profile::Hosting;
use crate::profile::{
    AttesterClaims, Backing, BindingMode, Bytes, CollateralCheck, CollateralOutcome,
    CollateralStatus, CpuClaims, CpuEvidence, Digest, FixedBytes, Freshness, HashAlg, HostData,
    HostDataSemantics, Identity, Owner, PolicyBits, RegisterSource, SnpTcbSet, SubmodAppraisal,
    Tcb, VerifiedPlatform, VerifiedRegister, VerifierClaims,
};
use crate::profile::{DebugStatus, SnpTcbValue};
use crate::types::{ProcessorGeneration, SnpTcb};
use crate::utils::constant_time_eq;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;
use std::collections::BTreeMap;

/// Whether any component of `have` is below `min`. A floor that names the
/// FMC SPL fails a report that has none (every generation before Turin).
fn below_floor(have: &SnpTcb, min: &SnpTcb) -> bool {
    let fmc_below = match (min.fmc, have.fmc) {
        (Some(m), Some(h)) => h < m,
        (Some(_), None) => true,
        (None, _) => false,
    };
    have.bootloader < min.bootloader
        || have.tee < min.tee
        || have.snp < min.snp
        || have.microcode < min.microcode
        || fmc_below
}

fn spl(t: &SnpTcb) -> String {
    let fmc = t.fmc.map(|f| format!(".{f}")).unwrap_or_default();
    format!("{}.{}.{}.{}{fmc}", t.bootloader, t.tee, t.snp, t.microcode)
}

fn tcb(v: &TcbVersion) -> SnpTcb {
    SnpTcb {
        bootloader: v.bootloader,
        tee: v.tee,
        snp: v.snp,
        microcode: v.microcode,
        fmc: v.fmc,
    }
}

/// The generation from the report's CPUID fields, or, for a v2 report without
/// them (Azure), from the issuer of the inline VEK; the chain verification
/// that follows confirms the choice.
fn generation(
    report: &AttestationReport,
    inline_vek: Option<&[u8]>,
) -> Result<ProcessorGeneration> {
    match (report.cpuid_fam_id, report.cpuid_mod_id) {
        (Some(fam), Some(model)) => ProcessorGeneration::from_cpuid(fam, model).ok_or_else(|| {
            AttestationError::QuoteParseFailed(format!(
                "unknown processor: family=0x{fam:02X}, model=0x{model:02X}"
            ))
        }),
        _ if report.version >= 3 => Err(AttestationError::QuoteParseFailed(
            "v3+ SNP report missing CPUID family or model".to_string(),
        )),
        _ => {
            let vek = inline_vek.ok_or_else(|| {
                AttestationError::QuoteParseFailed(
                    "a v2 SNP report names no generation and the envelope carries no VEK"
                        .to_string(),
                )
            })?;
            generation_from_issuer(vek)
        }
    }
}

/// The generation named by a VEK's issuer (`SEV-Genoa`, `SEV-VLEK-Genoa`, ...).
fn generation_from_issuer(vek_der: &[u8]) -> Result<ProcessorGeneration> {
    let (_, cert) = x509_parser::parse_x509_certificate(vek_der)
        .map_err(|e| AttestationError::CertChainError(format!("VEK x509 parse: {e}")))?;
    let cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .unwrap_or_default();
    [
        ProcessorGeneration::Milan,
        ProcessorGeneration::Genoa,
        ProcessorGeneration::Turin,
    ]
    .into_iter()
    .find(|g| cn.ends_with(&format!("-{}", g.product_name())))
    .ok_or_else(|| {
        AttestationError::CertChainError(format!("VEK issuer {cn:?} names no known generation"))
    })
}

/// Section 4.9 replay: the log's records, `chain_len` of them, replay every
/// touched slot from genesis to the committed value; untouched slots must
/// still be at genesis; workload slots report their claim.
fn replay_chain(
    log: &crate::profile::EventLog,
    chain_len: u64,
    bootseed: &[u8; 32],
    seed: &[u8; 48],
    registers: &mut [VerifiedRegister],
) -> Result<()> {
    use crate::profile::cel;
    use crate::profile::LogFormat;
    let records = match log.format {
        LogFormat::TcgCelCbor => cel::parse_cbor(log.data.as_slice())?,
        LogFormat::TcgCelJson => cel::parse_json(log.data.as_slice())?,
        other => {
            return Err(refuse(
                RefusalCode::LogRequired,
                format!("event log format {other:?} does not carry the register chain"),
            ))
        }
    };
    if records.len() as u64 != chain_len {
        return Err(refuse(
            RefusalCode::LogRequired,
            format!(
                "cvm_chain claims {chain_len} extensions but the log carries {}",
                records.len()
            ),
        ));
    }
    let out = cel::replay(
        &records,
        |i| (usize::from(i) < REG_COUNT).then(|| genesis(i as u8, seed)),
        true,
    )?;
    let expected_boot: [u8; 48] = {
        use sha2::Digest;
        sha2::Sha384::digest(bootseed).into()
    };
    match out.boot_digest {
        Some(d) if constant_time_eq(&d, &expected_boot) => {}
        _ => {
            return Err(refuse(
                RefusalCode::ReplayMismatch,
                "record 0 is not the boot record for this bootseed",
            ))
        }
    }
    for r in registers.iter_mut() {
        match out.slots.get(&r.index) {
            Some(slot) => {
                if !constant_time_eq(r.value.as_slice(), &slot.value) {
                    return Err(AttestationError::EventlogIntegrityFailed(format!(
                        "slot {} does not replay to the committed value",
                        r.index
                    )));
                }
                r.replayed = true;
                if let Some((owner, purpose)) = &slot.claim {
                    r.owner = Some(owner.clone());
                    r.purpose = Some(purpose.clone());
                }
            }
            None => {
                if !constant_time_eq(r.value.as_slice(), &genesis(r.index as u8, seed)) {
                    return Err(AttestationError::EventlogIntegrityFailed(format!(
                        "slot {} left genesis with no record in the log",
                        r.index
                    )));
                }
            }
        }
    }
    Ok(())
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
    // Azure's paravisor issues v2 reports, which carry no CPUID fields.
    let min_version = if cpu.cvm_platform.hosting == Hosting::Azure {
        2
    } else {
        MIN_REPORT_VERSION
    };
    if report.version < min_version || report.version > MAX_REPORT_VERSION {
        return Err(AttestationError::UnsupportedReportVersion {
            version: report.version,
            min: min_version,
            max: MAX_REPORT_VERSION,
        });
    }
    let signing_key = report_signing_key(report_bytes)?;
    let generation = generation(&report, collateral.raw("snp.vek"))?;
    // Section 4.2: a hint that contradicts the signed data is an error.
    if let Some(hint) = &cpu.cvm_platform.generation {
        if hint != generation.product_name() {
            return Err(invalid(format!(
                "cvm_platform.generation {hint:?} contradicts the report's {}",
                generation.product_name()
            )));
        }
    }

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
    let intermediate = verify_vek_chain_at(generation, signing_key, &vek_der, ctx.now)?;
    let ark_der = crate::platforms::snp::certs::get_ark(generation);
    let mut collateral_outcomes = BTreeMap::new();
    let mut revocation_checked = false;
    match collateral.get_snp_crl(generation).await? {
        Some(crl) => {
            check_chain_not_revoked_at(intermediate, &crl, ark_der, ctx.now)?;
            revocation_checked = true;
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
    verify_report_signature(report_bytes, &vek_der)?;
    verify_vcek_tcb(&report, &vek_der, generation)?;

    // 4. Guest policy. A guest runs at VMPL 0 to 3; any other value is a
    // report the host requested, whose report data the host chose.
    if report.vmpl > 3 {
        return Err(refuse(
            RefusalCode::GuestPolicy,
            format!(
                "VMPL {:#x}: the report was not requested by the guest",
                report.vmpl
            ),
        ));
    }
    if policy.policy_bits.require_vmpl0 && report.vmpl != 0 {
        return Err(AttestationError::VmplCheckFailed(report.vmpl));
    }
    let debug = report.policy.debug_allowed();
    // The guest policy is fixed at launch, so debug is off since boot or on.
    let dbgstat = if debug {
        DebugStatus::Enabled
    } else {
        DebugStatus::DisabledSinceBoot
    };
    if cpu
        .dbgstat
        .is_some_and(|hint| hint.is_disabled() != dbgstat.is_disabled())
    {
        return Err(invalid("dbgstat contradicts the report's debug policy bit"));
    }
    if debug && !policy.policy_bits.allow_debug {
        return Err(AttestationError::DebugPolicyViolation);
    }
    let migratable = report.policy.migrate_ma_allowed();
    if migratable && !policy.policy_bits.allow_migration {
        return Err(refuse(
            RefusalCode::GuestPolicy,
            "guest policy allows migration and policy does not",
        ));
    }
    if let Some(owner) = &policy.owner {
        if !owner
            .id_key_digests
            .iter()
            .any(|d| constant_time_eq(&d.0, &report.id_key_digest))
        {
            return Err(refuse(
                RefusalCode::ReferenceMismatch,
                "id_key_digest is not among the owner keys policy accepts",
            ));
        }
    }

    if let Some(expected) = &policy.reference.host_data {
        // A pin longer than HOST_DATA is one no report can meet.
        let padded = crate::utils::pad_report_data(expected.as_slice(), 32)
            .map_err(|_| AttestationError::InitDataMismatch)?;
        if !constant_time_eq(&report.host_data, &padded) {
            return Err(AttestationError::InitDataMismatch);
        }
    }

    // Identity, floor. A VLEK or a masked (all zero) CHIP_ID identifies no
    // machine (section 13.3).
    let machine = (signing_key == SigningKey::Vcek && report.chip_id.iter().any(|&b| b != 0))
        .then_some(&report.chip_id[..]);
    let (floor, instance_identity) = resolve_floor(policy, machine)?;
    let snp_floor = floor.and_then(|f| f.snp.as_ref());
    if let Some(f) = snp_floor {
        for value in &f.values {
            let have = tcb(match value {
                SnpTcbValue::Reported => &report.reported_tcb,
                SnpTcbValue::Current => &report.current_tcb,
                SnpTcbValue::Committed => &report.committed_tcb,
                SnpTcbValue::Launch => &report.launch_tcb,
            });
            if below_floor(&have, &f.min) {
                return Err(AttestationError::TcbMismatch(format!(
                    "{} TCB {} is below the policy floor {}",
                    value.as_str(),
                    spl(&have),
                    spl(&f.min)
                )));
            }
        }
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
            // The boot record is always the first extend into slot 3, so a
            // live chain never leaves that slot at genesis (section 4.9).
            if chain_len >= 1
                && bank[usize::from(BOOT_SLOT)] == genesis(BOOT_SLOT, &policy.commitment.seed.0)
            {
                return Err(refuse(
                    RefusalCode::RegisterMismatch,
                    "slot 3 is at genesis but the chain claims a boot record",
                ));
            }
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
            // 8. The log is what turns committed values into a chain: record
            // 0 is the boot record for this bootseed, every slot that left
            // genesis replays, and workload slots open with their claim.
            let log = cpu.cvm_log.as_ref().ok_or_else(|| {
                refuse(
                    RefusalCode::LogRequired,
                    "commitment mode without a log: the boot record cannot be checked",
                )
            })?;
            let seed_bytes = cpu
                .bootseed
                .ok_or_else(|| invalid("commitment mode without bootseed"))?;
            replay_chain(
                log,
                chain_len,
                &seed_bytes.0,
                &policy.commitment.seed.0,
                &mut registers,
            )?;
            for (slot, owner) in &policy.reference.slot_owners {
                let reg = registers.iter().find(|r| r.index == *slot);
                if reg.and_then(|r| r.owner.as_deref()) != Some(owner.as_str()) {
                    return Err(refuse(
                        RefusalCode::ReferenceMismatch,
                        format!("slot {slot} is not owned by {owner:?} as policy requires"),
                    ));
                }
            }
            chain = cpu.cvm_chain;
            bootseed = cpu.bootseed;
            true
        }
        #[cfg(feature = "az-snp")]
        BindingMode::VtpmExtradata => {
            let var_data = ctx.vtpm_var_data.as_deref().ok_or_else(|| {
                invalid("vtpm-extradata binding without a verified vtpm submodule")
            })?;
            verify_hcl_var_data_binding(&report.report_data, var_data)?;
            true
        }
        other => {
            return Err(invalid(format!(
                "binding mode {other:?} on an SNP cpu submodule"
            )))
        }
    };
    if !policy.reference.slot_owners.is_empty() && cpu.cvm_binding.mode != BindingMode::Commitment {
        return Err(refuse(
            RefusalCode::ReferenceMismatch,
            "policy pins slot owners but the evidence carries no workload slots",
        ));
    }

    // 9. References, backing, vector.
    let assessment = Assessment {
        launch_alg: HashAlg::Sha384,
        launch: &report.measurement,
        registers: &registers,
        // AMD runs no TCB status service, so a floor is the only TCB
        // assessment; without one, or without revocation, no claim.
        hardware: (snp_floor.is_some() && revocation_checked).then_some(2),
    };
    let (reference, executables) = evaluate_reference(policy, &assessment)?;
    let backing_min = evaluate_backing(policy, &registers)?;
    let configuration = if debug || report.vmpl != 0 { 96 } else { 2 };
    let vector = cpu_vector(
        instance_identity,
        executables,
        assessment.hardware,
        configuration,
        debug,
    );

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
        dbgstat,
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
            ear_appraisal_policy_ids: Vec::new(),
            ear_attester_claims: AttesterClaims::Cpu(Box::new(claims)),
            ear_verifier_claims: VerifierClaims {
                cvm_collateral: collateral_outcomes,
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
    use crate::profile::registers::SEED;
    use crate::profile::{EventLog, LogFormat};

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../docs/standard/vectors/cvm_profile_vectors.json"
        ))
        .unwrap()
    }

    fn hexv(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    fn bank(v: &serde_json::Value) -> Vec<VerifiedRegister> {
        (0..REG_COUNT as u8)
            .map(|i| {
                let value = match i {
                    3 => hexv(v, "boot_r3"),
                    4 => hexv(v, "claim_r4"),
                    _ => genesis(i, &SEED).to_vec(),
                };
                VerifiedRegister {
                    index: u16::from(i),
                    alg: HashAlg::Sha384,
                    value: Bytes(value),
                    source: RegisterSource::SnpVmr,
                    backing: Backing::Virtualized,
                    replayed: false,
                    owner: None,
                    purpose: None,
                }
            })
            .collect()
    }

    #[test]
    fn the_chain_replays_from_the_boot_record_to_the_committed_registers() {
        let v = vectors();
        let log = EventLog {
            format: LogFormat::TcgCelCbor,
            data: Bytes(hexv(&v, "cel_log")),
        };
        let bootseed: [u8; 32] = hexv(&v, "bootseed").try_into().unwrap();
        let mut regs = bank(&v);
        replay_chain(&log, 2, &bootseed, &SEED, &mut regs).unwrap();
        assert!(regs[3].replayed && regs[4].replayed && !regs[5].replayed);
        assert_eq!(regs[4].owner.as_deref(), Some("c8s"));
        assert_eq!(regs[4].purpose.as_deref(), Some("workload"));

        // chain_len must count the records
        assert!(replay_chain(&log, 3, &bootseed, &SEED, &mut bank(&v)).is_err());
        // a different bootseed is a different boot
        assert!(replay_chain(&log, 2, &[0u8; 32], &SEED, &mut bank(&v)).is_err());
        // a committed value the log does not reach
        let mut regs = bank(&v);
        regs[4].value = Bytes(vec![1u8; 48]);
        assert!(replay_chain(&log, 2, &bootseed, &SEED, &mut regs).is_err());
        // a slot that left genesis without a record
        let mut regs = bank(&v);
        regs[7].value = Bytes(vec![1u8; 48]);
        assert!(replay_chain(&log, 2, &bootseed, &SEED, &mut regs).is_err());
        // the CCEL format carries no chain
        let ccel = EventLog {
            format: LogFormat::TdxCcel,
            data: log.data.clone(),
        };
        assert!(replay_chain(&ccel, 2, &bootseed, &SEED, &mut bank(&v)).is_err());
    }

    #[test]
    fn v2_reports_take_their_generation_from_the_vek_issuer() {
        // Azure's v2 report carries no CPUID fields; its VCEK is issued by SEV-Milan.
        let hcl = include_bytes!("../../test_data/az_snp/hcl-report.bin");
        let report = parse_report(&hcl[0x20..0x20 + 1184]).unwrap();
        assert_eq!(report.version, 2);
        let vek = include_bytes!("../../test_data/az_snp/imds-vcek.der");
        assert_eq!(
            generation(&report, Some(vek)).unwrap(),
            ProcessorGeneration::Milan
        );
        assert!(generation(&report, None).is_err());
        assert!(generation_from_issuer(&vek[..vek.len() - 1]).is_err());
    }
}
