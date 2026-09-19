//! Reference values, machine allowlists, backing floors and the AR4SI
//! trustworthiness vector (sections 5.2 and 7).

use super::invalid;
use crate::error::Result;
use crate::profile::{
    BackingMin, Digest, HashAlg, ReferenceOutcome, TcbFloor, TrustVector, VerifiedRegister,
    VerifyPolicy,
};
use crate::utils::constant_time_eq;
use std::collections::BTreeMap;

/// What the vector builder needs from a platform appraiser.
pub(crate) struct Assessment<'a> {
    pub launch_alg: HashAlg,
    pub launch: &'a [u8],
    pub registers: &'a [VerifiedRegister],
    /// Hardware claim value: 2 verified and acceptable, 32 vendor reports a
    /// known vulnerability the policy accepts, `None` when the TCB status
    /// could not be assessed because policy allowed skipping collateral.
    pub hardware: Option<i8>,
}

/// The floor a machine is held to: its allowlist entry's, else the default.
pub(crate) fn resolve_floor<'p>(
    policy: &'p VerifyPolicy,
    identity: &[u8],
) -> Result<(Option<&'p TcbFloor>, Option<i8>)> {
    let Some(allow) = &policy.identity else {
        return Ok((
            policy
                .tcb
                .default_floor
                .as_deref()
                .and_then(|f| policy.tcb.floors.get(f)),
            None,
        ));
    };
    let Some(entry) = allow
        .machines
        .iter()
        .find(|m| constant_time_eq(m.id.as_slice(), identity))
    else {
        // AR4SI 97: the attester is not recognized, and policy says it should be.
        return Err(invalid(format!(
            "identity {} is not on the machine allowlist",
            hex::encode(identity)
        )));
    };
    let floor_name = entry
        .tcb_floor
        .as_deref()
        .or(policy.tcb.default_floor.as_deref());
    Ok((floor_name.and_then(|f| policy.tcb.floors.get(f)), Some(2)))
}

fn matches_any(refs: &[Digest], alg: HashAlg, value: &[u8]) -> bool {
    refs.iter()
        .any(|d| d.alg == alg && constant_time_eq(d.value.as_slice(), value))
}

/// Section 5.1 `cvm_reference` and the executables claim. A configured
/// expectation that fails is an error, never a lower value.
pub(crate) fn evaluate_reference(
    policy: &VerifyPolicy,
    a: &Assessment<'_>,
) -> Result<(Option<ReferenceOutcome>, Option<i8>)> {
    let refs = &policy.reference;
    let launch_pinned = !refs.launch_measurement.is_empty();
    if launch_pinned && !matches_any(&refs.launch_measurement, a.launch_alg, a.launch) {
        return Err(invalid(
            "launch measurement is not among the reference values",
        ));
    }
    let mut registers = BTreeMap::new();
    for (slot, expected) in &refs.registers {
        let Some(reg) = a.registers.iter().find(|r| r.index == *slot) else {
            return Err(invalid(format!(
                "register {slot} is pinned by policy but the evidence carries no such register"
            )));
        };
        if !matches_any(expected, reg.alg, reg.value.as_slice()) {
            return Err(invalid(format!(
                "register {slot} is not among its reference values"
            )));
        }
        registers.insert(*slot, true);
    }
    for (slot, owner) in &refs.slot_owners {
        let Some(reg) = a.registers.iter().find(|r| r.index == *slot) else {
            return Err(invalid(format!(
                "slot {slot} owner is pinned by policy but the evidence carries no such register"
            )));
        };
        if reg.owner.as_deref() != Some(owner.as_str()) {
            return Err(invalid(format!(
                "slot {slot} is owned by {:?}, policy requires {owner:?}",
                reg.owner
            )));
        }
    }
    if !launch_pinned && registers.is_empty() {
        return Ok((None, None));
    }
    let executables = if launch_pinned && !registers.is_empty() {
        2
    } else if launch_pinned {
        3
    } else {
        2
    };
    Ok((
        Some(ReferenceOutcome {
            launch_measurement: launch_pinned,
            registers,
        }),
        Some(executables),
    ))
}

/// Section 4.7: the weakest backing seen must reach the policy floor.
pub(crate) fn evaluate_backing(
    policy: &VerifyPolicy,
    registers: &[VerifiedRegister],
) -> Result<Option<BackingMin>> {
    let Some(weakest) = registers.iter().map(|r| r.backing).min() else {
        return Ok(None);
    };
    if weakest < policy.min_backing {
        return Err(invalid(format!(
            "a register is backed by {weakest:?}, policy requires at least {:?}",
            policy.min_backing
        )));
    }
    Ok(Some(BackingMin {
        required: policy.min_backing,
        weakest_seen: weakest,
    }))
}

/// Section 5.2 for a CPU submodule whose checks all passed.
pub(crate) fn cpu_vector(
    instance_identity: Option<i8>,
    executables: Option<i8>,
    hardware: Option<i8>,
) -> TrustVector {
    TrustVector {
        instance_identity,
        configuration: Some(2),
        executables,
        file_system: None,
        hardware,
        runtime_opaque: Some(2),
        storage_opaque: None,
        sourced_data: None,
    }
}
