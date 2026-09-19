//! Reference values, machine allowlists, backing floors and the AR4SI
//! trustworthiness vector (sections 5.2 and 7).

use super::invalid;
use crate::error::Result;
use crate::profile::{
    BackingMin, Digest, HashAlg, ReferenceOutcome, TrustVector, VerifiedRegister, VerifyPolicy,
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
    // Section 5.2: 2 needs the launch measurement and every pinned register;
    // 3 is the launch measurement alone; with the launch measurement unpinned
    // nothing vouches for the firmware, so no claim is made.
    let executables = match (launch_pinned, registers.is_empty()) {
        (true, false) => Some(2),
        (true, true) => Some(3),
        (false, _) => None,
    };
    Ok((
        Some(ReferenceOutcome {
            launch_measurement: Some(launch_pinned),
            registers,
        }),
        executables,
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

/// Section 5.2 for a CPU submodule whose checks all passed. `configuration`
/// is 96 when debug is enabled or VMPL is not 0, which policy may have allowed.
pub(crate) fn cpu_vector(
    instance_identity: Option<i8>,
    executables: Option<i8>,
    hardware: Option<i8>,
    configuration: i8,
) -> TrustVector {
    TrustVector {
        instance_identity,
        configuration: Some(configuration),
        executables,
        file_system: None,
        hardware,
        runtime_opaque: Some(2),
        storage_opaque: None,
        sourced_data: None,
    }
}
