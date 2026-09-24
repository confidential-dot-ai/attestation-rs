//! `gpu/<ueid>` and `nvswitch/<ueid>` submodules (sections 4.5, 9.7 and 12.6):
//! NVIDIA devices appraised through NRAS, one request per architecture.
//!
//! NRAS signs one JWT per device, named `GPU-<i>` or `SWITCH-<i>` by the
//! device's position in the request. Each is bound to the session by its own
//! `eat_nonce` (the SPDM nonce derived from the envelope's nonce) and gated by
//! the per-device policy before it becomes a submodule appraisal.

use super::{invalid, refuse, resolve_floor, Outcome};
use crate::error::{AttestationError, RefusalCode, Result};
use crate::platforms::nvidia_gpu::verify::{attest_arch, ArchGroupResult, MAX_GPU_DEVICES};
use crate::platforms::nvidia_gpu::NrasProvider;
use crate::profile::binding::{nras_gpu_nonce, nras_switch_nonce};
use crate::profile::{
    AttesterClaims, CollateralCheck, CollateralOutcome, CollateralStatus, DeviceClaims,
    GpuDeviceEvidence, Identity, NvidiaEvidenceOutcome, SubmodAppraisal, Tcb, TrustVector,
    VerifierClaims, VerifyPolicy,
};
use crate::types::{NvidiaGpuArch, NvidiaGpuDeviceClaims, NvidiaGpuDeviceEvidence};
use std::collections::BTreeMap;

pub(crate) async fn appraise_devices(
    devices: Vec<(String, &GpuDeviceEvidence)>,
    nonce: &[u8],
    policy: &VerifyPolicy,
    provider: &dyn NrasProvider,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<(String, Outcome)>> {
    if devices.is_empty() {
        return if policy.gpu.required {
            Err(AttestationError::NvidiaGpuRequired)
        } else {
            Ok(Vec::new())
        };
    }
    if devices.len() > MAX_GPU_DEVICES {
        return Err(AttestationError::NvidiaGpuTooManyDevices(
            devices.len(),
            MAX_GPU_DEVICES,
        ));
    }
    // NV_ALLOW_HOLD_CERT relaxes NRAS's revocation check from the process
    // environment, where neither the policy nor the appraisal shows it.
    if provider.accepts_certificate_hold() {
        return Err(refuse(
            RefusalCode::Unsupported,
            "the NRAS provider asks NRAS to accept device certificates on OCSP hold (NV_ALLOW_HOLD_CERT); the profile path does not relax revocation outside the policy",
        ));
    }
    if let Some(allowed) = &policy.gpu.expected_archs {
        for (_, d) in &devices {
            if !allowed.contains(&d.arch) {
                return Err(AttestationError::NvidiaGpuArchNotAllowed(
                    NvidiaGpuArch::from(d.arch).to_string(),
                ));
            }
        }
    }
    let device_policy = crate::types::NvidiaGpuDevicePolicy::from(&policy.gpu.device_policy);

    let mut groups: BTreeMap<NvidiaGpuArch, Vec<(String, &GpuDeviceEvidence)>> = BTreeMap::new();
    for (name, d) in devices {
        groups.entry(d.arch.into()).or_default().push((name, d));
    }
    let mut out = Vec::new();
    for (arch, group) in groups {
        let nonce_bytes = match arch {
            NvidiaGpuArch::Ls10 => nras_switch_nonce(nonce),
            _ => nras_gpu_nonce(nonce),
        };
        let entries: Vec<NvidiaGpuDeviceEvidence> = group
            .iter()
            .map(|(_, d)| NvidiaGpuDeviceEvidence::from(*d))
            .collect();
        let refs: Vec<&NvidiaGpuDeviceEvidence> = entries.iter().collect();
        let result = attest_arch(now, arch, &refs, nonce_bytes, &device_policy, provider).await?;
        out.extend(outcomes_for_group(&group, result, policy)?);
    }
    Ok(out)
}

/// The position a NRAS submodule name encodes (`GPU-3` is 3), only when
/// its kind is the batch's: `GPU` for GPU batches, `SWITCH` for NVSwitch.
fn submodule_index(name: &str, arch: NvidiaGpuArch) -> Option<usize> {
    let (kind, index) = name.rsplit_once('-')?;
    let expected = match arch {
        NvidiaGpuArch::Ls10 => "SWITCH",
        _ => "GPU",
    };
    if kind != expected {
        return None;
    }
    index.parse().ok()
}

/// Map one architecture's verified NRAS result back onto the devices that
/// were sent, by request position. Every device must come back exactly once.
fn outcomes_for_group(
    group: &[(String, &GpuDeviceEvidence)],
    result: ArchGroupResult,
    policy: &VerifyPolicy,
) -> Result<Vec<(String, Outcome)>> {
    let arch = NvidiaGpuArch::from(
        group
            .first()
            .map(|(_, d)| d.arch)
            .unwrap_or(crate::profile::GpuArch::Hopper),
    );
    if !result.overall_ok {
        return Err(AttestationError::NrasOverallFailed);
    }
    if !result.nonce_binding_ok {
        return Err(AttestationError::NvidiaGpuBindingMismatch);
    }
    if result.devices.len() != group.len() {
        return Err(AttestationError::NvidiaGpuDeviceCountMismatch {
            expected: group.len(),
            got: result.devices.len(),
        });
    }
    let mut seen = vec![false; group.len()];
    let mut out = Vec::with_capacity(group.len());
    for (sub_name, claims) in result.devices {
        let index = submodule_index(&sub_name, arch)
            .filter(|&i| i < group.len())
            .ok_or_else(|| {
                AttestationError::NrasResponseParse(format!(
                    "submodule {sub_name:?} names no device of this batch"
                ))
            })?;
        if std::mem::replace(&mut seen[index], true) {
            return Err(AttestationError::NrasResponseParse(format!(
                "submodule {sub_name:?} repeats a device position"
            )));
        }
        out.push((group[index].0.clone(), device_outcome(claims, policy)?));
    }
    Ok(out)
}

fn device_outcome(claims: NvidiaGpuDeviceClaims, policy: &VerifyPolicy) -> Result<Outcome> {
    let serde_json::Value::Object(raw) = claims.raw else {
        return Err(AttestationError::NrasResponseParse(
            "submodule claims are not an object".to_string(),
        ));
    };
    // The identity policy compares the signed `ueid`, never the envelope's
    // label; an allowlist with no ueid to check fails closed.
    let (_floor, instance_identity) = match claims.ueid.as_deref() {
        Some(ueid) => resolve_floor(policy, Some(ueid.as_bytes()))?,
        None if policy.identity.is_some() => {
            return Err(refuse(
                RefusalCode::MachineNotAllowed,
                "NRAS submodule carries no ueid to check against the machine allowlist",
            ))
        }
        None => (None, None),
    };
    let mut map: BTreeMap<String, serde_json::Value> = raw.into_iter().collect();
    if let Some(ueid) = claims.ueid.clone() {
        map.insert(
            "cvm_identity".to_string(),
            claim_value(&Identity::Gpu { ueid })?,
        );
    }
    if let (Some(driver), Some(vbios)) =
        (claims.driver_version.clone(), claims.vbios_version.clone())
    {
        map.insert(
            "cvm_tcb".to_string(),
            claim_value(&Tcb::Gpu { driver, vbios })?,
        );
    }
    // Section 12.4: sourced-data is what an NRAS-affirmed device with an
    // acceptable device policy earns; the CPU carries the platform claims.
    let vector = TrustVector {
        instance_identity,
        configuration: None,
        executables: None,
        file_system: None,
        hardware: None,
        runtime_opaque: None,
        storage_opaque: None,
        sourced_data: Some(2),
    };
    let mut collateral = BTreeMap::new();
    collateral.insert(
        CollateralCheck::NrasJwks,
        CollateralOutcome {
            status: CollateralStatus::Checked,
            reason: None,
            this_update: None,
            next_update: None,
            signed: Some(true),
        },
    );
    Ok(Outcome {
        appraisal: SubmodAppraisal {
            ear_status: vector.status(),
            ear_trustworthiness_vector: vector,
            ear_appraisal_policy_ids: Vec::new(),
            ear_attester_claims: AttesterClaims::Device(DeviceClaims { claims: map }),
            ear_verifier_claims: VerifierClaims {
                cvm_collateral: collateral,
                cvm_reference: None,
                cvm_backing_min: None,
                ear_nvidia_evidence: Some(NvidiaEvidenceOutcome {
                    signature_verified: claims.report_signature_verified,
                    parsed: claims.report_parsed,
                    nonce_match: claims.nonce_match,
                }),
            },
        },
        // A device NRAS reports unmatched is not bound to this session, even
        // when policy tolerates the mismatch (section 12.6).
        bound: claims.nonce_match == Some(true),
    })
}

fn claim_value<T: serde::Serialize>(v: &T) -> Result<serde_json::Value> {
    serde_json::to_value(v).map_err(|e| invalid(format!("claim encoding: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Binding, BindingMode, Bytes, FreshnessPattern, GpuArch, MachineEntry};
    use serde_json::json;

    fn device(uuid: &str) -> GpuDeviceEvidence {
        GpuDeviceEvidence {
            arch: GpuArch::Hopper,
            uuid: uuid.to_string(),
            evidence_b64: "AAAA".to_string(),
            cert_chain_b64: "AAAA".to_string(),
            cvm_binding: Binding {
                pattern: FreshnessPattern::Challenge,
                mode: BindingMode::NrasNonce,
                key: None,
            },
        }
    }

    fn claims(ueid: &str) -> NvidiaGpuDeviceClaims {
        NvidiaGpuDeviceClaims {
            ueid: Some(ueid.to_string()),
            driver_version: Some("570.86.15".to_string()),
            vbios_version: Some("96.00.9F.00.01".to_string()),
            report_signature_verified: Some(true),
            report_parsed: Some(true),
            nonce_match: Some(true),
            raw: json!({
                "ueid": ueid,
                "hwmodel": "GH100 A01 GSP BROM",
                "measres": "success",
                "secboot": true,
                "dbgstat": "disabled",
                "x-nvidia-gpu-driver-version": "570.86.15",
                "x-nvidia-gpu-vbios-version": "96.00.9F.00.01",
                "x-nvidia-gpu-attestation-report-nonce-match": true,
                "x-nvidia-gpu-attestation-report-signature-verified": true,
                "exp": 4102444800u64
            }),
            ..Default::default()
        }
    }

    fn result(devices: Vec<(&str, NvidiaGpuDeviceClaims)>) -> ArchGroupResult {
        ArchGroupResult {
            overall_ok: true,
            eat_nonce: None,
            nonce_binding_ok: true,
            overall_raw: json!({"x-nvidia-overall-att-result": true}),
            devices: devices
                .into_iter()
                .map(|(n, c)| (n.to_string(), c))
                .collect(),
        }
    }

    #[test]
    fn submodules_map_back_by_request_position() {
        let d0 = device("GPU-aaaa");
        let d1 = device("GPU-bbbb");
        let group = vec![
            ("gpu/GPU-aaaa".to_string(), &d0),
            ("gpu/GPU-bbbb".to_string(), &d1),
        ];
        let policy = VerifyPolicy::default();
        // NRAS's object order is not the request order; the index is.
        let out = outcomes_for_group(
            &group,
            result(vec![("GPU-1", claims("uB")), ("GPU-0", claims("uA"))]),
            &policy,
        )
        .unwrap();
        assert_eq!(out[0].0, "gpu/GPU-bbbb");
        assert_eq!(out[1].0, "gpu/GPU-aaaa");
        let a = &out[1].1.appraisal;
        assert_eq!(a.ear_status, crate::profile::Tier::Affirming);
        assert_eq!(a.ear_trustworthiness_vector.sourced_data, Some(2));
        assert_eq!(a.ear_trustworthiness_vector.instance_identity, None);
        let AttesterClaims::Device(dc) = &a.ear_attester_claims else {
            panic!("device claims")
        };
        assert_eq!(dc.claims["cvm_identity"], json!({"ueid": "uA"}));
        assert_eq!(
            dc.claims["cvm_tcb"],
            json!({"driver": "570.86.15", "vbios": "96.00.9F.00.01"})
        );
        assert_eq!(dc.claims["measres"], json!("success"));
        let nv = a.ear_verifier_claims.ear_nvidia_evidence.unwrap();
        assert_eq!(nv.signature_verified, Some(true));
        assert_eq!(nv.nonce_match, Some(true));
        assert_eq!(nv.parsed, Some(true));
        assert!(a
            .ear_verifier_claims
            .cvm_collateral
            .contains_key(&CollateralCheck::NrasJwks));
        assert!(out.iter().all(|(_, o)| o.bound));
    }

    #[test]
    fn a_batch_must_come_back_whole_and_once() {
        let d0 = device("GPU-aaaa");
        let d1 = device("GPU-bbbb");
        let group = vec![
            ("gpu/GPU-aaaa".to_string(), &d0),
            ("gpu/GPU-bbbb".to_string(), &d1),
        ];
        let policy = VerifyPolicy::default();
        let err =
            outcomes_for_group(&group, result(vec![("GPU-0", claims("uA"))]), &policy).unwrap_err();
        assert!(matches!(
            err,
            AttestationError::NvidiaGpuDeviceCountMismatch {
                expected: 2,
                got: 1
            }
        ));
        for names in [
            ["GPU-0", "GPU-0"],
            ["GPU-0", "GPU-2"],
            ["GPU-0", "GPU"],
            ["GPU-0", "SWITCH-1"],
        ] {
            let r = result(vec![(names[0], claims("uA")), (names[1], claims("uB"))]);
            assert!(matches!(
                outcomes_for_group(&group, r, &policy).unwrap_err(),
                AttestationError::NrasResponseParse(_)
            ));
        }
        let mut r = result(vec![("GPU-0", claims("uA")), ("GPU-1", claims("uB"))]);
        r.overall_ok = false;
        assert!(matches!(
            outcomes_for_group(&group, r, &policy).unwrap_err(),
            AttestationError::NrasOverallFailed
        ));
        let mut r = result(vec![("GPU-0", claims("uA")), ("GPU-1", claims("uB"))]);
        r.nonce_binding_ok = false;
        assert!(matches!(
            outcomes_for_group(&group, r, &policy).unwrap_err(),
            AttestationError::NvidiaGpuBindingMismatch
        ));
    }

    #[test]
    fn the_allowlist_compares_the_signed_ueid() {
        let d0 = device("GPU-aaaa");
        let group = vec![("gpu/GPU-aaaa".to_string(), &d0)];
        let mut policy = VerifyPolicy {
            identity: Some(crate::profile::IdentityPolicy {
                machines: vec![MachineEntry {
                    id: Bytes(b"uA".to_vec()),
                    tcb_floor: None,
                }],
            }),
            ..VerifyPolicy::default()
        };
        let out =
            outcomes_for_group(&group, result(vec![("GPU-0", claims("uA"))]), &policy).unwrap();
        assert_eq!(
            out[0]
                .1
                .appraisal
                .ear_trustworthiness_vector
                .instance_identity,
            Some(2)
        );
        // The envelope label matches the allowlist; the signed ueid does not.
        policy.identity.as_mut().unwrap().machines[0].id = Bytes(b"GPU-aaaa".to_vec());
        assert!(
            outcomes_for_group(&group, result(vec![("GPU-0", claims("uA"))]), &policy).is_err()
        );
        // No ueid at all under an allowlist fails closed.
        let mut c = claims("uA");
        c.ueid = None;
        assert!(outcomes_for_group(&group, result(vec![("GPU-0", c)]), &policy).is_err());
    }

    /// A provider that asks NRAS to accept certificates on OCSP hold, as
    /// `NV_ALLOW_HOLD_CERT=true` makes the default one do.
    struct HoldingProvider;

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl NrasProvider for HoldingProvider {
        fn url_for(&self, _arch: NvidiaGpuArch) -> &str {
            "https://invalid.test/never-called"
        }
        fn accepts_certificate_hold(&self) -> bool {
            true
        }
        async fn attest(
            &self,
            _request: &crate::platforms::nvidia_gpu::NrasRequest,
        ) -> Result<serde_json::Value> {
            panic!("the profile path reached NRAS with a relaxed revocation check");
        }
        async fn jwks(&self, _arch: NvidiaGpuArch) -> Result<crate::platforms::nvidia_gpu::Jwks> {
            panic!("the profile path reached NRAS with a relaxed revocation check");
        }
    }

    #[tokio::test]
    async fn the_profile_path_refuses_a_provider_that_accepts_held_certificates() {
        let d = device("GPU-aaaa");
        let err = appraise_devices(
            vec![("gpu/GPU-aaaa".to_string(), &d)],
            &crate::utils::sha256(b"device nonce"),
            &VerifyPolicy::default(),
            &HoldingProvider,
            chrono::Utc::now(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.refusal_code(), Some(RefusalCode::Unsupported), "{err}");
    }
}
