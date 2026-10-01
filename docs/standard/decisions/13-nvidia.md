# Layer 13: NVIDIA devices

Sections 4.5, 9.7 and 13.5: GPUs and NVSwitches attached to a CVM. The corpus holds no recorded NRAS exchange yet, so the token checks below rest on the reference implementation's unit tests.

### NVD-1. Device appraisal is delegated to NRAS

NVIDIA's Remote Attestation Service verifies each device's SPDM evidence and certificate chain against NVIDIA's reference values and returns signed tokens (API version 4, claims version 3.0). This verifier binds the devices to the nonce, authenticates NRAS's answer and applies the device policy.

- Why: NRAS is the appraisal NVIDIA operates, and its tokens are what the TDX confidential-GPU EAR draft composes with. Section 15.11 states the consequence: a compromise of NRAS or its keys defeats device appraisal.
- Rejected: appraising the SPDM evidence locally against NVIDIA's reference manifests and OCSP, as NVIDIA's SDK can. It puts SPDM parsing and manifest matching inside the verifier, and is left for a later version.
- Where: Sections 3.1, 9.7, 15.11.

### NVD-2. One submodule per device, carrying the evidence as NVIDIA's SDK exchanges it

A `gpu/<ueid>` or `nvswitch/<ueid>` submodule holds `arch`, `uuid`, `evidence_b64`, `cert_chain_b64` and a binding of `challenge` and `nras-nonce`. The two base64 members keep NVIDIA's standard alphabet, because NRAS consumes them as text.

- Why: passing the bytes through verbatim means the verifier never re-encodes what NRAS will check.
- Where: Section 4.5. Cases: `gpu-device-arch-under-gpu-name`, `gpu-device-uuid-differs-from-name`, `gpu-device-binding-not-nras-nonce`.

### NVD-3. The device nonce derives from the envelope's nonce and ignores the key

A GPU's SPDM nonce is `SHA-256(nonce || "NVIDIA-GPU-EAT-v1")` and an NVSwitch's is `SHA-256(nonce || "NVIDIA-SWITCH-EAT-v1")`. Device evidence carries no key binding.

- Why: NRAS derives the device challenge from a nonce it is given, so the key cannot be bound there. The devices answer the same challenge as the CPU, which is all `ear_all_submods_bound` states; it proves nothing about co-location (Section 15.6).
- Where: Section 5.4, Appendix B.1.

### NVD-4. One request per architecture, and the batch must come back whole

The verifier sends one NRAS request per architecture with every device of that architecture, in ascending order of submodule name, and maps the returned device tokens back by position. The number of device tokens must equal the number of devices sent, and each device token's `hwmodel` must name the batch's architecture.

- Why: NRAS names device tokens by position, so the order sent is the only link between a token and a submodule.
- Where: Sections 9.7.1, 9.7.2.

### NVD-5. NRAS's answer is authenticated token by token

Every token is an ES384 JWS under a key from NRAS's JWKS whose certificate chain ends at the pinned NVIDIA certificate. Every token's `iss` is the endpoint's origin, the overall token's nonce equals the device nonce, its `submods` digests cover exactly the device tokens, and each device token's nonce equals the device nonce.

- Why: the overall token alone would let a response mix tokens from another exchange.
- Where: Section 9.7.2, Appendix E.

### NVD-6. Device gates are strict by default

A device must have debug disabled, secure boot on, NRAS's nonce match true and measurements successful. Each gate has a named relaxation in `gpu.device_policy`. When the nonce-match gate is waived and NRAS reports a device's nonce match as false, the device is accepted and the appraisal carries `ear_all_submods_bound` `"false"`.

- Why: the waiver exists for device evidence NRAS could not bind to this nonce, which can be a replay, and the relying party must see that it was accepted.
- Where: Sections 9.7.3, 12.6, 13.5. RES-9 (layer 8) is open on the form of the claim.

### NVD-7. The verifier never asks NRAS to relax its certificate checks

A request that tells NRAS to accept device certificates whose OCSP status is on hold is outside the profile, and a verifier configured to send one refuses with `unsupported`.

- Why: the relaxation is invisible in NRAS's answer, so a relying party could not tell a held certificate was accepted.
- Where: Section 9.7.1.

### NVD-8. A device's identity is the signed `ueid`, and the policy can require devices

The machine allowlist compares the `ueid` NRAS signed, never the submodule's name. `gpu.required` refuses evidence without a device, and `gpu.expected_archs` refuses a device of another architecture.

- Why: the name is the attester's label. A policy that needs a GPU must be able to refuse a CPU-only envelope.
- Where: Sections 9.7.3, 13.3, 13.5. Cases: `snp-gpu-required-without-device`, `snp-gpu-arch-not-allowed`.
