| File | Source |
| --- | --- |
| `nras_gpu_x5c_chain.json` | the `x5c` chain of a production NRAS JWKS entry, recorded from `https://nras.attestation.nvidia.com/.well-known/jwks.json` |
| `nras_v4_hopper_detached_eat.json` | NVIDIA/attestation-sdk `nv-attestation-sdk-cpp/unit-tests/testdata/sample_attestation_data/hopperClaimsv3_detached_eat.json` at `0c1be386a8fbb8f2766a6a556d10df86f5fed9d3` (Apache-2.0): a production `/v4/attest/gpu` response with claims version 3.0, recorded 2025-06-10 |
| `nras_v4_switch_detached_eat.json` | same source, `switch_detached_eat.json`: a staging `/v4/attest/switch` response with claims version 3.0, recorded 2025-06-28 |

The recorded tokens have expired and their signing keys have rotated, so tests use them for the response shape, the `submods` digests and the claim mapping, never for signature verification.
