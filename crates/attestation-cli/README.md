# attestation-cli

Build from the workspace root:

```sh
cargo build --locked -p attestation-cli --release --features attest,nvidia-gpu
```

`attest` and `detect` are Linux-only. This build verifies NVIDIA bundles but
does not collect them; collection requires `nvidia-gpu-attest` and NVIDIA's
SDK/runtime. See [capabilities](../../README.md#capabilities).

## Generate and verify

On a compatible guest (use a fresh relying-party challenge, not this literal):

```sh
attestation-cli detect
attestation-cli attest --platform snp --report-data "example-challenge" --output evidence.json
```

`--report-data`, `--report-data-hex` and `--report-data-file` are mutually
exclusive. Omission uses empty report data. Generation attempts to attach
collateral; a warning or partial attachment does not make generation fail.

Verification works without TEE hardware. `NONCE_HEX` is the challenge's hex
encoding, chosen independently of the evidence:

```sh
attestation-cli verify --evidence evidence.json --platform snp   --expected-report-data "$NONCE_HEX"
```

The CLI has no SNP measurement-register mode; verify that evidence through the
library or the attestation-api `/verify` policies
([measurement registers](../attestation/README.md#snp-kernel-measurement-registers)).
On a report from a measurement-register kernel, `REPORT_DATA` is the kernel's
commitment, so `--expected-report-data` with the requester's bytes fails.

Use measurement pins to identify an approved workload. For TDX, where `MRTD`
and `RTMR1` are trusted 96-character hex values:

```sh
attestation-cli verify --platform tdx --expected-report-data "$NONCE_HEX"   --expected-mrtd "$MRTD" --expected-rtmr1 "$RTMR1" < evidence.json
```

`--platform` is repeatable. Without it, platform-specific pins determine the
accepted intersection: MRTD/RTMR pins accept TDX variants, launch-digest pins
accept SNP variants, and PCR pins accept Azure variants. No platform and no
platform-specific pins is exit 2; the evidence tag never chooses your policy.
A pin irrelevant to an explicitly accepted platform is also exit 2.

`--expected-mrtd`, `--expected-rtmr0`–`--expected-rtmr3` and
`--expected-launch-digest` are repeatable allowlists, each 48-byte hex values.
`--expected-pcr INDEX=HEX` pins a 32-byte SHA-256 PCR at index 0–23; repeat an
index only once. `--expected-init-data` pins TDX MRCONFIGID, SNP HOST_DATA or
Azure PCR[8] init-data hash. See [Policies](../attestation/README.md#policies)
for defaults and platform semantics.

GPU verification uses `--nvidia-gpu-user-nonce HEX`; if CPU report data is not
pinned explicitly it is set to that nonce. Add `--nvidia-gpu-required` to
reject a missing bundle, and optionally
`--nvidia-gpu-expected-archs HOPPER,BLACKWELL,LS10`. The nonce must be at least
16 bytes. [NRAS remains necessary](../../docs/collateral.md#nvidia-gpu) when no
usable attached answer is available.

## Output and exit codes

Verification writes JSON including `passed` to stdout, diagnostics to stderr.
Use the exit code or `passed`, not the removed `signature_valid` field.

| Verify exit | Meaning |
| --- | --- |
| 0 | All checks passed |
| 1 | Policy/freshness rejection or non-genuine/unverifiable evidence |
| 2 | Usage, input-file or invalid-parameter error |
| 3 | Collateral unavailable; bounded retry may help |

These are the `verify` contract; generation and detection failures use exit 1.
Only exit 3 is the retryable verification category. `RUST_LOG=info` enables
upstream-selection logging (default level: warn).

Collateral persists in the OS user cache directory under `attestation` when
that directory can be resolved. `--offline` disables network and uses attached
and saved collateral; a missing piece exits 3. Offline mode is not an expiry
or policy bypass. There are no CLI flags for upstream, floors or grace:
[discovery and freshness](../../docs/collateral.md) apply.
