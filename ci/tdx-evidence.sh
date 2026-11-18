#!/usr/bin/env bash
# TDX evidence payload: capture live Intel TDX evidence inside a TD and verify it.
#
# confidential-ci's tdx-evidence lane boots a per-job TD from the pinned
# confidential-os general-purpose image, clones this repo at the dispatched ref
# and runs this script as root over SSH. The cvm-e2e payload contract applies:
# `@@PAYLOAD_OK@@` on the last line is the gate, `@@...@@` lines are progress,
# The TD is 8 vCPU / 16Gi with a scratch disk.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { echo "@@$1@@"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (id -u = $(id -u))"; exit 1; }

step REPORT_INTERFACE
[ -e /dev/tdx_guest ] || [ -d /sys/kernel/config/tsm/report ] \
  || { echo "TDX report interface missing: /dev/tdx_guest absent and configfs-tsm not mounted"; exit 1; }

step DEPS
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  libtss2-dev pkg-config build-essential curl ca-certificates
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 300 \
  --retry 3 --retry-all-errors https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
# shellcheck source=/dev/null
. "$HOME/.cargo/env"
curl -fsSL --connect-timeout 10 --max-time 120 --retry 3 --retry-all-errors \
  https://get.nexte.st/0.9/linux | tar -xz -C /usr/local/bin cargo-nextest
cargo-nextest --version

# capture_fixture also holds the Azure fixtures, and az-snp/az-tdx are default
# features, so the test filter names the one native test: there is no vTPM or IMDS here.
step TEST
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_BUILD_JOBS=4   # 16Gi guest: about 4Gi per concurrent rustc
TEST_THREADS=4              # 8 vCPU: half the cores, leaving the rest to builds the tests spawn
select=(-p attestation --test capture_fixture --features attest --run-ignored all
  -E 'test(capture_tdx_evidence_fixture)')
selected=$(cargo nextest list "${select[@]}" --message-format oneline)
[ -n "$selected" ] || { echo "filter selects no tests"; exit 1; }
echo "$selected"
cargo nextest run "${select[@]}" --test-threads "$TEST_THREADS"

echo "@@PAYLOAD_OK@@"
