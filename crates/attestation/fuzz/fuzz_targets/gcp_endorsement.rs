#![no_main]

use attestation::platforms::gcp_endorsement::{fuzz_parse_golden, verify_endorsement};
use libfuzzer_sys::fuzz_target;

// 2026-10-01T00:00:00Z, inside the bundled root's validity.
const NOW: i64 = 1_790_812_800;

fuzz_target!(|data: &[u8]| {
    let _ = verify_endorsement(data, NOW);
    fuzz_parse_golden(data);
});
