#![no_main]

use attestation::platforms::gcp_endorsement::fuzz_parse_golden;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_parse_golden(data);
});
