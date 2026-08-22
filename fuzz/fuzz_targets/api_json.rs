#![no_main]

use box_image::RuntimeBundleManifest;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;

// This target exercises the public, deny-unknown-fields runtime manifest DTO.
// HTTP routing and auth are intentionally outside a hermetic fuzz target.
fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT)];
    let _ = serde_json::from_slice::<RuntimeBundleManifest>(input);
});
