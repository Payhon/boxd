#![no_main]

use box_egress::{build_dns_nodata_response, inspect_dns_query};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 1_232;

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT)];
    if let Ok(query) = inspect_dns_query(input) {
        let _ = build_dns_nodata_response(input);
        // The public query object intentionally exposes only bounded metadata;
        // the canonical name is not available to a fuzzer or a log sink.
        let _ = query.id;
    } else {
        let _ = build_dns_nodata_response(input);
    }
});
