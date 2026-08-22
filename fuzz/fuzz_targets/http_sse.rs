#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const MAX_INPUT: usize = 64 * 1024;
const MAX_FRAME: usize = 8 * 1024;

// Bounded parser boundary for HTTP/SSE payloads. The production Salvo stream
// owns transport/auth; this target proves that event framing and JSON decoding
// never allocate from an attacker-controlled unbounded line/frame.
fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT)];
    for frame in input.split(|byte| *byte == b'\n' || *byte == 0).take(64) {
        let frame = &frame[..frame.len().min(MAX_FRAME)];
        let text = String::from_utf8_lossy(frame);
        let mut data = String::new();
        for line in text.lines().take(128) {
            if let Some(value) = line.strip_prefix("data:") {
                if data.len() + value.len() <= MAX_FRAME {
                    data.push_str(value.trim_start());
                }
            }
        }
        if !data.is_empty() {
            let _ = serde_json::from_str::<Value>(&data);
        }
    }
});
