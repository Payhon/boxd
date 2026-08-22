#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;
const MAX_ENTRY: usize = 512;
const MAX_ENTRIES: usize = 128;

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

// The archive importer rejects unsafe archive paths before publication. The
// public importer takes filesystem sources, so this hermetic target fuzzes
// the same bounded path grammar without creating attacker-controlled files.
fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_INPUT)];
    for entry in input.split(|byte| *byte == b'\n').take(MAX_ENTRIES) {
        let entry = &entry[..entry.len().min(MAX_ENTRY)];
        let value = String::from_utf8_lossy(entry);
        let _ = safe_relative_path(value.trim());
    }
});
