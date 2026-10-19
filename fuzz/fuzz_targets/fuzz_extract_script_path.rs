#![no_main]

use clawband::extract_script_path;
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

const MAX_RUNTIME: Duration = Duration::from_secs(2);

// extract_script_path() is used to decide whether to open and scan a file
// from disk based on attacker-controlled command text. Property: it must
// never panic/hang, and the path it returns (if any) must be derived from
// the input — never an empty string standing in for "no path", which
// downstream file-opening code could otherwise misinterpret.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let start = Instant::now();
    let path = extract_script_path(s);
    assert!(
        start.elapsed() < MAX_RUNTIME,
        "extract_script_path did not return within the bounded-runtime limit"
    );

    if let Some(p) = path {
        assert!(
            !p.is_empty(),
            "extract_script_path returned an empty path instead of None"
        );
    }
});
