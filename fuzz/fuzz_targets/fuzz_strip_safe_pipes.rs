#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

const MAX_RUNTIME: Duration = Duration::from_secs(2);

// Property: strip_safe_pipes() never panics and never hangs on arbitrary
// input, regardless of quoting/escaping/Unicode content.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let start = Instant::now();
    let _ = clawband::strip_safe_pipes(s);
    assert!(
        start.elapsed() < MAX_RUNTIME,
        "strip_safe_pipes did not return within the bounded-runtime limit"
    );
});
