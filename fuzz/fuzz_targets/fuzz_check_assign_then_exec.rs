#![no_main]

use clawband::{check_assign_then_exec, split_segments};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

const MAX_RUNTIME: Duration = Duration::from_secs(2);

// check_assign_then_exec() looks for `cmd=rm; $cmd -rf /tmp/x`-style
// variable-indirection patterns spread across compound-command segments.
// Fed through split_segments() first so the fuzzer explores the same
// segment shapes the real pipeline produces.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let segments = split_segments(s);

    let start = Instant::now();
    let _ = check_assign_then_exec(&segments);
    assert!(
        start.elapsed() < MAX_RUNTIME,
        "check_assign_then_exec did not return within the bounded-runtime limit"
    );
});
