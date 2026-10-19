#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

// Properties under fuzz:
//   - never panics on arbitrary (including invalid-UTF-8) byte input
//   - never hangs: completes well under the bound below for any input
//   - the segment count can never exceed the input length (sanity bound —
//     catches pathological amplification bugs in the splitter itself)
const MAX_RUNTIME: Duration = Duration::from_secs(2);

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let start = Instant::now();
    let segments = clawband::split_segments(s);
    assert!(
        start.elapsed() < MAX_RUNTIME,
        "split_segments did not return within the bounded-runtime limit"
    );

    assert!(
        segments.len() <= s.len() + 1,
        "split_segments produced more segments than the input could plausibly contain"
    );
});
