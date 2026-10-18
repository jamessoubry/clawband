#![no_main]

use clawband::{builtin_ask, builtin_deny, check_subshells, Pattern};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

const MAX_RUNTIME: Duration = Duration::from_secs(2);

// check_subshells() recursively extracts and re-checks $(...) / `...`
// command-substitution bodies. Recursion over attacker-controlled nesting is
// exactly the kind of surface that can hang or blow the stack, so the bound
// here matters more than most of the other targets.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let deny_pats: Vec<Pattern> = builtin_deny();
    let ask_pats: Vec<Pattern> = builtin_ask();
    let allow_pats: Vec<Pattern> = Vec::new();

    let start = Instant::now();
    let decision = check_subshells(s, &deny_pats, &ask_pats, &allow_pats);
    assert!(
        start.elapsed() < MAX_RUNTIME,
        "check_subshells did not return within the bounded-runtime limit"
    );

    if let Some((tag, _reason)) = decision {
        assert!(
            tag == "deny" || tag == "ask",
            "check_subshells returned an invalid decision tag: {tag:?}"
        );
    }
});
