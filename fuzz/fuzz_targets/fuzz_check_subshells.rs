#![no_main]

use clawband::{builtin_ask, builtin_deny, check_subshells, Pattern};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const MAX_RUNTIME: Duration = Duration::from_secs(2);

// Built-in deny/ask pattern sets are expensive to (re)compile (they're a few
// hundred regexes each). Rebuilding them on every single fuzz input, as the
// original version of this target did, spent the overwhelming majority of
// runtime on setup instead of on the code path under test. Build them once
// per process and reuse the same `Vec<Pattern>` across every invocation.
static DENY_PATS: OnceLock<Vec<Pattern>> = OnceLock::new();
static ASK_PATS: OnceLock<Vec<Pattern>> = OnceLock::new();
static ALLOW_PATS: OnceLock<Vec<Pattern>> = OnceLock::new();

// check_subshells() recursively extracts and re-checks $(...) / `...`
// command-substitution bodies. Recursion over attacker-controlled nesting is
// exactly the kind of surface that can hang or blow the stack, so the bound
// here matters more than most of the other targets.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let deny_pats = DENY_PATS.get_or_init(builtin_deny);
    let ask_pats = ASK_PATS.get_or_init(builtin_ask);
    let allow_pats = ALLOW_PATS.get_or_init(Vec::new);

    let start = Instant::now();
    let decision = check_subshells(s, deny_pats, ask_pats, allow_pats);
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
