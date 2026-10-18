#![no_main]

use clawband::{builtin_ask, builtin_deny, check_command, Pattern};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

const MAX_RUNTIME: Duration = Duration::from_secs(2);

// check_command() is the core evaluation pipeline and the single most
// attacker-reachable surface in clawband: every Bash command the agent
// wants to run flows through it. Properties under fuzz:
//   - never panics on arbitrary (including malformed/invalid-UTF-8) input
//   - never hangs (bounded runtime, catches catastrophic regex backtracking)
//   - always returns a structurally valid decision: None, Some(("deny", _))
//     or Some(("ask", _)) — never any other tag
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let deny_pats: Vec<Pattern> = builtin_deny();
    let ask_pats: Vec<Pattern> = builtin_ask();
    let allow_pats: Vec<Pattern> = Vec::new();

    let start = Instant::now();
    let decision = check_command(s, &deny_pats, &ask_pats, &allow_pats);
    assert!(
        start.elapsed() < MAX_RUNTIME,
        "check_command did not return within the bounded-runtime limit"
    );

    if let Some((tag, _reason)) = decision {
        assert!(
            tag == "deny" || tag == "ask",
            "check_command returned an invalid decision tag: {tag:?}"
        );
    }
});
