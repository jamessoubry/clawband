//! Latency benchmarks for the hook's hot path.
//!
//! clawband sits directly in the agent's execution path — every Bash tool
//! call blocks on a decision from `check_command()` (plus, when the command
//! contains `$(...)`/`` `...` ``, `check_subshells()`) before it is allowed
//! to run. Unlike correctness, which is covered by unit/e2e tests and the
//! `fuzz/` crate, latency here was previously unmeasured. These benchmarks
//! cover the shapes called out in issue #287: a short safe/denied command,
//! a large compound command, a large script-shaped blob, a case engineered
//! to exercise many patterns before resolving, nested subshells, a large
//! heredoc/encoded payload that trips an early deny short-circuit, and a
//! separate large encoded payload that actually reaches the decode-and-scan
//! path. Criterion's own console/HTML report covers p50/p95/p99/max — no
//! manual percentile tracking needed here.

use clawband::{builtin_ask, builtin_deny, check_command, check_subshells, Pattern};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn deny_pats() -> Vec<Pattern> {
    builtin_deny()
}
fn ask_pats() -> Vec<Pattern> {
    builtin_ask()
}
fn no_allow() -> Vec<Pattern> {
    Vec::new()
}

/// A long, well-formed but entirely benign compound command, so the full
/// pattern set has to be walked across every segment without an early
/// deny/ask short-circuit. Exercises the "many patterns" case: every
/// built-in deny/ask pattern gets a chance to run its regex against text
/// that doesn't match it.
fn many_patterns_benign_command() -> String {
    (0..60)
        .map(|i| format!("echo 'build step {i} completed successfully'"))
        .collect::<Vec<_>>()
        .join(" && ")
}

/// A large compound command: many `&&`-joined segments, each a realistic
/// short shell invocation.
fn large_compound_command() -> String {
    (0..200)
        .map(|i| format!("cd /tmp/build_{i} && make -j4 && cp out.bin /artifacts/{i}.bin"))
        .collect::<Vec<_>>()
        .join(" && ")
}

/// A "large script" shape: a single command string whose body resembles a
/// sizeable inline script (many newline-separated statements), the way a
/// heredoc'd or `bash -c`'d multi-statement script looks to the scanner.
fn large_script_command() -> String {
    let mut s = String::from("bash -c '");
    for i in 0..500 {
        s.push_str(&format!("echo line_{i}; "));
    }
    s.push('\'');
    s
}

/// Deeply nested command substitutions: `$(... $(... $(...) ...) ...)`.
/// check_subshells() recurses into these, so this is the shape most likely
/// to reveal pathological recursive-regex or stack-depth behavior.
fn nested_subshells_command(depth: usize) -> String {
    let mut s = String::from("echo ");
    for _ in 0..depth {
        s.push_str("$(echo ");
    }
    s.push_str("inner");
    for _ in 0..depth {
        s.push(')');
    }
    s
}

/// A large heredoc / base64-style encoded payload embedded in an otherwise
/// short command — simulates `cat <<'EOF' | base64 -d | bash` style
/// obfuscation attempts with a sizeable encoded blob.
///
/// Note: this shape is caught by the "base64 decode | interpreter" deny
/// pattern on the *outer* command text (`| base64 -d | bash`) before
/// `check_command` ever reaches the body-scanning/decode path — so this
/// benchmark only measures that early-denial short-circuit, not the actual
/// decode-and-scan work. See `large_encoded_payload_for_scan_command` below
/// for a fixture that genuinely exercises the decode/scan path.
fn large_heredoc_command() -> String {
    let payload: String = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(2000);
    format!("cat <<'EOF' | base64 -d | bash\n{payload}\nEOF")
}

/// Minimal base64 encoder (standard alphabet, `=` padding) — just enough to
/// build a large encoded benchmark fixture without pulling in a dependency.
fn encode_base64(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// A large base64-encoded payload that actually reaches `check_command`'s
/// decode-and-scan path (`check_encoded_payload` / `scan_decoded_content`,
/// issue #221): `echo '<base64>' | base64 -d` alone — no further pipe to an
/// interpreter and no redirect — so none of the earlier "base64 decode |
/// interpreter" / "base64 decode redirect" deny patterns short-circuit it
/// first. The decoded body is a sizeable (~70KB) multi-line, entirely
/// benign script, so this measures real decode + full segment/pattern scan
/// work over a large payload instead of an early-denial short-circuit.
fn large_encoded_payload_for_scan_command() -> String {
    let body: String = (0..2000)
        .map(|i| format!("echo 'line_{i} is safe'\n"))
        .collect();
    let encoded = encode_base64(body.as_bytes());
    format!("echo '{encoded}' | base64 -d")
}

fn bench_short_safe_command(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    c.bench_function("short_safe_command", |b| {
        b.iter(|| black_box(check_command(black_box("git status"), &dp, &ap, &al)))
    });
}

fn bench_short_denied_command(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    c.bench_function("short_denied_command", |b| {
        b.iter(|| black_box(check_command(black_box("rm -rf /"), &dp, &ap, &al)))
    });
}

fn bench_large_compound_command(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    let cmd = large_compound_command();
    c.bench_function("large_compound_command", |b| {
        b.iter(|| black_box(check_command(black_box(cmd.as_str()), &dp, &ap, &al)))
    });
}

fn bench_large_script(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    let cmd = large_script_command();
    c.bench_function("large_script", |b| {
        b.iter(|| black_box(check_command(black_box(cmd.as_str()), &dp, &ap, &al)))
    });
}

fn bench_many_patterns(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    let cmd = many_patterns_benign_command();
    c.bench_function("many_patterns_benign", |b| {
        b.iter(|| black_box(check_command(black_box(cmd.as_str()), &dp, &ap, &al)))
    });
}

fn bench_nested_subshells(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    let cmd = nested_subshells_command(25);
    c.bench_function("nested_subshells", |b| {
        b.iter(|| black_box(check_subshells(black_box(cmd.as_str()), &dp, &ap, &al)))
    });
}

fn bench_large_heredoc_payload_early_denial(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    let cmd = large_heredoc_command();
    c.bench_function("large_heredoc_encoded_payload_early_denial", |b| {
        b.iter(|| black_box(check_command(black_box(cmd.as_str()), &dp, &ap, &al)))
    });
}

fn bench_large_encoded_payload_scan(c: &mut Criterion) {
    let dp = deny_pats();
    let ap = ask_pats();
    let al = no_allow();
    let cmd = large_encoded_payload_for_scan_command();
    c.bench_function("large_encoded_payload_scan", |b| {
        b.iter(|| black_box(check_command(black_box(cmd.as_str()), &dp, &ap, &al)))
    });
}

criterion_group!(
    benches,
    bench_short_safe_command,
    bench_short_denied_command,
    bench_large_compound_command,
    bench_large_script,
    bench_many_patterns,
    bench_nested_subshells,
    bench_large_heredoc_payload_early_denial,
    bench_large_encoded_payload_scan,
);
criterion_main!(benches);
