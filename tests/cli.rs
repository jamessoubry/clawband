//! End-to-end tests: pipe real Claude Code hook JSON through the built binary
//! and assert on the decision. These catch tool-routing regressions (Bash vs
//! Write/Edit) and JSON I/O bugs that unit tests of `check_command` can't.

use std::io::Write;
use std::process::{Command, Stdio};

/// Run the built clawband binary with `stdin`, returning (stdout, exit_ok).
/// Optional env overrides are applied (e.g. CLAWBAND_SKIP, HOME).
fn run(stdin: &str, env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_clawband"));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Neutralise ambient config so tests are deterministic regardless of the
    // machine's real ~/.clawband or env.
    cmd.env_remove("CLAWBAND_SKIP")
        .env_remove("RTK_ENABLED")
        .env_remove("SQZ_ENABLED")
        .env_remove("CLAWBAND_LOG");
    cmd.env("HOME", "/nonexistent-clawband-test-home");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn clawband");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait clawband");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn decision(stdout: &str) -> Option<&'static str> {
    if stdout.contains("\"permissionDecision\":\"deny\"") {
        Some("deny")
    } else if stdout.contains("\"permissionDecision\":\"ask\"") {
        Some("ask")
    } else if stdout.contains("\"permissionDecision\":\"allow\"") {
        Some("allow")
    } else {
        None // empty output = pass
    }
}

fn bash(command: &str) -> String {
    format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":{:?}}}}}"#,
        command
    )
}

#[test]
fn e2e_blocks_destructive_bash() {
    let out = run(&bash("docker system prune"), &[]);
    assert_eq!(decision(&out), Some("deny"));
    // attribution prefix is present in the reason
    assert!(
        out.contains("[CLAWBAND]"),
        "reason should be prefixed: {out}"
    );
}

#[test]
fn e2e_compound_command_caught() {
    let out = run(&bash("ls -la && git push --force"), &[]);
    assert_eq!(decision(&out), Some("deny"));
}

#[test]
fn e2e_safe_command_passes() {
    let out = run(&bash("ls -la"), &[]);
    assert_eq!(decision(&out), None);
}

#[test]
fn e2e_ask_command() {
    let out = run(&bash("git reset --hard HEAD~1"), &[]);
    assert_eq!(decision(&out), Some("ask"));
}

#[test]
fn e2e_skip_bypasses_everything() {
    let out = run(&bash("docker system prune"), &[("CLAWBAND_SKIP", "1")]);
    assert_eq!(decision(&out), None, "CLAWBAND_SKIP=1 should bypass");
}

#[test]
fn e2e_non_bash_tool_without_protect_is_noop() {
    // Write tool, no protect.paths in the test HOME -> no decision (allow).
    let json = r#"{"tool_name":"Write","tool_input":{"file_path":"/etc/passwd"}}"#;
    let out = run(json, &[]);
    assert_eq!(decision(&out), None);
}

#[test]
fn e2e_malformed_json_is_safe_noop() {
    // Garbage stdin must not crash or emit a decision.
    let out = run("not json at all", &[]);
    assert_eq!(decision(&out), None);
}

#[test]
fn e2e_allow_pattern_emits_explicit_allow() {
    // A full-command match in allow.patterns should emit permissionDecision:allow
    // (so Claude Code skips its own check), while an unrelated command still passes
    // silently (None) — proving allow is scoped to the listed command only.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_allow_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(
        home.join(".clawband/allow.patterns"),
        "^cd \\S+ && git log\n",
    )
    .unwrap();
    let h = home.to_str().unwrap();

    let allowed = run(&bash("cd /tmp && git log 2>/dev/null"), &[("HOME", h)]);
    assert_eq!(decision(&allowed), Some("allow"));

    let other = run(&bash("echo hello"), &[("HOME", h)]);
    assert_eq!(
        decision(&other),
        None,
        "non-listed command must stay silent"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn e2e_default_decision_config() {
    // default_decision in ~/.clawband/config controls what an unmatched command does.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_dd_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    let h = home.to_str().unwrap();
    let unmatched = bash("echo hello world"); // matches nothing

    // passthrough (default) → silent
    fs::write(
        home.join(".clawband/config"),
        "default_decision = passthrough\n",
    )
    .unwrap();
    assert_eq!(decision(&run(&unmatched, &[("HOME", h)])), None);

    // allow → explicit allow
    fs::write(home.join(".clawband/config"), "default_decision = allow\n").unwrap();
    assert_eq!(decision(&run(&unmatched, &[("HOME", h)])), Some("allow"));

    // ask → explicit ask
    fs::write(home.join(".clawband/config"), "default_decision = ask\n").unwrap();
    assert_eq!(decision(&run(&unmatched, &[("HOME", h)])), Some("ask"));

    // a denied command is STILL denied regardless of default_decision=allow
    fs::write(home.join(".clawband/config"), "default_decision = allow\n").unwrap();
    assert_eq!(
        decision(&run(&bash("docker system prune"), &[("HOME", h)])),
        Some("deny"),
        "default_decision must not override deny patterns"
    );

    let _ = fs::remove_dir_all(&home);
}

#[test]
fn e2e_long_command_with_multibyte_does_not_crash_logger() {
    // Regression: log_action truncated by BYTE index, which panics if a multibyte
    // char straddles the cut — and because logging runs before the decision is
    // emitted, the crashed hook would fail OPEN. Build a denied command with a
    // 3-byte char at byte boundary 200, with logging ON, and assert it still denies.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_utf8_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let h = home.to_str().unwrap();

    let mut cmd = "a".repeat(199); // bytes 0..199
    cmd.push('€'); // 3 bytes at 199,200,201 — byte 200 is mid-char
    cmd.push_str(" ; docker system prune"); // denied segment

    let out = run(&bash(&cmd), &[("HOME", h), ("CLAWBAND_LOG", "1")]);
    assert_eq!(
        decision(&out),
        Some("deny"),
        "must still deny (no panic / fail-open) on multibyte-boundary command"
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn e2e_version_flag() {
    let out = run("", &[]); // stdin unused for --version path; invoke separately
    let _ = out;
    let v = Command::new(env!("CARGO_BIN_EXE_clawband"))
        .arg("--version")
        .output()
        .expect("run --version");
    let s = String::from_utf8_lossy(&v.stdout);
    assert!(s.starts_with("clawband v"), "got: {s}");
}
