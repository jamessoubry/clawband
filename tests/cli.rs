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

// ── Item #3: variable-indirection ask (e2e) ───────────────────────────────────

#[test]
fn e2e_var_indirection_asks() {
    // `cmd=rm; $cmd -rf /tmp/x` — the $cmd token leads the second segment
    let out = run(&bash("cmd=rm; $cmd -rf /tmp/x"), &[]);
    assert_eq!(
        decision(&out),
        Some("ask"),
        "variable-indirection pattern should trigger ask"
    );
}

#[test]
fn e2e_echo_dollar_home_no_false_positive() {
    // `echo $HOME` has a real command word first — must not trigger ask
    let out = run(&bash("echo $HOME"), &[]);
    assert_eq!(
        decision(&out),
        None,
        "echo $HOME must not be flagged as variable-indirection"
    );
}

// ── Item #4: script-scan non-regular file does not hang (e2e) ────────────────

#[test]
fn e2e_scan_nonregular_file_no_hang() {
    // Ask clawband to evaluate `bash /dev/stdin` — the hook must not hang trying
    // to read the non-regular file and must return no decision (safe skip).
    let out = run(&bash("bash /dev/stdin"), &[]);
    // No hang means we reach this assertion. The decision should be None
    // (no pattern fires on the command itself; script scan skips /dev/stdin).
    assert_eq!(
        decision(&out),
        None,
        "non-regular script path should be skipped without hanging"
    );
}

// ── Multi-agent mode tests ────────────────────────────────────────────────────

/// Check for Gemini-format `{"decision":"block",...}`.
fn gemini_decision(stdout: &str) -> Option<&'static str> {
    if stdout.contains("\"decision\":\"block\"") {
        Some("block")
    } else if stdout.contains("\"decision\":\"allow\"") {
        Some("allow")
    } else {
        None
    }
}

/// Check for Hermes-format `{"decision":"block",...}` or `{}` (allow).
fn hermes_decision(stdout: &str) -> Option<&'static str> {
    if stdout.contains("\"decision\":\"block\"") {
        Some("block")
    } else if stdout.trim() == "{}" {
        Some("allow")
    } else {
        None
    }
}

// ── Regression: no mode set = unchanged Claude behavior ──────────────────────

#[test]
fn e2e_regression_no_mode_claude_deny() {
    // With no CLAWBAND_MODE set, a denied command must produce Claude-format deny.
    let out = run(&bash("docker system prune"), &[]);
    assert_eq!(decision(&out), Some("deny"), "must deny in Claude mode");
    assert!(
        out.contains("hookSpecificOutput"),
        "must use Claude hookSpecificOutput format: {out}"
    );
    assert!(
        out.contains("[CLAWBAND]"),
        "must carry [CLAWBAND] prefix: {out}"
    );
}

#[test]
fn e2e_regression_no_mode_claude_ask() {
    // With no CLAWBAND_MODE set, an ask command must produce Claude-format ask.
    let out = run(&bash("git reset --hard HEAD~1"), &[]);
    assert_eq!(decision(&out), Some("ask"), "must ask in Claude mode");
    assert!(
        out.contains("hookSpecificOutput"),
        "must use Claude hookSpecificOutput format: {out}"
    );
}

// ── Codex mode ────────────────────────────────────────────────────────────────

#[test]
fn e2e_codex_deny_uses_hookspecificoutput() {
    // Codex: denied command → hookSpecificOutput with permissionDecision:deny
    let out = run(&bash("docker system prune"), &[("CLAWBAND_MODE", "codex")]);
    assert_eq!(decision(&out), Some("deny"), "codex must deny: {out}");
    assert!(
        out.contains("hookSpecificOutput"),
        "codex must use hookSpecificOutput shape: {out}"
    );
    assert!(
        out.contains("[CLAWBAND]"),
        "must carry [CLAWBAND] prefix: {out}"
    );
}

#[test]
fn e2e_codex_safe_command_passes() {
    // Codex: a safe command produces no output (pass).
    let out = run(&bash("ls -la"), &[("CLAWBAND_MODE", "codex")]);
    assert_eq!(decision(&out), None, "codex must pass safe command: {out}");
}

#[test]
fn e2e_codex_ask_fallback_default_allow() {
    // Codex: ask tier → allow by default (ask_fallback=allow is the default;
    // non-Claude agents can't render an interactive ask). git reset --hard
    // triggers ask.
    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "codex")],
    );
    assert_eq!(
        decision(&out),
        Some("allow"),
        "codex ask-tier must fall back to allow by default: {out}"
    );
}

#[test]
fn e2e_codex_ask_fallback_deny_explicit() {
    // Codex with ask_fallback=deny: ask tier → hard deny with the hint reason.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_codex_dn_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(home.join(".clawband/config"), "ask_fallback = deny\n").unwrap();
    let h = home.to_str().unwrap();

    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "codex"), ("HOME", h)],
    );
    assert_eq!(
        decision(&out),
        Some("deny"),
        "codex ask-tier with ask_fallback=deny must deny: {out}"
    );
    assert!(
        out.contains("ask_fallback=allow to permit"),
        "fallback reason must mention ask_fallback=allow: {out}"
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn e2e_codex_ask_fallback_allow_permits() {
    // Codex with ask_fallback=allow: ask tier → allow.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_codex_fb_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(home.join(".clawband/config"), "ask_fallback = allow\n").unwrap();
    let h = home.to_str().unwrap();

    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "codex"), ("HOME", h)],
    );
    assert_eq!(
        decision(&out),
        Some("allow"),
        "codex ask-tier with ask_fallback=allow must allow: {out}"
    );
    let _ = fs::remove_dir_all(&home);
}

// ── Gemini mode ───────────────────────────────────────────────────────────────

#[test]
fn e2e_gemini_deny_uses_block_json() {
    // Gemini: denied command → {"decision":"block","reason":"..."}
    let out = run(&bash("docker system prune"), &[("CLAWBAND_MODE", "gemini")]);
    assert_eq!(
        gemini_decision(&out),
        Some("block"),
        "gemini must block: {out}"
    );
    assert!(
        out.contains("[CLAWBAND]"),
        "must carry [CLAWBAND] prefix: {out}"
    );
    // Must NOT use hookSpecificOutput (different shape)
    assert!(
        !out.contains("hookSpecificOutput"),
        "gemini must not use hookSpecificOutput: {out}"
    );
}

#[test]
fn e2e_gemini_safe_command_passes() {
    // Gemini: a safe command produces no output.
    let out = run(&bash("ls -la"), &[("CLAWBAND_MODE", "gemini")]);
    assert_eq!(
        gemini_decision(&out),
        None,
        "gemini must pass safe command: {out}"
    );
}

#[test]
fn e2e_gemini_ask_fallback_default_allow() {
    // Gemini: ask tier → allow by default (ask_fallback=allow).
    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "gemini")],
    );
    assert_eq!(
        gemini_decision(&out),
        Some("allow"),
        "gemini ask-tier must fall back to allow by default: {out}"
    );
}

#[test]
fn e2e_gemini_ask_fallback_deny_explicit() {
    // Gemini with ask_fallback=deny: ask tier → block.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_gemini_dn_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(home.join(".clawband/config"), "ask_fallback = deny\n").unwrap();
    let h = home.to_str().unwrap();

    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "gemini"), ("HOME", h)],
    );
    assert_eq!(
        gemini_decision(&out),
        Some("block"),
        "gemini ask-tier with ask_fallback=deny must block: {out}"
    );
    let _ = fs::remove_dir_all(&home);
}

// ── Hermes mode ───────────────────────────────────────────────────────────────

#[test]
fn e2e_hermes_deny_uses_block_json() {
    // Hermes: denied command → {"decision":"block","reason":"..."}
    let out = run(&bash("docker system prune"), &[("CLAWBAND_MODE", "hermes")]);
    assert_eq!(
        hermes_decision(&out),
        Some("block"),
        "hermes must block: {out}"
    );
    assert!(
        out.contains("[CLAWBAND]"),
        "must carry [CLAWBAND] prefix: {out}"
    );
    assert!(
        !out.contains("hookSpecificOutput"),
        "hermes must not use hookSpecificOutput: {out}"
    );
}

#[test]
fn e2e_hermes_safe_command_passes_silently() {
    // Hermes: a safe command produces no output (pass-through).
    let out = run(&bash("ls -la"), &[("CLAWBAND_MODE", "hermes")]);
    // No block decision on safe command
    assert_ne!(
        hermes_decision(&out),
        Some("block"),
        "hermes must not block safe command: {out}"
    );
}

#[test]
fn e2e_hermes_ask_fallback_default_allow() {
    // Hermes: ask tier → allow by default (ask_fallback=allow; rendered as `{}`).
    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "hermes")],
    );
    assert_eq!(
        hermes_decision(&out),
        Some("allow"),
        "hermes ask-tier must fall back to allow by default: {out}"
    );
}

#[test]
fn e2e_hermes_ask_fallback_deny_explicit() {
    // Hermes with ask_fallback=deny: ask tier → block.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_hermes_dn_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(home.join(".clawband/config"), "ask_fallback = deny\n").unwrap();
    let h = home.to_str().unwrap();

    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "hermes"), ("HOME", h)],
    );
    assert_eq!(
        hermes_decision(&out),
        Some("block"),
        "hermes ask-tier with ask_fallback=deny must block: {out}"
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn e2e_hermes_ask_fallback_allow() {
    // Hermes with ask_fallback=allow: ask tier → allow (rendered as `{}`).
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_hermes_fb_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(home.join(".clawband/config"), "ask_fallback = allow\n").unwrap();
    let h = home.to_str().unwrap();

    let out = run(
        &bash("git reset --hard HEAD~1"),
        &[("CLAWBAND_MODE", "hermes"), ("HOME", h)],
    );
    // With ask_fallback=allow, hermes renders allow as `{}`
    assert_eq!(
        hermes_decision(&out),
        Some("allow"),
        "hermes ask-tier with ask_fallback=allow must output {{}}: {out}"
    );
    let _ = fs::remove_dir_all(&home);
}

// ── tool_name-agnostic command routing ───────────────────────────────────────

#[test]
fn e2e_hermes_terminal_tool_name_routed() {
    // Hermes uses tool_name "terminal" instead of "Bash" — the hook must still
    // route on tool_input.command regardless of tool_name.
    let json = r#"{"tool_name":"terminal","tool_input":{"command":"docker system prune"}}"#;
    let out = run(json, &[("CLAWBAND_MODE", "hermes")]);
    assert_eq!(
        hermes_decision(&out),
        Some("block"),
        "hermes must route on tool_input.command regardless of tool_name: {out}"
    );
}

#[test]
fn e2e_arbitrary_tool_name_with_command_routed() {
    // Any tool whose tool_input.command is non-empty should be evaluated.
    let json = r#"{"tool_name":"run_shell","tool_input":{"command":"docker system prune"}}"#;
    let out = run(json, &[("CLAWBAND_MODE", "gemini")]);
    assert_eq!(
        gemini_decision(&out),
        Some("block"),
        "arbitrary tool_name with command must be routed: {out}"
    );
}

// ── Mode via config file ──────────────────────────────────────────────────────

#[test]
fn e2e_mode_from_config_file() {
    // When mode = gemini is set in ~/.clawband/config, the gemini output format
    // is used even without CLAWBAND_MODE env var.
    use std::fs;
    let home = std::env::temp_dir().join(format!("cb_mode_cfg_{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".clawband")).unwrap();
    fs::write(home.join(".clawband/config"), "mode = gemini\n").unwrap();
    let h = home.to_str().unwrap();

    let out = run(&bash("docker system prune"), &[("HOME", h)]);
    assert_eq!(
        gemini_decision(&out),
        Some("block"),
        "mode from config file must activate gemini format: {out}"
    );
    assert!(
        !out.contains("hookSpecificOutput"),
        "must not use Claude format when mode=gemini in config: {out}"
    );
    let _ = fs::remove_dir_all(&home);
}
