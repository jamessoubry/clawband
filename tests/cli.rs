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
