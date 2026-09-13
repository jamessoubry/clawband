// Test fixtures for `redact_secrets()`/`log_action()` deliberately contain
// credential-*shaped* literal strings (fake values, but structurally similar
// to real tokens/keys/passwords) so the tests can verify they get redacted.
//
// This file is physically separate from main.rs (rather than living inline
// in main.rs's `#[cfg(test)] mod tests`) specifically so it matches this
// project's `.deepsource.toml` `test_patterns = ["tests/**", "**/*_test.rs"]`
// glob. DeepSource's Secrets analyzer matches by file path, not by module —
// it has no way to know an inline `mod tests { ... }` block inside main.rs is
// test code, so it was flagging these fixtures (even ones already renamed to
// obviously-fake EXAMPLE-suffixed values) as potential real credentials. See
// issue #286 and the review discussion on PR #295 for the full history.
//
// Included via `include!("redact_secrets_test.rs");` inside `mod tests` in
// main.rs, so it has the same scope (redact_secrets, log_action, fs,
// env_test_lock, with_fake_home, etc. are all already in scope at the
// include site) — this is textual inclusion, not a separate module.

// ── Issue #286: redact secrets from log previews ──────────────────────────

#[test]
fn redact_secrets_covers_all_documented_forms() {
    let cases = [
        (
            r#"curl -H "Authorization: Bearer FAKEBEARERTOKEN1234EXAMPLE" https://api.example.com"#,
            "FAKEBEARERTOKEN1234EXAMPLE",
        ),
        (
            "curl -H 'Authorization: FAKEPLAINTOKENXYZEXAMPLE' https://api.example.com",
            "FAKEPLAINTOKENXYZEXAMPLE",
        ),
        (
            "AWS_SECRET_ACCESS_KEY=FAKEAWSSECRETKEYEXAMPLE1234 aws s3 ls",
            "FAKEAWSSECRETKEYEXAMPLE1234",
        ),
        (
            "AWS_SESSION_TOKEN=FAKESESSIONTOKENEXAMPLE9999 aws sts get-caller-identity",
            "FAKESESSIONTOKENEXAMPLE9999",
        ),
        ("mysql -u root -p password=hunter2 db", "hunter2"),
        ("some-tool --passwd=letmein123", "letmein123"),
        ("some-tool --pwd='p@ssw0rd!'", "p@ssw0rd!"),
        (
            r#"curl -H "token=FAKETOKENVALUE123456EXAMPLE""#,
            "FAKETOKENVALUE123456EXAMPLE",
        ),
        (
            // Deliberately not shaped like a real Google API key (no
            // "AIza" prefix) so secret-scanners don't flag this test
            // fixture as a live credential — see issue #286 DeepSource
            // Secrets follow-up.
            "export api_key=FAKEKEY1234567890EXAMPLE",
            "FAKEKEY1234567890EXAMPLE",
        ),
        (
            "export apikey=FAKEKEY2345678901EXAMPLE",
            "FAKEKEY2345678901EXAMPLE",
        ),
        (
            "export api-key=FAKEKEY3456789012EXAMPLE",
            "FAKEKEY3456789012EXAMPLE",
        ),
        ("secret=topsecretvalue terraform apply", "topsecretvalue"),
    ];
    for (input, sensitive) in cases {
        let out = redact_secrets(input);
        assert!(
            !out.contains(sensitive),
            "expected {:?} to be redacted from {:?}, got {:?}",
            sensitive,
            input,
            out
        );
        assert!(
            out.contains("***REDACTED***"),
            "expected redaction marker in output for {:?}, got {:?}",
            input,
            out
        );
    }
}

#[test]
fn redact_secrets_handles_quoted_and_unquoted_values_case_insensitively() {
    let unquoted = redact_secrets("PASSWORD=mySecretPass123 run-thing");
    assert!(!unquoted.contains("mySecretPass123"));

    let double_quoted = redact_secrets(r#"Token="FAKETOKENVALUEEXAMPLE" run-thing"#);
    assert!(!double_quoted.contains("FAKETOKENVALUEEXAMPLE"));

    let single_quoted = redact_secrets("Secret='FAKESECRETVALUEEXAMPLE' run-thing");
    assert!(!single_quoted.contains("FAKESECRETVALUEEXAMPLE"));

    // Quote characters around the value must be preserved so the redacted
    // preview still reads like a normal key=value assignment.
    assert!(double_quoted.contains(r#""***REDACTED***""#));
    assert!(single_quoted.contains("'***REDACTED***'"));
}

#[test]
fn redact_secrets_leaves_normal_commands_unchanged() {
    let benign = [
        "git status",
        "ls -la /tmp",
        "cargo build --release",
        "echo hello world",
        "git commit -m 'fix: update docs'",
    ];
    for cmd in benign {
        assert_eq!(
            redact_secrets(cmd),
            cmd,
            "benign command should pass through unchanged: {:?}",
            cmd
        );
    }
}

#[test]
fn redact_secrets_runs_before_truncation_so_secret_cannot_leak() {
    // Build a command where the secret value would still be partially
    // visible after a naive 200-char truncation if redaction ran after
    // (or not at all). Redaction must strip the value regardless of
    // where it falls relative to the 200-char cutoff used by log_action.
    let padding = "x".repeat(150);
    let secret = "FAKEPADDEDVALUE1234567890EXAMPLE";
    let cmd = format!("echo {} && password={}", padding, secret);
    let redacted = redact_secrets(&cmd);
    // Simulate log_action's own truncation on the *redacted* string.
    let preview: String = redacted.chars().take(200).collect();
    assert!(
        !preview.contains(secret),
        "secret must not survive redaction+truncation: {:?}",
        preview
    );
    assert!(
        !preview.contains("FAKEPADDEDVALUE"),
        "no partial fragment of the secret should leak: {:?}",
        preview
    );
}

// ── Greptile P1 follow-up: decision reason must be redacted too ──────────

#[test]
fn log_action_redacts_secrets_from_decision_reason_not_just_preview() {
    // Regression: a deny reason built from `format!("Blocked: '{}' matched
    // in: {}", label, segment)` embeds the raw matched segment verbatim.
    // If that segment carries a secret (e.g. the dangerous command was
    // itself prefixed with `password=...`), the reason column must be
    // redacted exactly like the preview column, not written raw.
    let _guard = env_test_lock().lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join(format!(
        "cb_log_reason_redact_{}_{}",
        std::process::id(),
        line!()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let reason = "Blocked: 'rm -rf /' matched in: rm -rf / password=FAKEREASONVALUE123EXAMPLE";
    with_fake_home(&tmp, || {
        log_action(
            "deny",
            reason,
            "rm -rf / password=FAKEREASONVALUE123EXAMPLE",
        );
    });

    let log_contents = fs::read_to_string(tmp.join(".clawband.log")).unwrap();
    assert!(
        !log_contents.contains("FAKEREASONVALUE123EXAMPLE"),
        "secret embedded in the decision reason must not reach the log: {log_contents}"
    );
    assert!(
        log_contents.contains("***REDACTED***"),
        "redaction marker should appear (in reason and/or preview): {log_contents}"
    );
    // The reason column (second field, before the pipe-delimited preview)
    // specifically must carry the marker, not just the preview column.
    let reason_field = log_contents.split(" | ").nth(1).unwrap_or("");
    assert!(
        reason_field.contains("***REDACTED***"),
        "the reason field itself must be redacted, got: {reason_field:?} (full line: {log_contents:?})"
    );

    let _ = fs::remove_dir_all(&tmp);
}

// ── Greptile P1 follow-up: complex secret shapes must be fully redacted ──

#[test]
fn redact_secrets_covers_full_sigv4_authorization_header() {
    // A real AWS SigV4 Authorization header has multiple comma-separated
    // fields after the scheme; `Signature=...` is the actual secret and
    // sits at the very end. The previous pattern stopped at the first
    // whitespace-delimited "word" and left `Signature=SECRETVALUE`
    // un-redacted.
    let cmd = "curl -H \"Authorization: AWS4-HMAC-SHA256 Credential=FAKEAWSKEYIDEXAMPLE/20260101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=FAKESIGVALUE1234567890EXAMPLE\" https://example.com";
    let out = redact_secrets(cmd);
    assert!(
        !out.contains("FAKESIGVALUE1234567890EXAMPLE"),
        "SigV4 Signature value must be redacted: {out}"
    );
    assert!(
        !out.contains("FAKEAWSKEYIDEXAMPLE"),
        "SigV4 Credential value must be redacted: {out}"
    );
    assert!(
        out.contains("***REDACTED***"),
        "expected redaction marker in output, got: {out}"
    );
}

#[test]
fn redact_secrets_handles_escaped_quote_inside_quoted_value() {
    // `\"` inside a double-quoted value must not be treated as the
    // closing quote — otherwise the match terminates early and leaves
    // the trailing fragment of the secret (`word123`) exposed.
    let cmd = r#"some-tool --password="FakeValA\"trail123" run"#;
    let out = redact_secrets(cmd);
    assert!(
        !out.contains("trail123"),
        "trailing fragment after an escaped quote must not leak: {out}"
    );
    assert!(
        !out.contains("FakeValA"),
        "leading fragment before the escaped quote must not leak: {out}"
    );
    assert!(
        out.contains("***REDACTED***"),
        "expected redaction marker in output, got: {out}"
    );
}
