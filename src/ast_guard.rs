//! AST-based content guard for the Write/Edit/MultiEdit/NotebookEdit hook.
//!
//! Ported from the standalone `treeband` project (github.com/jamessoubry/treeband),
//! which was merged into clawband because the two fired on the identical
//! Write|Edit|MultiEdit|NotebookEdit hook event as separate processes — the
//! receipt-sharing mechanism briefly built to let them cooperate across that
//! boundary was itself the symptom that they should have been one thing.
//!
//! clawband's existing checks (`builtin_edit_deny`, `builtin_edit_protected_ask`,
//! user `protect.paths`) are regex/path-based: solid for *where* a file is
//! being written, but structurally unable to tell a real `eval(x)` call apart
//! from `// eval(x)` in a comment or `"eval(x)"` in a string literal, since
//! they never parse the actual code. This module parses the content being
//! written with tree-sitter and matches AST *structure* instead of text — a
//! rule for "a real call to `eval`" only ever matches an actual call
//! expression, never a comment or string that happens to contain the same
//! characters. See the "AST content guard" section in README.md for the
//! fuller rationale (prior-art check, why a full reparse per hook call is
//! correct here rather than a missed optimization).

use streaming_iterator::StreamingIterator;
use tree_sitter::{Language as TsLanguage, Parser, Query, QueryCursor};

/// A single rule match against a file's content — which rule fired and why.
pub struct Finding {
    /// Short rule identifier, e.g. `"dynamic-eval"`.
    pub rule: &'static str,
    /// Human-readable explanation shown to the user in the `ask` prompt.
    pub reason: &'static str,
}

/// A language `ast_guard` can parse and run rules against.
pub enum Lang {
    /// `.rs` — `shell-invoking-subprocess` (`Command::new("sh"/"bash"/...).arg("-c")`).
    Rust,
    /// `.py` / `.pyi` — `dynamic-eval` (`eval`/`exec`), `shell-invoking-subprocess`
    /// (`subprocess.*(shell=True)`, `os.system`/`os.popen`), `insecure-deserialize`
    /// (`pickle.load`/`pickle.loads`, `marshal.loads`, `yaml.load` without a safe
    /// `Loader=`).
    Python,
    /// `.js` / `.mjs` / `.cjs` / `.jsx` — `dynamic-eval` (`eval`/`Function`),
    /// `shell-invoking-subprocess` (`.exec`/`.execSync`), `insecure-deserialize`
    /// (`vm.runInNewContext`/`runInThisContext`/`runInContext`).
    JavaScript,
    /// `.ts` / `.tsx` — `dynamic-eval` (`eval`/`Function`),
    /// `shell-invoking-subprocess` (`.exec`/`.execSync`), `insecure-deserialize`
    /// (`vm.runInNewContext`/`runInThisContext`/`runInContext`).
    TypeScript,
}

/// Extensions this module can parse. Anything else returns `None` and the
/// caller falls through to clawband's existing path-based checks only —
/// this module augments those, it never replaces them.
pub fn detect_language(path: &str) -> Option<Lang> {
    let ext = path.rsplit('.').next()?;
    match ext {
        "rs" => Some(Lang::Rust),
        "py" => Some(Lang::Python),
        "js" | "mjs" | "cjs" | "jsx" => Some(Lang::JavaScript),
        "ts" | "tsx" => Some(Lang::TypeScript),
        _ => None,
    }
}

fn ts_language(lang: &Lang) -> TsLanguage {
    match lang {
        Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
        Lang::Python => tree_sitter_python::LANGUAGE.into(),
        Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    }
}

/// Rule set. `dynamic-eval` was ported as-is from treeband;
/// `shell-invoking-subprocess` (issue #253) and `insecure-deserialize`
/// (issue #254) were added directly in clawband.
/// Each rule is a tree-sitter query, not a regex — it matches AST structure,
/// so `// eval(x)` in a comment or `"eval(x)"` in a string literal never
/// matches, unlike a naive text search.
///
/// `insecure-deserialize`'s Python `yaml.load` case is NOT included here —
/// "flag `yaml.load(...)` unless it has a safe `Loader=` kwarg" needs a
/// negative condition tree-sitter queries can't express (a query can match
/// the presence of a node, not the absence of one elsewhere in the same
/// call). That case is handled by a dedicated post-match walk,
/// `python_yaml_load_findings`, called directly from `scan()`.
fn rules_for(lang: &Lang) -> Vec<(&'static str, &'static str, &'static str)> {
    // (rule_name, query, reason)
    //
    // IMPORTANT — predicate placement: `#eq?`/`#match?` predicates must be
    // written INSIDE the closing paren of the pattern node they scope to,
    // not after it. Placing them after (as a sibling of the top-level
    // pattern) silently turns them into unrelated, effectively-unconstrained
    // top-level patterns of their own — the query still compiles, but the
    // predicates are never actually applied, and the "structural" match
    // fires on any node satisfying the bare shape. Verified empirically
    // while building the shell-invoking-subprocess rule (issue #253): a
    // predicate-after-the-paren query matched 176 unrelated nodes in a
    // one-line test file. Every query below has been tested this way
    // (correct predicate placement, both true- and false-positive cases)
    // before being committed — see the PR description for the verification
    // matrix rather than re-deriving it from scratch when adding a new rule.
    let shell_invoking_reason = "shell-invoking call — if any part of the command/argument is not a fixed literal, this is a command-injection surface; prefer exec'ing the program directly with an argv array";
    let insecure_deserialize_reason = "insecure deserialization — this API can execute arbitrary code embedded in its input; if the input isn't fully trusted, use a data-only parser instead";
    match lang {
        Lang::JavaScript | Lang::TypeScript => vec![
            (
                "dynamic-eval",
                r#"(call_expression function: (identifier) @fn (#match? @fn "^(eval|Function)$"))"#,
                "dynamic code execution (eval/Function constructor) — can run attacker-controlled strings as code",
            ),
            (
                "shell-invoking-subprocess",
                r#"(call_expression
  function: (member_expression
    property: (property_identifier) @method)
  (#match? @method "^(exec|execSync)$"))"#,
                shell_invoking_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call_expression
  function: (member_expression
    object: (identifier) @obj
    property: (property_identifier) @method)
  (#eq? @obj "vm")
  (#match? @method "^(runInNewContext|runInThisContext|runInContext)$"))"#,
                insecure_deserialize_reason,
            ),
        ],
        Lang::Python => vec![
            (
                "dynamic-eval",
                r#"(call function: (identifier) @fn (#match? @fn "^(eval|exec)$"))"#,
                "dynamic code execution (eval/exec) — can run attacker-controlled strings as code",
            ),
            (
                "shell-invoking-subprocess",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kw
      value: (true)))
  (#eq? @obj "subprocess")
  (#match? @method "^(run|call|Popen|check_call|check_output)$")
  (#eq? @kw "shell"))"#,
                shell_invoking_reason,
            ),
            (
                "shell-invoking-subprocess",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "os")
  (#match? @method "^(system|popen)$"))"#,
                "shell-invoking call — os.system()/os.popen() always run through a shell; if any part of the command is not a fixed literal, this is a command-injection surface",
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "pickle")
  (#match? @method "^(load|loads)$"))"#,
                insecure_deserialize_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "marshal")
  (#eq? @method "loads"))"#,
                insecure_deserialize_reason,
            ),
        ],
        Lang::Rust => vec![(
            "shell-invoking-subprocess",
            r#"(call_expression
  function: (field_expression
    value: (call_expression
      function: (scoped_identifier
        path: (identifier) @cmd_path
        name: (identifier) @cmd_new)
      arguments: (arguments (string_literal (string_content) @shell_bin)))
    field: (field_identifier) @arg_method)
  arguments: (arguments (string_literal (string_content) @flag))
  (#eq? @cmd_path "Command")
  (#eq? @cmd_new "new")
  (#eq? @arg_method "arg")
  (#match? @shell_bin "^(sh|bash|/bin/sh|/bin/bash)$")
  (#eq? @flag "-c"))"#,
            shell_invoking_reason,
        )],
    }
}

/// Finds `yaml.load(...)` calls (specifically `load`, never `safe_load` —
/// the query constrains the attribute name so it can't match that) that lack
/// a `Loader=` keyword argument naming a safe loader. Tree-sitter queries
/// can't express "matches X but not if Y is also present" directly, so this
/// matches the call generically and then walks its argument list in Rust
/// code looking for a `Loader=` kwarg whose value mentions "Safe" (covers
/// both `Loader=yaml.SafeLoader` and a bare `Loader=SafeLoader` import).
fn python_yaml_load_findings(tree: &tree_sitter::Tree, content: &str) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
    let query_src = r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @obj "yaml")
  (#eq? @method "load"))"#;
    let query = match Query::new(&ts_lang, query_src) {
        Ok(q) => q,
        Err(_) => return vec![],
    };
    let args_index = query
        .capture_names()
        .iter()
        .position(|n| *n == "args")
        .expect("query defines an @args capture");

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != args_index {
                continue;
            }
            let mut has_safe_loader = false;
            let mut c = cap.node.walk();
            for child in cap.node.named_children(&mut c) {
                if child.kind() != "keyword_argument" {
                    continue;
                }
                let name_ok = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                    == Some("Loader");
                let value_safe = child
                    .child_by_field_name("value")
                    .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                    .is_some_and(|v| v.contains("Safe"));
                if name_ok && value_safe {
                    has_safe_loader = true;
                    break;
                }
            }
            if !has_safe_loader {
                findings.push(Finding {
                    rule: "insecure-deserialize",
                    reason: "insecure deserialization — yaml.load() without a safe Loader can execute arbitrary code embedded in its input; use yaml.safe_load() or pass Loader=yaml.SafeLoader",
                });
            }
        }
    }
    findings
}

/// Parses `content` as `lang` and runs the rule set against the AST.
/// Returns an empty vec (never fails closed) if the content fails to parse —
/// scanning augments clawband's existing checks, it doesn't gate on its own
/// success.
pub fn scan(content: &str, lang: Lang) -> Vec<Finding> {
    let mut parser = Parser::new();
    let ts_lang = ts_language(&lang);
    if parser.set_language(&ts_lang).is_err() {
        return vec![];
    }
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return vec![],
    };

    let mut findings = Vec::new();
    for (rule, query_src, reason) in rules_for(&lang) {
        let query = match Query::new(&ts_lang, query_src) {
            Ok(q) => q,
            Err(_) => continue,
        };
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
        if matches.next().is_some() {
            findings.push(Finding { rule, reason });
        }
    }
    if matches!(lang, Lang::Python) {
        findings.extend(python_yaml_load_findings(&tree, content));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── The false-positive-avoidance contrast (the actual reason this
    // module exists over a regex approach) — ported from treeband's
    // ignores_eval_in_comment / ignores_eval_in_string_literal pair. ──

    #[test]
    fn flags_real_eval_call_in_js() {
        let findings = scan("eval(x);", Lang::JavaScript);
        assert!(!findings.is_empty(), "a real eval() call must be flagged");
    }

    #[test]
    fn ignores_eval_in_comment() {
        let findings = scan(
            "// eval(x) is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(
            findings.is_empty(),
            "eval mentioned in a comment must not be flagged: this is the entire point of AST scanning over regex"
        );
    }

    #[test]
    fn ignores_eval_in_string_literal() {
        let findings = scan(r#"const s = "call eval(x) here";"#, Lang::JavaScript);
        assert!(
            findings.is_empty(),
            "eval mentioned in a string literal must not be flagged: this is the entire point of AST scanning over regex"
        );
    }

    #[test]
    fn flags_real_eval_call_in_python() {
        let findings = scan("eval(user_input)", Lang::Python);
        assert!(!findings.is_empty());
    }

    #[test]
    fn flags_exec_in_python() {
        let findings = scan("exec(user_input)", Lang::Python);
        assert!(!findings.is_empty());
    }

    #[test]
    fn ignores_exec_in_python_comment() {
        let findings = scan("# exec(user_input) would be bad\nprint('hi')", Lang::Python);
        assert!(findings.is_empty());
    }

    #[test]
    fn rust_has_no_dynamic_eval_equivalent_rule() {
        // Rust has no dynamic-eval equivalent rule (no eval()/exec() built
        // in to flag) — but it does have shell-invoking-subprocess (see
        // below). A bare eval() call must never flag under either rule.
        let findings = scan("fn main() { eval(); }", Lang::Rust);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_language_matches_supported_extensions() {
        for (path, matches) in [
            ("a.rs", true),
            ("a.py", true),
            ("a.js", true),
            ("a.mjs", true),
            ("a.cjs", true),
            ("a.jsx", true),
            ("a.ts", true),
            ("a.tsx", true),
            ("a.go", false),
            ("a.sh", false),
            ("noext", false),
        ] {
            assert_eq!(
                detect_language(path).is_some(),
                matches,
                "{path} language detection"
            );
        }
    }

    // ── issue #253: shell-invoking-subprocess ────────────────────────────────
    // Command-injection surface: handing a string to a shell interpreter
    // instead of exec'ing a program directly.

    fn has_shell_invoking_finding(findings: &[Finding]) -> bool {
        findings
            .iter()
            .any(|f| f.rule == "shell-invoking-subprocess")
    }

    // Python: subprocess.*(shell=True)

    #[test]
    fn python_flags_subprocess_run_shell_true() {
        let findings = scan("subprocess.run(cmd, shell=True)", Lang::Python);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn python_flags_subprocess_shell_true_regardless_of_position() {
        // shell=True can appear first or last — the query must not care.
        let findings = scan("subprocess.run(shell=True, args=cmd)", Lang::Python);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn python_flags_all_shell_invoking_subprocess_methods() {
        for method in ["run", "call", "Popen", "check_call", "check_output"] {
            let code = format!("subprocess.{method}(cmd, shell=True)");
            let findings = scan(&code, Lang::Python);
            assert!(
                has_shell_invoking_finding(&findings),
                "subprocess.{method}(..., shell=True) must be flagged"
            );
        }
    }

    #[test]
    fn python_ignores_subprocess_without_shell_true() {
        // Required false-positive test from issue #253.
        let findings = scan(r#"subprocess.run(["ls", "-la"])"#, Lang::Python);
        assert!(
            !has_shell_invoking_finding(&findings),
            "subprocess.run with an argv list and no shell=True must not be flagged"
        );
    }

    #[test]
    fn python_ignores_subprocess_shell_false() {
        let findings = scan("subprocess.run(cmd, shell=False)", Lang::Python);
        assert!(!has_shell_invoking_finding(&findings));
    }

    #[test]
    fn python_flags_bare_os_system() {
        let findings = scan("os.system(cmd)", Lang::Python);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn python_flags_bare_os_popen() {
        let findings = scan("os.popen(cmd)", Lang::Python);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn python_ignores_unrelated_os_calls() {
        let findings = scan("os.path.join(a, b)", Lang::Python);
        assert!(!has_shell_invoking_finding(&findings));
    }

    #[test]
    fn python_ignores_shell_invoking_mention_in_comment() {
        // Required false-positive test from issue #253.
        let findings = scan(
            "# subprocess.run(cmd, shell=True) would be dangerous\nprint(1)",
            Lang::Python,
        );
        assert!(
            !has_shell_invoking_finding(&findings),
            "a comment mentioning subprocess.run(..., shell=True) must not be flagged"
        );
    }

    #[test]
    fn python_ignores_shell_invoking_mention_in_string_literal() {
        // Required false-positive test from issue #253.
        let findings = scan(r#"s = "os.system(cmd)""#, Lang::Python);
        assert!(
            !has_shell_invoking_finding(&findings),
            "a string literal containing \"os.system(...)\" must not be flagged"
        );
    }

    // JavaScript/TypeScript: child_process.exec / execSync

    #[test]
    fn js_flags_child_process_exec() {
        let findings = scan("child_process.exec(cmd);", Lang::JavaScript);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn js_flags_child_process_exec_sync() {
        let findings = scan("child_process.execSync(cmd);", Lang::JavaScript);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn js_flags_exec_on_any_receiver() {
        // We can't statically know which variable holds the child_process
        // module without data-flow analysis, so this matches any `.exec(`/
        // `.execSync(` member call, not just one literally named
        // `child_process`. Matches clawband's own existing Bash-side
        // detection of `require('child_process').exec(...)`.
        let findings = scan("cp.exec(cmd);", Lang::JavaScript);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn js_ignores_exec_file() {
        // Required false-positive test from issue #253.
        let findings = scan(
            "child_process.execFile(\"ls\", [\"-la\"]);",
            Lang::JavaScript,
        );
        assert!(
            !has_shell_invoking_finding(&findings),
            "execFile must not be flagged: it takes an argv array and doesn't invoke a shell"
        );
    }

    #[test]
    fn js_ignores_exec_file_sync() {
        let findings = scan(
            "child_process.execFileSync(\"ls\", [\"-la\"]);",
            Lang::JavaScript,
        );
        assert!(!has_shell_invoking_finding(&findings));
    }

    #[test]
    fn js_ignores_spawn_and_spawn_sync() {
        let findings = scan("child_process.spawn(\"ls\", [\"-la\"]);", Lang::JavaScript);
        assert!(!has_shell_invoking_finding(&findings));
        let findings = scan(
            "child_process.spawnSync(\"ls\", [\"-la\"]);",
            Lang::JavaScript,
        );
        assert!(!has_shell_invoking_finding(&findings));
    }

    #[test]
    fn ts_flags_child_process_exec() {
        let findings = scan("child_process.exec(cmd);", Lang::TypeScript);
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn ts_ignores_exec_file() {
        let findings = scan(
            "child_process.execFile(\"ls\", [\"-la\"]);",
            Lang::TypeScript,
        );
        assert!(!has_shell_invoking_finding(&findings));
    }

    // Rust: Command::new("sh"/"bash"/...).arg("-c")

    #[test]
    fn rust_flags_command_sh_dash_c() {
        let findings = scan(
            r#"fn main() { Command::new("sh").arg("-c").arg(cmd); }"#,
            Lang::Rust,
        );
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn rust_flags_command_bash_dash_c() {
        let findings = scan(
            r#"fn main() { Command::new("bash").arg("-c").arg(cmd); }"#,
            Lang::Rust,
        );
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn rust_flags_command_absolute_shell_path_dash_c() {
        let findings = scan(
            r#"fn main() { Command::new("/bin/sh").arg("-c").arg(cmd); }"#,
            Lang::Rust,
        );
        assert!(has_shell_invoking_finding(&findings));
    }

    #[test]
    fn rust_ignores_non_shell_command() {
        let findings = scan(
            r#"fn main() { Command::new("ls").arg("-la"); }"#,
            Lang::Rust,
        );
        assert!(
            !has_shell_invoking_finding(&findings),
            "Command::new for a non-shell program must not be flagged"
        );
    }

    #[test]
    fn rust_ignores_shell_command_without_dash_c() {
        let findings = scan(r#"fn main() { Command::new("sh").arg("-x"); }"#, Lang::Rust);
        assert!(
            !has_shell_invoking_finding(&findings),
            "Command::new(\"sh\") without .arg(\"-c\") must not be flagged"
        );
    }

    #[test]
    fn rust_ignores_shell_invoking_mention_in_comment() {
        let findings = scan(
            "// Command::new(\"sh\").arg(\"-c\") is dangerous\nfn main() {}",
            Lang::Rust,
        );
        assert!(!has_shell_invoking_finding(&findings));
    }

    #[test]
    fn rust_ignores_shell_invoking_mention_in_string_literal() {
        let findings = scan(
            r#"fn main() { let s = "Command::new(sh).arg(-c)"; }"#,
            Lang::Rust,
        );
        assert!(!has_shell_invoking_finding(&findings));
    }

    // ── insecure-deserialize (issue #254) ──

    fn has_insecure_deserialize_finding(findings: &[Finding]) -> bool {
        findings.iter().any(|f| f.rule == "insecure-deserialize")
    }

    // Python: pickle.load / pickle.loads

    #[test]
    fn python_flags_pickle_load() {
        let findings = scan("pickle.load(f)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_pickle_loads() {
        let findings = scan("pickle.loads(data)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_pickle_mention_in_comment() {
        let findings = scan("# pickle.loads(data) is bad\nprint(1)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_pickle_mention_in_string_literal() {
        let findings = scan(r#"s = "pickle.loads(data)""#, Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    // Python: marshal.loads

    #[test]
    fn python_flags_marshal_loads() {
        let findings = scan("marshal.loads(data)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_marshal_dumps() {
        let findings = scan("marshal.dumps(obj)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "marshal.dumps (serializing, not deserializing) must not be flagged"
        );
    }

    // Python: yaml.load without a safe Loader

    #[test]
    fn python_flags_yaml_load_without_loader() {
        let findings = scan("yaml.load(data)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_yaml_load_with_dotted_safe_loader() {
        let findings = scan("yaml.load(data, Loader=yaml.SafeLoader)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "yaml.load with Loader=yaml.SafeLoader must not be flagged"
        );
    }

    #[test]
    fn python_ignores_yaml_load_with_bare_safe_loader() {
        let findings = scan("yaml.load(data, Loader=SafeLoader)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "yaml.load with a bare (imported) Loader=SafeLoader must not be flagged"
        );
    }

    #[test]
    fn python_ignores_yaml_safe_load() {
        let findings = scan("yaml.safe_load(data)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "yaml.safe_load must never be flagged, only yaml.load"
        );
    }

    #[test]
    fn python_ignores_yaml_load_mention_in_comment() {
        let findings = scan("# yaml.load(data) is bad\nprint(1)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_yaml_load_mention_in_string_literal() {
        let findings = scan(r#"s = "yaml.load(x)""#, Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_json_loads_sanity_check() {
        let findings = scan("json.loads(data)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "json.loads is a data-only parser and must never be flagged"
        );
    }

    // JS/TS: vm.runInNewContext / runInThisContext / runInContext

    #[test]
    fn js_flags_vm_run_in_new_context() {
        let findings = scan("vm.runInNewContext(code, sandbox);", Lang::JavaScript);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn js_flags_vm_run_in_this_context() {
        let findings = scan("vm.runInThisContext(code);", Lang::JavaScript);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn ts_flags_vm_run_in_context() {
        let findings = scan("vm.runInContext(code, ctx);", Lang::TypeScript);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn js_ignores_vm_mention_in_comment() {
        let findings = scan(
            "// vm.runInNewContext(code) is dangerous\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn js_ignores_vm_mention_in_string_literal() {
        let findings = scan(r#"const s = "vm.runInNewContext(code)";"#, Lang::JavaScript);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn rust_has_no_insecure_deserialize_rule() {
        let findings = scan(r#"fn main() { let x = 1; }"#, Lang::Rust);
        assert!(!has_insecure_deserialize_finding(&findings));
    }
}
