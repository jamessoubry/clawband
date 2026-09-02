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
    /// `.rs` — no rules yet (see `rules_for`).
    Rust,
    /// `.py` / `.pyi` — `dynamic-eval` (`eval`/`exec`).
    Python,
    /// `.js` / `.mjs` / `.cjs` / `.jsx` — `dynamic-eval` (`eval`/`Function`).
    JavaScript,
    /// `.ts` / `.tsx` — `dynamic-eval` (`eval`/`Function`).
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

/// v0.1 rule set (ported as-is from treeband). Each rule is a tree-sitter
/// query, not a regex — it matches AST structure, so `// eval(x)` in a
/// comment or `"eval(x)"` in a string literal never matches, unlike a naive
/// text search.
fn rules_for(lang: &Lang) -> Vec<(&'static str, &'static str, &'static str)> {
    // (rule_name, query, reason)
    match lang {
        Lang::JavaScript | Lang::TypeScript => vec![(
            "dynamic-eval",
            r#"(call_expression function: (identifier) @fn (#match? @fn "^(eval|Function)$"))"#,
            "dynamic code execution (eval/Function constructor) — can run attacker-controlled strings as code",
        )],
        Lang::Python => vec![(
            "dynamic-eval",
            r#"(call function: (identifier) @fn (#match? @fn "^(eval|exec)$"))"#,
            "dynamic code execution (eval/exec) — can run attacker-controlled strings as code",
        )],
        Lang::Rust => vec![],
    }
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
    fn rust_has_no_rules_yet() {
        // Rust has no dynamic-eval equivalent rule yet — must never flag.
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
}
