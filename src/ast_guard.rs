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

/// Shared XXE reason string — used both by the pre-narrowing doc trail and
/// by `python_xxe_findings`'s post-match walk (issue #261 review round).
const XXE_REASON: &str = "XML external entity (XXE) injection — this call is explicitly configured to resolve external entities/DTDs, which can read local files or trigger SSRF/DoS; use defusedxml instead of a custom unsafe parser configuration";

/// A single rule match against a file's content — which rule fired and why.
pub struct Finding {
    /// Short rule identifier, e.g. `"dynamic-eval"`.
    pub rule: &'static str,
    /// Human-readable explanation shown to the user in the `ask` prompt.
    pub reason: &'static str,
}

/// A language `ast_guard` can parse and run rules against.
pub enum Lang {
    /// `.rs` — `shell-invoking-subprocess` (`Command::new("sh"/"bash"/...).arg("-c")`),
    /// `tls-verify-disabled` (`.danger_accept_invalid_certs(true)`),
    /// `rust-unsafe-block` (`unsafe { ... }` — visibility, not necessarily wrong;
    /// a bare `unsafe fn` signature with no block is out of scope for v1).
    Rust,
    /// `.py` / `.pyi` — `dynamic-eval` (`eval`/`exec`), `shell-invoking-subprocess`
    /// (`subprocess.*(shell=True)`, `os.system`/`os.popen`), `insecure-deserialize`
    /// (`pickle.load`/`pickle.loads`, `pickle.Unpickler`, `cPickle`/`cloudpickle`/
    /// `dill` load/loads, `marshal.loads`, `shelve.open`, `yaml.load` without a
    /// safe `Loader=`, `yaml.unsafe_load`, `joblib.load`, `pandas.read_pickle`/
    /// `pd.read_pickle`, `numpy.load`/`np.load` with `allow_pickle=True`,
    /// `torch.load` without `weights_only=True`, and XXE injection via a
    /// *configured-unsafe* `xml.etree.ElementTree.parse`/`fromstring`/`XML`,
    /// `minidom.parse`/`parseString`, or `xml.sax.parse` call — i.e. one that
    /// passes an explicit `resolve_entities=True`/`forbid_dtd=False`-style
    /// keyword argument or a custom `XMLParser` instance, not a bare call
    /// with default arguments (modern Python 3 stdlib does not resolve
    /// external entities by default, so bare calls are routine and are not
    /// flagged — see the `python_xxe_findings` doc comment for the review
    /// finding this narrowed), `tls-verify-disabled` (any call with
    /// keyword argument `verify=False`), `sql-string-interpolation`
    /// (`.execute`/`.executemany` with an f-string/`%`-format/`.format()`/
    /// `+`-concatenated argument).
    Python,
    /// `.js` / `.mjs` / `.cjs` / `.jsx` — `dynamic-eval` (`eval`/`Function`),
    /// `shell-invoking-subprocess` (`.exec`/`.execSync`), `insecure-deserialize`
    /// (`vm.runInNewContext`/`runInThisContext`/`runInContext`), `tls-verify-disabled`
    /// (object literal property `rejectUnauthorized: false`), `dynamic-module-load`
    /// (`require`/`import()` with a non-string-literal argument),
    /// `sql-string-interpolation` (`.query`/`.execute` with a template-literal
    /// argument containing `${...}` interpolation), `xss-sink`
    /// (`.innerHTML =`/`.outerHTML =` assignment, `.insertAdjacentHTML(...)`,
    /// `document.write(...)`, and — since the default `tree-sitter-javascript`
    /// grammar parses JSX out of the box, even in a plain `.js` file — the
    /// `dangerouslySetInnerHTML` JSX attribute; see `Lang::Tsx`'s doc comment
    /// for why `.tsx` needs a separate grammar variant for the JSX form of
    /// this rule but `.js`/`.jsx` do not).
    JavaScript,
    /// `.ts` — `dynamic-eval` (`eval`/`Function`), `shell-invoking-subprocess`
    /// (`.exec`/`.execSync`), `insecure-deserialize`
    /// (`vm.runInNewContext`/`runInThisContext`/`runInContext`), `tls-verify-disabled`
    /// (object literal property `rejectUnauthorized: false`), `dynamic-module-load`
    /// (`require`/`import()` with a non-string-literal argument),
    /// `sql-string-interpolation` (`.query`/`.execute` with a template-literal
    /// argument containing `${...}` interpolation), `xss-sink` (`.innerHTML =`/
    /// `.outerHTML =` assignment, `.insertAdjacentHTML(...)`, `document.write(...)`
    /// — but NOT the `dangerouslySetInnerHTML` JSX-attribute form, since plain
    /// `.ts` files can't contain JSX syntax and `tree-sitter-typescript`'s
    /// `LANGUAGE_TYPESCRIPT` grammar has no JSX node kinds at all; see
    /// `Lang::Tsx` for the `.tsx` variant that does parse JSX).
    TypeScript,
    /// `.tsx` — same rule set as `Lang::TypeScript` (all of `.ts`'s rules
    /// apply verbatim, since `.tsx` is a superset of `.ts` syntax), PLUS the
    /// `dangerouslySetInnerHTML` JSX-attribute form of `xss-sink`, which
    /// `.ts` cannot have. This needs its own `Lang` variant (rather than
    /// reusing `Lang::TypeScript` for both `.ts` and `.tsx` as clawband did
    /// prior to issue #262) because `tree-sitter-typescript` ships JSX
    /// support as a genuinely separate compiled grammar,
    /// `tree_sitter_typescript::LANGUAGE_TSX` — confirmed empirically
    /// (issue #262 investigation) that `LANGUAGE_TYPESCRIPT`'s
    /// `node-types.json` has zero `jsx_*` node kinds, while `LANGUAGE_TSX`'s
    /// does; a `jsx_attribute` tree-sitter query fails to even compile
    /// (`Query::new` returns `Err`) against `LANGUAGE_TYPESCRIPT`, so
    /// `dangerouslySetInnerHTML` is genuinely unreachable there and not just
    /// unlikely to match syntactically.
    Tsx,
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
        "ts" => Some(Lang::TypeScript),
        "tsx" => Some(Lang::Tsx),
        _ => None,
    }
}

fn ts_language(lang: &Lang) -> TsLanguage {
    match lang {
        Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
        Lang::Python => tree_sitter_python::LANGUAGE.into(),
        Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
    }
}

/// Rule set. `dynamic-eval` was ported as-is from treeband;
/// `shell-invoking-subprocess` (issue #253), `insecure-deserialize`
/// (issue #254), `tls-verify-disabled` (issue #255), `dynamic-module-load`
/// (issue #256), `sql-string-interpolation` (issue #257), and
/// `rust-unsafe-block` (issue #258) were added directly in clawband. Each
/// rule is a tree-sitter query, not a regex — it matches AST structure, so
/// `// eval(x)` in a comment or `"eval(x)"` in a string literal never
/// matches, unlike a naive text search.
///
/// `insecure-deserialize`'s Python `yaml.load` case, `dynamic-module-load`,
/// and `sql-string-interpolation` are NOT included here — all three need a
/// condition tree-sitter queries can't express (a query can match the
/// presence of a node, not the absence/kind of one elsewhere in the same
/// call): "flag `yaml.load(...)` unless it has a safe `Loader=` kwarg", "flag
/// `require`/`import()` unless the argument is a string literal", and "flag
/// `.execute(...)` only when its argument is specifically an interpolated/
/// concatenated/formatted string, not any string." All three are handled by
/// dedicated post-match walks — `python_yaml_load_findings`,
/// `python_torch_load_findings` (issue #261 — same shape: flag `torch.load(...)`
/// unless it has a `weights_only=True` kwarg), `js_dynamic_module_load_findings`,
/// `python_sql_string_interpolation_findings`, and
/// `js_sql_string_interpolation_findings` — called directly from `scan()`.
/// `numpy.load(..., allow_pickle=True)` (issue #261) is also a post-match
/// walk (`python_numpy_load_findings`) rather than a plain query: a bare
/// `value: (true)` constraint doesn't match a parenthesized
/// `allow_pickle=(True)`, since that wraps the literal in a
/// `parenthesized_expression` node with a different shape — the walk unwraps
/// parenthesization before checking the literal (Greptile review round on
/// #261's PR). `python_xxe_findings` is the same "post-match walk over the
/// argument list" shape, used to require an explicit unsafe-configuration
/// indicator before flagging XXE-prone XML parsing (see its doc comment).
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
    let tls_verify_disabled_reason = "TLS certificate verification disabled — this accepts connections to servers with invalid/self-signed/expired certificates, defeating TLS's protection against MITM; should not ship to production";
    match lang {
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => {
            let mut rules = vec![
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
                (
                    "tls-verify-disabled",
                    r#"(pair
  key: (property_identifier) @key
  value: (false)
  (#eq? @key "rejectUnauthorized"))"#,
                    tls_verify_disabled_reason,
                ),
                (
                    "xss-sink",
                    r#"(assignment_expression
  left: [
    (member_expression
      property: (property_identifier) @prop)
    (subscript_expression
      index: (string (string_fragment) @prop))
  ]
  (#eq? @prop "innerHTML"))"#,
                    "cross-site scripting (XSS) sink — assigning to innerHTML renders its value as live HTML/script; if the value isn't fully trusted, use textContent for plain text, or sanitize with a library like DOMPurify if HTML is genuinely needed",
                ),
                (
                    "xss-sink",
                    // `+=`/`||=`/etc. on innerHTML is the same sink as `=` —
                    // this is an `augmented_assignment_expression` node, a
                    // distinct grammar rule from `assignment_expression`
                    // (confirmed against tree-sitter-javascript's grammar.js:
                    // `augmented_assignment_expression` has its own `left`/
                    // `operator`/`right` fields and its own `_augmented_assignment_lhs`
                    // choice, which is why it needs its own query rather than
                    // being covered by the plain-assignment pattern above).
                    // Verified P1 Greptile finding on PR #299: `el.innerHTML
                    // += attackerHtml` bypassed the guard entirely before
                    // this rule existed.
                    r#"(augmented_assignment_expression
  left: [
    (member_expression
      property: (property_identifier) @prop)
    (subscript_expression
      index: (string (string_fragment) @prop))
  ]
  (#eq? @prop "innerHTML"))"#,
                    "cross-site scripting (XSS) sink — compound-assigning (+=) to innerHTML is equivalent to a plain assignment for XSS purposes; if the value isn't fully trusted, use textContent for plain text, or sanitize with a library like DOMPurify if HTML is genuinely needed",
                ),
                (
                    "xss-sink",
                    r#"(assignment_expression
  left: [
    (member_expression
      property: (property_identifier) @prop)
    (subscript_expression
      index: (string (string_fragment) @prop))
  ]
  (#eq? @prop "outerHTML"))"#,
                    "cross-site scripting (XSS) sink — outerHTML assignment is equivalent to innerHTML for XSS purposes; use textContent or sanitize with a library like DOMPurify",
                ),
                (
                    "xss-sink",
                    // See the innerHTML `augmented_assignment_expression`
                    // comment above — same node kind, same bypass shape,
                    // just for outerHTML.
                    r#"(augmented_assignment_expression
  left: [
    (member_expression
      property: (property_identifier) @prop)
    (subscript_expression
      index: (string (string_fragment) @prop))
  ]
  (#eq? @prop "outerHTML"))"#,
                    "cross-site scripting (XSS) sink — compound-assigning (+=) to outerHTML is equivalent to innerHTML for XSS purposes; use textContent or sanitize with a library like DOMPurify",
                ),
                (
                    "xss-sink",
                    // Covers both `el.insertAdjacentHTML(...)` (dot access,
                    // `member_expression`) and `el["insertAdjacentHTML"](...)`
                    // (computed/bracket access, `subscript_expression` — a
                    // genuinely different grammar node from `member_expression`,
                    // with its own `object`/`index` fields rather than
                    // `object`/`property`; verified against
                    // tree-sitter-javascript's grammar.js and node-types.json).
                    // Verified P1 Greptile finding on PR #299: the bracket
                    // form bypassed the guard entirely before this rule
                    // covered it.
                    r#"(call_expression
  function: [
    (member_expression
      property: (property_identifier) @method)
    (subscript_expression
      index: (string (string_fragment) @method))
  ]
  (#eq? @method "insertAdjacentHTML"))"#,
                    "cross-site scripting (XSS) sink — insertAdjacentHTML renders its argument as live HTML/script; if it isn't fully trusted, use insertAdjacentText() or sanitize with a library like DOMPurify",
                ),
                (
                    "xss-sink",
                    // Covers `document.write(...)` and `document["write"](...)`
                    // alike, but — same as the pre-existing dot-form rule —
                    // deliberately scoped to the `document` object only
                    // (`#eq? @obj "document"`), not `.write()`/`["write"]()`
                    // on any arbitrary object; `foo["write"](x)` must not
                    // flag. Verified P1 Greptile finding on PR #299:
                    // `document["write"](attackerHtml)` bypassed the guard
                    // entirely before this rule covered the bracket form.
                    r#"(call_expression
  function: [
    (member_expression
      object: (identifier) @obj
      property: (property_identifier) @method)
    (subscript_expression
      object: (identifier) @obj
      index: (string (string_fragment) @method))
  ]
  (#eq? @obj "document")
  (#eq? @method "write"))"#,
                    "cross-site scripting (XSS) sink — document.write() with untrusted content injects and executes attacker-controlled HTML/script; use safe DOM methods like createElement()/appendChild() instead",
                ),
            ];
            // `dangerouslySetInnerHTML` is a JSX attribute — a grammar
            // construct that only `Lang::JavaScript` (default
            // `tree-sitter-javascript` grammar, which parses JSX out of the
            // box) and `Lang::Tsx` (dedicated `LANGUAGE_TSX` grammar) can
            // even syntactically contain. Plain `Lang::TypeScript`'s
            // `LANGUAGE_TYPESCRIPT` grammar has no `jsx_attribute` node kind
            // at all, so including this query there would make `Query::new`
            // fail (harmlessly skipped by `scan()`'s `Err(_) => continue`) —
            // excluded here instead so the rule list documents what's
            // actually reachable per-language rather than relying on that
            // fallback. See `Lang::Tsx`'s doc comment for the empirical
            // grammar-support check.
            if !matches!(lang, Lang::TypeScript) {
                rules.push((
                    "xss-sink",
                    r#"(jsx_attribute (property_identifier) @name (#eq? @name "dangerouslySetInnerHTML"))"#,
                    "cross-site scripting (XSS) sink — React's dangerouslySetInnerHTML renders its __html value as raw HTML, executing attacker-controlled markup/script if the value isn't fully trusted; sanitize with a library like DOMPurify or avoid raw HTML rendering",
                ));
            }
            rules
        }
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
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "pickle")
  (#eq? @method "Unpickler"))"#,
                insecure_deserialize_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#match? @obj "^(cPickle|cloudpickle|dill)$")
  (#match? @method "^(load|loads)$"))"#,
                insecure_deserialize_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "shelve")
  (#eq? @method "open"))"#,
                insecure_deserialize_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "yaml")
  (#eq? @method "unsafe_load"))"#,
                insecure_deserialize_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#eq? @obj "joblib")
  (#eq? @method "load"))"#,
                insecure_deserialize_reason,
            ),
            (
                "insecure-deserialize",
                r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  (#match? @obj "^(pandas|pd)$")
  (#eq? @method "read_pickle"))"#,
                insecure_deserialize_reason,
            ),
            (
                "tls-verify-disabled",
                r#"(call
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kw
      value: (false)))
  (#eq? @kw "verify"))"#,
                tls_verify_disabled_reason,
            ),
        ],
        Lang::Rust => vec![
            (
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
            ),
            (
                "tls-verify-disabled",
                r#"(call_expression
  function: (field_expression
    field: (field_identifier) @method)
  arguments: (arguments (boolean_literal) @val)
  (#eq? @method "danger_accept_invalid_certs")
  (#eq? @val "true"))"#,
                tls_verify_disabled_reason,
            ),
            (
                "rust-unsafe-block",
                r#"(unsafe_block)"#,
                "unsafe block — not necessarily wrong, but worth a human review pass; unsafe code bypasses Rust's memory-safety guarantees",
            ),
        ],
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

/// Finds `torch.load(...)` calls (unsafe-deserialization gap review, issue
/// #261) that lack a `weights_only=True` keyword argument. `torch.load`
/// unpickles its input by default, so the absence of `weights_only=True` is
/// the dangerous case — same "flag unless a specific safe kwarg is present"
/// shape as `python_yaml_load_findings`'s `Loader=` check above, which a
/// tree-sitter query can't express directly (a query matches a node's
/// presence, not another node's absence), so this matches the call
/// generically and walks its argument list in Rust looking for
/// `weights_only=True`.
fn python_torch_load_findings(tree: &tree_sitter::Tree, content: &str) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
    let query_src = r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @obj "torch")
  (#eq? @method "load"))"#;
    let query = match Query::new(&ts_lang, query_src) {
        Ok(q) => q,
        Err(_) => return vec![],
    };
    let args_index = match query.capture_names().iter().position(|n| *n == "args") {
        Some(i) => i,
        None => return vec![],
    };

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != args_index {
                continue;
            }
            let mut has_weights_only_true = false;
            let mut c = cap.node.walk();
            for child in cap.node.named_children(&mut c) {
                if child.kind() != "keyword_argument" {
                    continue;
                }
                let name_ok = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                    == Some("weights_only");
                let value_true = child
                    .child_by_field_name("value")
                    .is_some_and(|v| v.kind() == "true");
                if name_ok && value_true {
                    has_weights_only_true = true;
                    break;
                }
            }
            if !has_weights_only_true {
                findings.push(Finding {
                    rule: "insecure-deserialize",
                    reason: "insecure deserialization — torch.load() without weights_only=True can execute arbitrary code embedded in the checkpoint via pickle; pass weights_only=True unless you need to load non-tensor Python objects from a fully trusted source",
                });
            }
        }
    }
    findings
}

/// Unwraps a value node through any number of nested `parenthesized_expression`
/// wrappers to reach the underlying expression node — e.g. `(True)` and
/// `((True))` both unwrap to the bare `true` literal node. Needed because a
/// query constraint like `value: (true)` only matches when the argument
/// value node IS the `true` node directly; `allow_pickle=(True)` wraps it in
/// a `parenthesized_expression` first, which is a different AST shape with
/// the same runtime meaning, and was not being flagged (Greptile review
/// round on #261's PR: `numpy.load(path, allow_pickle=(True))` bypassed the
/// original `allow_pickle=True` query).
fn unwrap_parenthesized(mut node: tree_sitter::Node) -> tree_sitter::Node {
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

/// Finds `numpy.load(...)`/`np.load(...)` calls with an `allow_pickle=True`
/// keyword argument (issue #261; Greptile review round tightened this from a
/// plain query into a post-match walk — see `unwrap_parenthesized`'s doc
/// comment for why). `numpy.load` unpickles object arrays when
/// `allow_pickle=True`, so presence of that kwarg with a truthy value
/// (parenthesized or not) is the dangerous case.
fn python_numpy_load_findings(tree: &tree_sitter::Tree, content: &str) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
    let query_src = r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @obj "^(numpy|np)$")
  (#eq? @method "load"))"#;
    let query = match Query::new(&ts_lang, query_src) {
        Ok(q) => q,
        Err(_) => return vec![],
    };
    let args_index = match query.capture_names().iter().position(|n| *n == "args") {
        Some(i) => i,
        None => return vec![],
    };

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != args_index {
                continue;
            }
            let mut has_allow_pickle_true = false;
            let mut c = cap.node.walk();
            for child in cap.node.named_children(&mut c) {
                if child.kind() != "keyword_argument" {
                    continue;
                }
                let name_ok = child
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                    == Some("allow_pickle");
                let value_true = child
                    .child_by_field_name("value")
                    .is_some_and(|v| unwrap_parenthesized(v).kind() == "true");
                if name_ok && value_true {
                    has_allow_pickle_true = true;
                    break;
                }
            }
            if has_allow_pickle_true {
                findings.push(Finding {
                    rule: "insecure-deserialize",
                    reason: "insecure deserialization — numpy.load() with allow_pickle=True can execute arbitrary code embedded in the array file; only pass allow_pickle=True for fully trusted files",
                });
            }
        }
    }
    findings
}

/// Returns true if `args_node` (a call's `argument_list`) contains an
/// explicit indicator that XML entity/DTD resolution has been deliberately
/// enabled: a `resolve_entities=True`-style keyword argument, a
/// `forbid_dtd=False`/`forbid_entities=False`/`forbid_external=False`-style
/// keyword argument (the defusedxml-style knobs, inverted to re-enable the
/// danger they normally guard against), or a `parser=`-style argument (
/// keyword or positional) whose value constructs a custom `XMLParser`
/// instance. Used by `python_xxe_findings` to distinguish a genuinely unsafe
/// call from routine default-configuration parsing.
fn has_unsafe_xml_config(args_node: tree_sitter::Node, content: &str) -> bool {
    let mut c = args_node.walk();
    for child in args_node.named_children(&mut c) {
        if child.kind() == "keyword_argument" {
            let name = child
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(content.as_bytes()).ok());
            let value = child.child_by_field_name("value");
            match name {
                Some("resolve_entities") => {
                    if value.is_some_and(|v| unwrap_parenthesized(v).kind() == "true") {
                        return true;
                    }
                }
                Some("forbid_dtd") | Some("forbid_entities") | Some("forbid_external") => {
                    if value.is_some_and(|v| unwrap_parenthesized(v).kind() == "false") {
                        return true;
                    }
                }
                Some("parser")
                    if value
                        .and_then(|v| v.utf8_text(content.as_bytes()).ok())
                        .is_some_and(|t| t.contains("XMLParser")) =>
                {
                    return true;
                }
                _ => {}
            }
        } else if let Ok(text) = child.utf8_text(content.as_bytes()) {
            // A bare positional argument that itself constructs a custom
            // XMLParser (e.g. `ET.parse(path, XMLParser(resolve_entities=True))`)
            // is the same "custom parser instance" indicator as the keyword
            // form above.
            if text.contains("XMLParser(") {
                return true;
            }
        }
    }
    false
}

/// Finds XXE-prone XML parsing calls (`ElementTree`/`minidom`/`xml.sax`,
/// bare and fully-qualified module-path forms) that are actually configured
/// to enable unsafe entity/DTD resolution (issue #261 review round).
///
/// The original rule blanket-flagged every bare `ET.parse`/`minidom.parse`/
/// `xml.sax.parse` call on the theory that these resolve external entities
/// by default. Greptile's review reproduced that on Python 3.11 this isn't
/// true: `ElementTree.parse`/`fromstring`, `minidom.parse`, and
/// `xml.sax.parse` do NOT expand external `file://` entities by default in
/// that Python version's stdlib configuration, so the blanket rule fired on
/// routine, safe XML parsing — a false positive that risks alert fatigue.
/// Anthropic's security-guidance plugin's `xml_unsafe_parse` rule (the
/// reference this project targets behavioral parity with per issue #261) has
/// the identical blanket-flag-bare-calls shape via a plain regex with no
/// config scoping (see `security-guidance/hooks/patterns.py`), so there is
/// no narrower upstream behavior to match here — this deliberately diverges
/// from the reference rather than reproducing its false positive.
///
/// Like `python_yaml_load_findings`/`python_torch_load_findings` above, this
/// is a "flag conditionally on argument content" shape a plain query can't
/// express, so it matches the call generically and only flags when
/// `has_unsafe_xml_config` finds an explicit unsafe-configuration indicator
/// in the argument list — i.e. a call that has been deliberately configured
/// to resolve external entities/DTDs (see that function's doc comment for
/// the exact indicators), not a default-configuration call.
fn python_xxe_findings(tree: &tree_sitter::Tree, content: &str) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
    let query_srcs = [
        r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @obj "^(ET|ElementTree|cElementTree)$")
  (#match? @method "^(parse|fromstring|XML)$"))"#,
        r#"(call
  function: (attribute
    object: (attribute
      object: (attribute
        object: (identifier) @mod1
        attribute: (identifier) @mod2)
      attribute: (identifier) @mod3)
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @mod1 "xml")
  (#eq? @mod2 "etree")
  (#eq? @mod3 "ElementTree")
  (#match? @method "^(parse|fromstring|XML)$"))"#,
        r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @obj "minidom")
  (#match? @method "^(parse|parseString)$"))"#,
        r#"(call
  function: (attribute
    object: (attribute
      object: (attribute
        object: (identifier) @mod1
        attribute: (identifier) @mod2)
      attribute: (identifier) @mod3)
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @mod1 "xml")
  (#eq? @mod2 "dom")
  (#eq? @mod3 "minidom")
  (#match? @method "^(parse|parseString)$"))"#,
        r#"(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @obj "sax")
  (#eq? @method "parse"))"#,
        r#"(call
  function: (attribute
    object: (attribute
      object: (identifier) @mod1
      attribute: (identifier) @mod2)
    attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#eq? @mod1 "xml")
  (#eq? @mod2 "sax")
  (#eq? @method "parse"))"#,
    ];

    let mut findings = Vec::new();
    for query_src in query_srcs {
        let query = match Query::new(&ts_lang, query_src) {
            Ok(q) => q,
            Err(_) => continue,
        };
        let args_index = match query.capture_names().iter().position(|n| *n == "args") {
            Some(i) => i,
            None => continue,
        };
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
        while let Some(m) = matches.next() {
            for cap in m.captures {
                if cap.index as usize != args_index {
                    continue;
                }
                if has_unsafe_xml_config(cap.node, content) {
                    findings.push(Finding {
                        rule: "insecure-deserialize",
                        reason: XXE_REASON,
                    });
                }
            }
        }
    }
    findings
}

/// Finds `require(...)`/dynamic `import(...)` calls in JS/TS whose argument
/// is not a string literal (issue #256). "Flag everything except a specific
/// node kind" is a shape a tree-sitter query can't express directly — a
/// query matches a node's presence, not its kind's absence — so this matches
/// the call generically (capturing its sole argument) and inspects the
/// argument node's kind in Rust code. A plain template literal with no
/// `${...}` interpolation (e.g. `` require(`./locales/en`) ``) is treated as
/// literal-equivalent and not flagged; a template literal WITH interpolation
/// (e.g. `` require(`./locales/${lang}`) ``) is exactly the risky
/// runtime-computed-path case and must flag.
fn js_dynamic_module_load_findings(
    tree: &tree_sitter::Tree,
    content: &str,
    ts_lang: &TsLanguage,
) -> Vec<Finding> {
    let query_src = r#"[
  (call_expression
    function: (identifier) @fn
    arguments: (arguments . (_) @arg)
    (#eq? @fn "require"))
  (call_expression
    function: (import)
    arguments: (arguments . (_) @arg))
]"#;
    let query = match Query::new(ts_lang, query_src) {
        Ok(q) => q,
        Err(_) => return vec![],
    };
    let arg_index = match query.capture_names().iter().position(|n| *n == "arg") {
        Some(i) => i,
        None => return vec![],
    };

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != arg_index {
                continue;
            }
            let node = cap.node;
            if node.kind() == "string" {
                continue;
            }
            if node.kind() == "template_string" {
                let mut c = node.walk();
                let has_interpolation = node
                    .named_children(&mut c)
                    .any(|child| child.kind() == "template_substitution");
                if !has_interpolation {
                    continue;
                }
            }
            findings.push(Finding {
                rule: "dynamic-module-load",
                reason: "dynamic module load — the module path isn't a fixed string literal; if any part of it is influenced by external input, this can load and execute an arbitrary file as code",
            });
        }
    }
    findings
}

/// Finds `.execute(...)`/`.executemany(...)` calls (issue #257) in Python
/// whose argument is built via string interpolation/concatenation/formatting
/// rather than passed as a separate parameter — the structural shape of SQL
/// injection, independent of whether the interpolated value is actually
/// attacker-controlled. Matches by method-name suffix only (not object name),
/// covering `sqlite3`, `psycopg2`, `pymysql`, and SQLAlchemy's raw-connection
/// `.execute` alike. An f-string (`string` node with an `interpolation`
/// child) flags; a plain string or an f-string with zero interpolations
/// (same `string` node kind, no `interpolation` child) does not — tree-sitter
/// can't express "this node kind but only sometimes" in the query itself, so
/// the interpolation check is a Rust-side inspection of the argument node's
/// children, same shape as the `yaml.load`/`dynamic-module-load` checks
/// above. `%`-formatting and `+`-concatenation share one grammar node
/// (`binary_operator`) and are told apart by its `operator` field's text.
fn python_sql_string_interpolation_findings(
    tree: &tree_sitter::Tree,
    content: &str,
) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_python::LANGUAGE.into();
    let query_src = r#"(call
  function: (attribute
    object: (_)
    attribute: (identifier) @method)
  arguments: (argument_list . (_) @arg)
  (#match? @method "^(execute|executemany)$"))"#;
    let query = match Query::new(&ts_lang, query_src) {
        Ok(q) => q,
        Err(_) => return vec![],
    };
    let arg_index = match query.capture_names().iter().position(|n| *n == "arg") {
        Some(i) => i,
        None => return vec![],
    };

    let reason = "SQL query built via string interpolation instead of parameterized query — if any interpolated value originates from external input, this is SQL-injectable; use parameterized queries (?, %s, or named placeholders) instead";
    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != arg_index {
                continue;
            }
            let node = cap.node;
            let flagged = match node.kind() {
                "string" => {
                    let mut c = node.walk();
                    let mut has_interpolation = false;
                    for child in node.named_children(&mut c) {
                        if child.kind() == "interpolation" {
                            has_interpolation = true;
                            break;
                        }
                    }
                    has_interpolation
                }
                "binary_operator" => node
                    .child_by_field_name("operator")
                    .and_then(|op| op.utf8_text(content.as_bytes()).ok())
                    .is_some_and(|op| op == "%" || op == "+"),
                "call" => {
                    node.child_by_field_name("function")
                        .filter(|f| f.kind() == "attribute")
                        .and_then(|f| f.child_by_field_name("attribute"))
                        .and_then(|a| a.utf8_text(content.as_bytes()).ok())
                        == Some("format")
                }
                _ => false,
            };
            if flagged {
                findings.push(Finding {
                    rule: "sql-string-interpolation",
                    reason,
                });
            }
        }
    }
    findings
}

/// JS/TS counterpart of `python_sql_string_interpolation_findings` (issue
/// #257): `.query(...)`/`.execute(...)` calls (covers `mysql`, `pg`, and
/// common query-builder raw-query methods) whose argument is a template
/// literal containing `${...}` interpolation.
fn js_sql_string_interpolation_findings(
    tree: &tree_sitter::Tree,
    content: &str,
    ts_lang: &TsLanguage,
) -> Vec<Finding> {
    let query_src = r#"(call_expression
  function: (member_expression
    object: (_)
    property: (property_identifier) @method)
  arguments: (arguments . (_) @arg)
  (#match? @method "^(query|execute)$"))"#;
    let query = match Query::new(ts_lang, query_src) {
        Ok(q) => q,
        Err(_) => return vec![],
    };
    let arg_index = match query.capture_names().iter().position(|n| *n == "arg") {
        Some(i) => i,
        None => return vec![],
    };

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != arg_index {
                continue;
            }
            let node = cap.node;
            if node.kind() != "template_string" {
                continue;
            }
            let mut c = node.walk();
            let has_interpolation = node
                .named_children(&mut c)
                .any(|child| child.kind() == "template_substitution");
            if has_interpolation {
                findings.push(Finding {
                    rule: "sql-string-interpolation",
                    reason: "SQL query built via string interpolation instead of parameterized query — if any interpolated value originates from external input, this is SQL-injectable; use parameterized queries (?, %s, or named placeholders) instead",
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
        findings.extend(python_torch_load_findings(&tree, content));
        findings.extend(python_numpy_load_findings(&tree, content));
        findings.extend(python_xxe_findings(&tree, content));
        findings.extend(python_sql_string_interpolation_findings(&tree, content));
    }
    if matches!(lang, Lang::JavaScript | Lang::TypeScript | Lang::Tsx) {
        findings.extend(js_dynamic_module_load_findings(&tree, content, &ts_lang));
        findings.extend(js_sql_string_interpolation_findings(
            &tree, content, &ts_lang,
        ));
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

    // Python: unsafe-deserialization gap review (issue #261)

    #[test]
    fn python_flags_pickle_unpickler() {
        let findings = scan("pickle.Unpickler(f)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_cpickle_load() {
        let findings = scan("cPickle.load(f)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_cloudpickle_loads() {
        let findings = scan("cloudpickle.loads(data)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_dill_load() {
        let findings = scan("dill.load(f)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_shelve_open() {
        let findings = scan("shelve.open(path)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_yaml_unsafe_load() {
        let findings = scan("yaml.unsafe_load(data)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_joblib_load() {
        let findings = scan("joblib.load(path)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_pandas_read_pickle() {
        let findings = scan("pandas.read_pickle(path)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_pd_read_pickle() {
        let findings = scan("pd.read_pickle(path)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_numpy_load_with_allow_pickle_true() {
        let findings = scan("numpy.load(path, allow_pickle=True)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_np_load_with_allow_pickle_true() {
        let findings = scan("np.load(path, allow_pickle=True)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_numpy_load_without_allow_pickle() {
        let findings = scan("numpy.load(path)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "numpy.load without allow_pickle=True must not be flagged"
        );
    }

    #[test]
    fn python_ignores_numpy_load_with_allow_pickle_false() {
        let findings = scan("numpy.load(path, allow_pickle=False)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "numpy.load with allow_pickle=False must not be flagged"
        );
    }

    #[test]
    fn python_flags_numpy_load_with_parenthesized_allow_pickle_true() {
        // Greptile review round on #261's PR: allow_pickle=(True) is a
        // parenthesized-but-functionally-identical bypass of the original
        // `value: (true)` query, which only matched the bare literal shape.
        let findings = scan("numpy.load(path, allow_pickle=(True))", Lang::Python);
        assert!(
            has_insecure_deserialize_finding(&findings),
            "numpy.load with parenthesized allow_pickle=(True) must be flagged"
        );
    }

    #[test]
    fn python_flags_torch_load_without_weights_only() {
        let findings = scan("torch.load(path)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_torch_load_with_weights_only_true() {
        let findings = scan("torch.load(path, weights_only=True)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "torch.load with weights_only=True must not be flagged"
        );
    }

    #[test]
    fn python_flags_torch_load_with_weights_only_false() {
        let findings = scan("torch.load(path, weights_only=False)", Lang::Python);
        assert!(has_insecure_deserialize_finding(&findings));
    }

    // XXE-prone XML parsing: narrowed (issue #261 review round) to only fire
    // when the call is actually configured to enable unsafe entity/DTD
    // resolution — Greptile reproduced that bare calls don't do this by
    // default on Python 3.11, so the previous blanket-flag-every-bare-call
    // behavior was a false positive. Each bare-call "ignores" test below is
    // the regression coverage for that false positive; each "flags" test
    // pairs it with an explicit unsafe-configuration indicator.

    #[test]
    fn python_ignores_bare_et_parse() {
        let findings = scan("ET.parse(path)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "bare ET.parse with default config is routine on modern Python 3 and must not be flagged"
        );
    }

    #[test]
    fn python_flags_et_parse_with_custom_xml_parser() {
        let findings = scan(
            "ET.parse(path, parser=XMLParser(resolve_entities=True))",
            Lang::Python,
        );
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_et_fromstring() {
        let findings = scan("ET.fromstring(data)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_elementtree_xml() {
        let findings = scan("ElementTree.XML(data)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_full_dotted_elementtree_parse() {
        let findings = scan("xml.etree.ElementTree.parse(path)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_full_dotted_elementtree_parse_with_custom_xml_parser() {
        let findings = scan(
            "xml.etree.ElementTree.parse(path, parser=XMLParser(resolve_entities=True))",
            Lang::Python,
        );
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_minidom_parse() {
        let findings = scan("minidom.parse(path)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_minidom_parse_string() {
        let findings = scan("minidom.parseString(data)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_minidom_parse_with_custom_xml_parser() {
        let findings = scan(
            "minidom.parse(path, parser=XMLParser(resolve_entities=True))",
            Lang::Python,
        );
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_full_dotted_minidom_parse() {
        // Qualified form (`import xml.dom.minidom` then `xml.dom.minidom.parse`)
        // — Greptile review round: the original rule only matched the bare
        // `minidom` identifier form, missing this fully-qualified call chain.
        let findings = scan("xml.dom.minidom.parse(path)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_flags_full_dotted_minidom_parse_with_custom_xml_parser() {
        let findings = scan(
            "xml.dom.minidom.parse(path, parser=XMLParser(resolve_entities=True))",
            Lang::Python,
        );
        assert!(has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_full_dotted_minidom_parse_string() {
        let findings = scan("xml.dom.minidom.parseString(data)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_sax_parse_alias() {
        let findings = scan("sax.parse(path, handler)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_bare_full_dotted_xml_sax_parse() {
        let findings = scan("xml.sax.parse(path, handler)", Lang::Python);
        assert!(!has_insecure_deserialize_finding(&findings));
    }

    #[test]
    fn python_ignores_defusedxml_parse() {
        let findings = scan("defusedxml.ElementTree.parse(path)", Lang::Python);
        assert!(
            !has_insecure_deserialize_finding(&findings),
            "defusedxml is the safe alternative and must not be flagged"
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

    // ── tls-verify-disabled (issue #255) ──

    fn has_tls_verify_disabled_finding(findings: &[Finding]) -> bool {
        findings.iter().any(|f| f.rule == "tls-verify-disabled")
    }

    #[test]
    fn python_flags_verify_false() {
        let findings = scan("requests.get(url, verify=False)", Lang::Python);
        assert!(has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn python_ignores_verify_true() {
        let findings = scan("requests.get(url, verify=True)", Lang::Python);
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn python_ignores_verify_variable() {
        // Required by issue #255: verify=some_variable is a legitimate
        // conditional-TLS pattern (e.g. verify=IS_PRODUCTION) and must not
        // be flagged — only the literal-False case is in scope for v1.
        let findings = scan("requests.get(url, verify=IS_PRODUCTION)", Lang::Python);
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn python_ignores_verify_false_mention_in_comment() {
        let findings = scan("# verify=False is bad\nprint(1)", Lang::Python);
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn python_ignores_verify_false_mention_in_string_literal() {
        let findings = scan(r#"s = "verify=False""#, Lang::Python);
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn js_flags_reject_unauthorized_false() {
        let findings = scan(
            "https.request(url, { rejectUnauthorized: false });",
            Lang::JavaScript,
        );
        assert!(has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn js_ignores_reject_unauthorized_true() {
        let findings = scan(
            "https.request(url, { rejectUnauthorized: true });",
            Lang::JavaScript,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn js_ignores_reject_unauthorized_as_variable_name() {
        // Required by issue #255: a variable named rejectUnauthorized used
        // elsewhere (not as an object property with literal false) must not
        // be flagged.
        let findings = scan(
            "let rejectUnauthorized = false; foo(rejectUnauthorized);",
            Lang::JavaScript,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn js_ignores_reject_unauthorized_mention_in_comment() {
        let findings = scan(
            "// rejectUnauthorized: false is bad\nfunction f(){}",
            Lang::JavaScript,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn js_ignores_reject_unauthorized_mention_in_string_literal() {
        let findings = scan(
            r#"const s = "rejectUnauthorized: false";"#,
            Lang::JavaScript,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn ts_flags_reject_unauthorized_false() {
        let findings = scan(
            "https.request(url, { rejectUnauthorized: false });",
            Lang::TypeScript,
        );
        assert!(has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn rust_flags_danger_accept_invalid_certs_true() {
        let findings = scan(
            "fn main() { ClientBuilder::new().danger_accept_invalid_certs(true).build(); }",
            Lang::Rust,
        );
        assert!(has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn rust_ignores_danger_accept_invalid_certs_false() {
        let findings = scan(
            "fn main() { ClientBuilder::new().danger_accept_invalid_certs(false).build(); }",
            Lang::Rust,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn rust_ignores_danger_accept_invalid_certs_mention_in_comment() {
        let findings = scan(
            "// danger_accept_invalid_certs(true) is bad\nfn main() {}",
            Lang::Rust,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    #[test]
    fn rust_ignores_danger_accept_invalid_certs_mention_in_string_literal() {
        let findings = scan(
            r#"fn main() { let s = "danger_accept_invalid_certs(true)"; }"#,
            Lang::Rust,
        );
        assert!(!has_tls_verify_disabled_finding(&findings));
    }

    // ── dynamic-module-load (issue #256) ──

    fn has_dynamic_module_load_finding(findings: &[Finding]) -> bool {
        findings.iter().any(|f| f.rule == "dynamic-module-load")
    }

    #[test]
    fn js_ignores_require_string_literal() {
        let findings = scan(r#"require("./config")"#, Lang::JavaScript);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_ignores_dynamic_import_string_literal() {
        let findings = scan(r#"import("./lazy-module")"#, Lang::JavaScript);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_flags_require_identifier_argument() {
        let findings = scan("require(userInput)", Lang::JavaScript);
        assert!(has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_flags_require_template_literal_with_interpolation() {
        // Required by issue #256: this is exactly the risky i18n-loader
        // case — a module path built from a request param.
        let findings = scan("require(`./locales/${lang}`)", Lang::JavaScript);
        assert!(has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_ignores_require_template_literal_without_interpolation() {
        // A plain template literal with no ${...} is literal-equivalent.
        let findings = scan("require(`./locales/en`)", Lang::JavaScript);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_flags_require_binary_expression() {
        let findings = scan("require(a + b)", Lang::JavaScript);
        assert!(has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_flags_require_call_expression_argument() {
        let findings = scan("require(getPath())", Lang::JavaScript);
        assert!(has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_ignores_require_mention_in_comment() {
        let findings = scan(
            "// require(userInput) is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn js_ignores_require_mention_in_string_literal() {
        let findings = scan(r#"const s = "require(x)";"#, Lang::JavaScript);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn ts_flags_require_identifier_argument() {
        let findings = scan("require(userInput);", Lang::TypeScript);
        assert!(has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn ts_ignores_dynamic_import_string_literal() {
        let findings = scan(r#"import("./lazy-module");"#, Lang::TypeScript);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn python_has_no_dynamic_module_load_rule() {
        // v1 is JS/TS only per issue #256 — importlib.import_module is a
        // deliberate v2 follow-up, not in scope here.
        let findings = scan("importlib.import_module(name)", Lang::Python);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    #[test]
    fn rust_has_no_dynamic_module_load_rule() {
        let findings = scan(r#"fn main() { let x = 1; }"#, Lang::Rust);
        assert!(!has_dynamic_module_load_finding(&findings));
    }

    // ── sql-string-interpolation (issue #257) ──

    fn has_sql_string_interpolation_finding(findings: &[Finding]) -> bool {
        findings
            .iter()
            .any(|f| f.rule == "sql-string-interpolation")
    }

    #[test]
    fn python_flags_execute_fstring_with_interpolation() {
        let findings = scan(r#"cursor.execute(f"SELECT * FROM {table}")"#, Lang::Python);
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_ignores_execute_fstring_without_interpolation() {
        // Required by issue #257: an f-string with no actual interpolation
        // has no injection surface and must not flag.
        let findings = scan(r#"cursor.execute(f"SELECT * FROM users")"#, Lang::Python);
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_ignores_parameterized_execute() {
        // Required false-positive test from issue #257.
        let findings = scan(
            r#"cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))"#,
            Lang::Python,
        );
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_flags_execute_percent_format() {
        let findings = scan(
            r#"cursor.execute("SELECT * FROM %s" % table)"#,
            Lang::Python,
        );
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_flags_execute_dot_format() {
        let findings = scan(
            r#"cursor.execute("SELECT * FROM {}".format(table))"#,
            Lang::Python,
        );
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_flags_execute_string_concat() {
        let findings = scan(r#"cursor.execute("SELECT * FROM " + table)"#, Lang::Python);
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_flags_executemany_fstring() {
        let findings = scan(
            r#"cursor.executemany(f"INSERT INTO {table} VALUES (?)", rows)"#,
            Lang::Python,
        );
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_ignores_execute_mention_in_comment() {
        // Required false-positive test from issue #257.
        let findings = scan(
            "# cursor.execute(f\"SELECT * FROM {table}\") is bad\nprint(1)",
            Lang::Python,
        );
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn python_ignores_execute_mention_in_string_literal() {
        // Required false-positive test from issue #257.
        let findings = scan(r#"s = "cursor.execute(x)""#, Lang::Python);
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn js_flags_query_template_literal_with_interpolation() {
        // Required by issue #257.
        let findings = scan(
            "db.query(`SELECT * FROM users WHERE id = ${id}`)",
            Lang::JavaScript,
        );
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn js_ignores_query_template_literal_without_interpolation() {
        let findings = scan("db.query(`SELECT * FROM users`)", Lang::JavaScript);
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn js_ignores_parameterized_query() {
        let findings = scan(
            r#"db.query("SELECT * FROM users WHERE id = $1", [id])"#,
            Lang::JavaScript,
        );
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn js_flags_execute_template_literal_with_interpolation() {
        let findings = scan(
            "connection.execute(`DELETE FROM users WHERE id = ${id}`)",
            Lang::JavaScript,
        );
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn ts_flags_query_template_literal_with_interpolation() {
        let findings = scan(
            "db.query(`SELECT * FROM users WHERE id = ${id}`);",
            Lang::TypeScript,
        );
        assert!(has_sql_string_interpolation_finding(&findings));
    }

    #[test]
    fn rust_has_no_sql_string_interpolation_rule() {
        let findings = scan(r#"fn main() { let x = 1; }"#, Lang::Rust);
        assert!(!has_sql_string_interpolation_finding(&findings));
    }

    // ── xss-sink (issue #262) ──
    // No RHS/value narrowing here — the reference (security-guidance's
    // innerHTML_xss/outerHTML_xss/insertAdjacentHTML_xss/document_write_xss/
    // react_dangerously_set_html rules) flags every occurrence of these
    // sinks via a plain substring match, gated only by file extension
    // (path_filter), not by whether the assigned/passed value looks
    // static or dynamic — so there is no narrower upstream behavior to
    // match here, unlike e.g. `tls-verify-disabled`'s literal-`False`-only
    // narrowing. AST matching still eliminates the comment/string-literal
    // false positives a regex would hit, same as every other rule in this
    // file.

    fn has_xss_sink_finding(findings: &[Finding]) -> bool {
        findings.iter().any(|f| f.rule == "xss-sink")
    }

    // .innerHTML =

    #[test]
    fn js_flags_inner_html_assignment() {
        let findings = scan("el.innerHTML = userInput;", Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_inner_html_assignment_of_static_string() {
        // No RHS narrowing (see section doc comment) — even an apparently
        // static string literal assignment flags, matching the reference's
        // unnarrowed substring behavior.
        let findings = scan(r#"el.innerHTML = "<b>hi</b>";"#, Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_text_content_assignment() {
        // Required false-positive test: textContent is the safe alternative
        // and must never be flagged.
        let findings = scan("el.textContent = userInput;", Lang::JavaScript);
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_inner_html_mention_in_comment() {
        let findings = scan(
            "// el.innerHTML = userInput; is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_inner_html_mention_in_string_literal() {
        let findings = scan(r#"const s = "el.innerHTML = userInput";"#, Lang::JavaScript);
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn ts_flags_inner_html_assignment() {
        let findings = scan("el.innerHTML = userInput;", Lang::TypeScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_inner_html_compound_assignment() {
        // Verified P1 Greptile finding on PR #299: `+=` is an
        // `augmented_assignment_expression`, a distinct grammar node from
        // plain `assignment_expression`, and previously bypassed the guard.
        let findings = scan("el.innerHTML += userInput;", Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_inner_html_bracket_assignment() {
        // Verified P1 Greptile finding on PR #299: computed/bracket property
        // access is a `subscript_expression`, a distinct grammar node from
        // `member_expression`, and previously bypassed the guard.
        let findings = scan(r#"el["innerHTML"] = userInput;"#, Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    // .outerHTML =

    #[test]
    fn js_flags_outer_html_assignment() {
        let findings = scan("el.outerHTML = userInput;", Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_outer_html_mention_in_comment() {
        let findings = scan(
            "// el.outerHTML = userInput; is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn ts_flags_outer_html_assignment() {
        let findings = scan("el.outerHTML = userInput;", Lang::TypeScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_outer_html_compound_assignment() {
        // Verified P1 Greptile finding on PR #299.
        let findings = scan("el.outerHTML += userInput;", Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_outer_html_bracket_assignment() {
        // Verified P1 Greptile finding on PR #299.
        let findings = scan(r#"el["outerHTML"] = userInput;"#, Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    // .insertAdjacentHTML(...)

    #[test]
    fn js_flags_insert_adjacent_html() {
        let findings = scan(
            "el.insertAdjacentHTML('beforeend', userInput);",
            Lang::JavaScript,
        );
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_insert_adjacent_text() {
        // Required false-positive test: insertAdjacentText is the safe
        // alternative and must never be flagged.
        let findings = scan(
            "el.insertAdjacentText('beforeend', userInput);",
            Lang::JavaScript,
        );
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_insert_adjacent_html_mention_in_comment() {
        let findings = scan(
            "// el.insertAdjacentHTML('beforeend', x) is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn ts_flags_insert_adjacent_html() {
        let findings = scan(
            "el.insertAdjacentHTML('beforeend', userInput);",
            Lang::TypeScript,
        );
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_insert_adjacent_html_bracket_call() {
        // Verified P1 Greptile finding on PR #299: computed-property call
        // form (`subscript_expression` as the call's `function`) previously
        // bypassed the guard entirely.
        let findings = scan(
            r#"el["insertAdjacentHTML"]("beforeend", userInput);"#,
            Lang::JavaScript,
        );
        assert!(has_xss_sink_finding(&findings));
    }

    // document.write(...)

    #[test]
    fn js_flags_document_write() {
        let findings = scan("document.write(userInput);", Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_document_writeln() {
        // document.writeln is a distinct method name; the query matches
        // "write" exactly, not as a prefix.
        let findings = scan("document.writeln(userInput);", Lang::JavaScript);
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_document_write_mention_in_comment() {
        let findings = scan(
            "// document.write(x) is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_document_write_mention_in_string_literal() {
        let findings = scan(r#"const s = "document.write(x)";"#, Lang::JavaScript);
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn ts_flags_document_write() {
        let findings = scan("document.write(userInput);", Lang::TypeScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_flags_document_write_bracket_call() {
        // Verified P1 Greptile finding on PR #299: `document["write"](...)`
        // previously bypassed the guard entirely.
        let findings = scan(r#"document["write"](userInput);"#, Lang::JavaScript);
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_bracket_write_on_other_object() {
        // Negative case: the document.write rule is deliberately scoped to
        // the `document` object, not any object with a `.write()`/`["write"]()`
        // method — `foo["write"](x)` must not flag, mirroring the existing
        // scoping of the dot-access form to `document` specifically.
        let findings = scan(r#"foo["write"](userInput);"#, Lang::JavaScript);
        assert!(!has_xss_sink_finding(&findings));
    }

    // dangerouslySetInnerHTML (JSX attribute — reachable in .js/.jsx via
    // tree-sitter-javascript's built-in JSX support, and in .tsx via the
    // dedicated LANGUAGE_TSX grammar; NOT reachable in plain .ts, which
    // can't contain JSX syntax at all).

    #[test]
    fn js_flags_dangerously_set_inner_html_in_jsx() {
        let findings = scan(
            "const el = <div dangerouslySetInnerHTML={{__html: userInput}} />;",
            Lang::JavaScript,
        );
        assert!(
            has_xss_sink_finding(&findings),
            "tree-sitter-javascript parses JSX by default even in a .js/.jsx file"
        );
    }

    #[test]
    fn tsx_flags_dangerously_set_inner_html() {
        let findings = scan(
            "const el = <div dangerouslySetInnerHTML={{__html: userInput}} />;",
            Lang::Tsx,
        );
        assert!(has_xss_sink_finding(&findings));
    }

    #[test]
    fn ts_has_no_dangerously_set_inner_html_rule() {
        // Plain .ts can't contain JSX syntax; LANGUAGE_TYPESCRIPT has no
        // jsx_attribute node kind at all, so this is genuinely unreachable,
        // not just an unlikely false negative. A bare mention of the
        // identifier (not inside a JSX attribute) must not flag either.
        let findings = scan("const dangerouslySetInnerHTML = true;", Lang::TypeScript);
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn js_ignores_dangerously_set_inner_html_mention_in_comment() {
        let findings = scan(
            "// dangerouslySetInnerHTML is bad\nfunction f(){return 1;}",
            Lang::JavaScript,
        );
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn python_has_no_xss_sink_rule() {
        let findings = scan("eval(x)", Lang::Python);
        assert!(!has_xss_sink_finding(&findings));
    }

    #[test]
    fn rust_has_no_xss_sink_rule() {
        let findings = scan(r#"fn main() { let x = 1; }"#, Lang::Rust);
        assert!(!has_xss_sink_finding(&findings));
    }

    // ── rust-unsafe-block (issue #258) ──

    fn has_rust_unsafe_block_finding(findings: &[Finding]) -> bool {
        findings.iter().any(|f| f.rule == "rust-unsafe-block")
    }

    #[test]
    fn rust_flags_unsafe_block() {
        let findings = scan(r#"fn main() { unsafe { std::ptr::read(x) }; }"#, Lang::Rust);
        assert!(has_rust_unsafe_block_finding(&findings));
    }

    #[test]
    fn rust_ignores_unsafe_fn_signature_without_block() {
        // Documented as out of scope for v1 per issue #258: `unsafe fn`
        // produces a distinct `function_modifiers` node with no
        // `unsafe_block` child, so a bare unsafe fn signature never matches.
        let findings = scan(r#"unsafe fn foo() {}"#, Lang::Rust);
        assert!(!has_rust_unsafe_block_finding(&findings));
    }

    #[test]
    fn rust_ignores_unsafe_block_mention_in_comment() {
        let findings = scan("// unsafe { ... } is dangerous\nfn f(){}", Lang::Rust);
        assert!(!has_rust_unsafe_block_finding(&findings));
    }

    #[test]
    fn rust_ignores_unsafe_block_mention_in_string_literal() {
        let findings = scan(
            r#"fn main() { let s = "unsafe { ptr::read(x) }"; }"#,
            Lang::Rust,
        );
        assert!(!has_rust_unsafe_block_finding(&findings));
    }

    #[test]
    fn python_has_no_rust_unsafe_block_rule() {
        let findings = scan("eval(x)", Lang::Python);
        assert!(!has_rust_unsafe_block_finding(&findings));
    }
}
