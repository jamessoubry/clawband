//! YAML (GitHub Actions workflow) and HTML (Subresource Integrity) specific
//! `ast_guard` rules — split out of `ast_guard.rs` to keep that file's own
//! CodeScene "Lines of Code in a Single File" metric under control as new
//! languages are added (issue #265 follow-up); these rules share no code
//! with the other languages' rules beyond `Finding` itself.

use super::Finding;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language as TsLanguage, Query, QueryCursor};

/// A parsed file's AST paired with its source text — bundles the two values
/// every `*_findings` function in this module needs together (a tree-sitter
/// query runs against the tree, but text extraction/regex-scanning needs the
/// original bytes) into a single parameter object rather than two separate
/// arguments, per CodeScene's "Introduce Parameter Object" guidance for a
/// String Heavy Function Arguments finding.
pub(super) struct ParsedSource<'a> {
    pub(super) tree: &'a tree_sitter::Tree,
    pub(super) content: &'a str,
}

/// Compiles `query_src` against `ts_lang` and resolves `capture_name` to its
/// capture index, collapsing the "query failed to compile" / "capture not
/// found" pair of early-return branches every `*_findings` function in this
/// module repeats into a single `let...else` at the call site — shared here
/// (rather than only by the two new rules) purely to keep each new rule's
/// own cyclomatic complexity down; pre-existing `*_findings` functions are
/// left as-is since they're unchanged by issue #265.
fn compile_query_with_capture(
    ts_lang: &TsLanguage,
    query_src: &str,
    capture_name: &str,
) -> Option<(Query, usize)> {
    let query = Query::new(ts_lang, query_src).ok()?;
    let index = query
        .capture_names()
        .iter()
        .position(|n| *n == capture_name)?;
    Some((query, index))
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Decodes a single `\xXX`/`\uXXXX`/`\UXXXXXXXX` escape (or a short table of
/// fixed single-char escapes) starting right after the backslash in a YAML
/// double-quoted scalar's raw text, returning the decoded `char` and how
/// many source bytes (not counting the backslash itself) it consumed.
/// Unrecognized escapes fall back to the escaped character literally (e.g.
/// `\q` -> `q`), which is safe here: this is used only to recognize whether
/// a key decodes to `run`, and under-decoding an obscure escape just means
/// a (rare) missed match, never a wrong one.
fn decode_yaml_escape(rest: &str) -> (char, usize) {
    let hex_escape = |rest: &str, digits: usize| -> Option<(char, usize)> {
        let hex = rest.get(..digits)?;
        let code = u32::from_str_radix(hex, 16).ok()?;
        Some((char::from_u32(code)?, digits))
    };
    match rest.chars().next() {
        Some('x') => hex_escape(&rest[1..], 2).map(|(c, n)| (c, n + 1)),
        Some('u') => hex_escape(&rest[1..], 4).map(|(c, n)| (c, n + 1)),
        Some('U') => hex_escape(&rest[1..], 8).map(|(c, n)| (c, n + 1)),
        Some('n') => Some(('\n', 1)),
        Some('t') => Some(('\t', 1)),
        Some('r') => Some(('\r', 1)),
        Some('0') => Some(('\0', 1)),
        Some(c) => Some((c, 1)),
        None => None,
    }
    .unwrap_or_else(|| (rest.chars().next().unwrap_or('\\'), 1))
}

/// Decodes a YAML double-quoted scalar's escape sequences (confirmed via
/// `tree-sitter-yaml`'s actual node text — a `double_quote_scalar` node's
/// text is the raw source between and including the quote characters,
/// escapes un-decoded) into the string it actually represents at the YAML
/// level.
///
/// Third-opinion/Greptile review finding on PR #319: a key written as
/// `"run"` is the YAML string `run` (the `u` escape decodes to
/// `u`) but compares unequal to the literal text `run` unless the escapes
/// are actually decoded — a real bypass of the quoted-key fix added earlier
/// in this PR, since an attacker who can't use a literal `run` key due to
/// detection can trivially spell it with an escape instead.
fn decode_yaml_double_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.char_indices();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let (decoded, consumed) = decode_yaml_escape(&inner[i + 1..]);
        out.push(decoded);
        for _ in 0..consumed {
            chars.next();
        }
    }
    out
}

/// Returns the YAML-level string value of a `key: (_)` capture's node —
/// decoding quotes and escapes per YAML's three key-quoting styles (plain,
/// single-quoted, double-quoted) — so comparing it against `"run"` can't be
/// bypassed by a quoting or escaping trick a literal-text comparison would
/// miss. `key_node` is the `flow_node` the query captures; its first named
/// child is the actual scalar node, whose `kind()` says which style applies.
fn yaml_scalar_value(key_node: tree_sitter::Node, content: &str) -> Option<String> {
    let scalar = key_node.named_child(0)?;
    let raw = scalar.utf8_text(content.as_bytes()).ok()?;
    match scalar.kind() {
        "double_quote_scalar" => {
            let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
            Some(decode_yaml_double_quoted(inner))
        }
        "single_quote_scalar" => {
            let inner = raw.strip_prefix('\'')?.strip_suffix('\'')?;
            Some(inner.replace("''", "'"))
        }
        _ => Some(raw.trim().to_string()),
    }
}

/// Returns true if `expr` contains `base` as a real field-access root (e.g.
/// `base.foo`, `base[0]`, or `base` alone) rather than merely as a substring
/// of a longer identifier. Second-opinion review finding on PR #319:
/// `expr.contains("github.event")` false-flagged `github.event_name` — a
/// fixed, GitHub-controlled value this rule's own doc comment explicitly
/// says is NOT meant to match — because a bare substring check can't tell
/// "github.event." from "github.event_name". Checked directionally: the
/// character immediately *after* the match must not continue an identifier
/// (rules out `_name`/`_path` suffixes), and the character immediately
/// *before* it must not continue one either (rules out matching the tail of
/// some unrelated longer identifier). Scans every occurrence, not just the
/// first, since `expr` can be an arbitrary expression like
/// `toJson(github.event.issue.title)`.
fn contains_field_access(expr: &str, base: &str) -> bool {
    let mut search_from = 0;
    while let Some(rel) = expr[search_from..].find(base) {
        let start = search_from + rel;
        let end = start + base.len();
        let end_is_boundary = expr[end..].chars().next().is_none_or(|c| !is_ident_char(c));
        let start_is_boundary = expr[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c));
        if end_is_boundary && start_is_boundary {
            return true;
        }
        search_from = start + 1;
    }
    false
}

/// Returns true if `expr` (the text between `${{` and `}}`) references a
/// GitHub Actions context that can carry attacker-controlled text —
/// `github.event.*` (issue/PR/comment titles and bodies, commit messages,
/// etc.), `github.head_ref` (a PR's source branch name), or `inputs.*` (a
/// `workflow_dispatch`/`pull_request_target` trigger's user-supplied input
/// values) — per GitHub's own documented script-injection hardening
/// guidance. `github.event_name`/`github.sha`/etc. are fixed,
/// workflow-controlled values and intentionally not matched here.
///
/// Second-opinion review finding on PR #319: `inputs.*` wasn't covered at
/// all, despite GitHub's hardening docs listing it alongside `head_ref` as
/// untrusted on those two trigger types. This rule doesn't track which
/// trigger a given workflow uses, so `inputs.*` is flagged unconditionally —
/// a deliberately conservative choice (a false positive on a safely-scoped
/// `inputs.*` use costs a reviewed-and-dismissed finding; a false negative
/// on an actually-unsafe one costs a real injection).
///
/// Third-opinion review finding on PR #319: GitHub Actions expressions
/// support index syntax (`github['event']`) as an alternative to dot
/// access — the literal substring `github.event` never appears in
/// `github['event']`, so the dot-only check above missed it entirely. (The
/// `inputs`/`head_ref` checks don't need an equivalent bracket form here:
/// `contains_field_access(expr, "inputs")` already matches `inputs['foo']`
/// as a substring with an `inputs` root and a non-identifier boundary right
/// after it, and `head_ref` is checked below.) `expr` is already
/// lowercased by the caller, so only lowercase bracket forms need
/// checking.
fn is_untrusted_github_context(expr: &str) -> bool {
    contains_field_access(expr, "github.event")
        || expr.contains("github.head_ref")
        || expr.contains("github['head_ref'")
        || expr.contains("github[\"head_ref\"")
        || contains_field_access(expr, "inputs")
        || expr.contains("github['event'")
        || expr.contains("github[\"event\"")
}

/// Compiled once (the pattern is a fixed literal, not user input) rather
/// than on every `yaml_github_actions_workflow_findings` call.
///
/// Third-opinion review finding on PR #319: the original `[^}]*?` body
/// stops at the *first* `}`, so an expression with a single inner brace —
/// `format('{0}', github.event.issue.title)`, `fromJSON('{"k":1}')` — never
/// reaches a `\s*\}\}` and the whole interpolation goes unmatched. `(?s).*?`
/// (non-greedy, `.` matches `\n` too) still stops at the first `}}` it
/// finds, which is correct: GitHub Actions expressions can't themselves
/// contain a literal `}}`, so the first one is always the real terminator.
fn github_interpolation_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?s)\$\{\{\s*(.*?)\s*\}\}").expect("valid literal regex"))
}

/// Finds untrusted GitHub Actions context expressions (`${{ github.event...
/// }}`, `${{ github.head_ref }}`) interpolated directly into a `run:` step's
/// shell script body (issue #265) — the classic command-injection pattern:
/// the expression is substituted into the script text verbatim *before* the
/// shell ever runs, so an attacker-controlled issue/PR title containing
/// shell metacharacters executes as code. The documented-safe fix is to pass
/// the value through an `env:` entry first and reference it as a shell
/// variable (`$TITLE`) instead — such a workflow has no `${{ }}` in the
/// `run:` body at all, so it simply doesn't match this query's text scan.
///
/// A tree-sitter query can match a `run:` mapping pair's presence, but
/// "scan this scalar's raw text for a substring pattern" isn't an AST
/// structural condition at all — same reason `python_sql_string_interpolation_findings`
/// inspects node text content with a plain string/regex check rather than a
/// query predicate. `value: (_) @value` is used (rather than naming the
/// exact scalar node kind) because a `run:` value can be a block scalar
/// (`run: |`) or a plain/quoted flow scalar (`run: echo ...`) — distinct AST
/// shapes with the same raw-text danger.
///
/// Third-opinion review finding on PR #319: the original query only matched
/// `block_mapping_pair key: (flow_node (plain_scalar (string_scalar) @key))`
/// with an `#eq?` predicate against the literal `run` — so `"run":`
/// (`key: (flow_node (double_quote_scalar))`) and `'run':` (`single_quote_scalar`)
/// never matched the `plain_scalar` shape and bypassed detection entirely,
/// and flow-mapping steps (`{ run: 'echo ...' }`, parsed as `flow_pair`
/// inside `flow_mapping`, never `block_mapping_pair`) weren't matched by
/// either grammar rule at all. Fixed by matching `key: (_) @key` generically
/// on both `block_mapping_pair` and `flow_pair` (confirmed against
/// `tree-sitter-yaml`'s actual parse output for both quoted-key and
/// flow-mapping forms) and comparing the captured key's text — with
/// surrounding quotes stripped — in Rust instead of via `#eq?`, which can
/// only compare a node's literal source text and so can't itself see past
/// the quote characters.
pub(super) fn yaml_github_actions_workflow_findings(source: &ParsedSource) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_yaml::LANGUAGE.into();
    let query_src = r#"
(block_mapping_pair key: (_) @key value: (_) @value)
(flow_pair key: (_) @key value: (_) @value)
"#;
    let Ok(query) = Query::new(&ts_lang, query_src) else {
        return vec![];
    };
    let capture_names = query.capture_names();
    let (Some(key_index), Some(value_index)) = (
        capture_names.iter().position(|n| *n == "key"),
        capture_names.iter().position(|n| *n == "value"),
    ) else {
        return vec![];
    };
    let interpolation = github_interpolation_regex();
    let content = source.content;

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, source.tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        let is_run_key = m
            .captures
            .iter()
            .find(|c| c.index as usize == key_index)
            .and_then(|c| yaml_scalar_value(c.node, content))
            .is_some_and(|k| k.eq_ignore_ascii_case("run"));
        if !is_run_key {
            continue;
        }
        let Some(cap) = m.captures.iter().find(|c| c.index as usize == value_index) else {
            continue;
        };
        let Ok(text) = cap.node.utf8_text(content.as_bytes()) else {
            continue;
        };
        let flagged = interpolation
            .captures_iter(text)
            .any(|c| is_untrusted_github_context(&c[1].to_lowercase()));
        if flagged {
            findings.push(Finding {
                rule: "github-actions-workflow",
                reason: "untrusted GitHub Actions context expression interpolated directly into a run: step's shell script — the value is substituted into the script text before the shell runs, so attacker-controlled content (an issue/PR title, branch name, etc.) executes as shell code; pass it through env: instead and reference it as a shell variable (e.g. $TITLE)",
            });
        }
    }
    findings
}

/// Returns the text content of an HTML `attribute` node's value — handling
/// both the unquoted form (`attribute_value` as a direct child) and the
/// quoted form (`attribute_value` nested inside `quoted_attribute_value`),
/// since `tree-sitter-html`'s grammar represents these as genuinely
/// different node shapes (confirmed against node-types.json) despite having
/// the same meaning.
fn html_attribute_value<'a>(attr: tree_sitter::Node, source: &ParsedSource<'a>) -> Option<&'a str> {
    let mut c = attr.walk();
    for child in attr.named_children(&mut c) {
        let value_node = match child.kind() {
            "attribute_value" => Some(child),
            "quoted_attribute_value" => child
                .named_child(0)
                .filter(|n| n.kind() == "attribute_value"),
            _ => None,
        };
        if let Some(node) = value_node {
            return node.utf8_text(source.content.as_bytes()).ok();
        }
    }
    None
}

/// `true` if `value` contains at least one well-formed SRI hash token
/// (`sha256-`/`sha384-`/`sha512-` followed by a non-empty base64-alphabet
/// hash — multiple space-separated hashes are valid per the SRI spec; a
/// browser uses whichever one it supports). Greptile review finding on PR
/// #319: the original check only asked "is this attribute's value
/// non-empty", so `integrity="garbage"` counted as protection despite
/// supplying no real hash for the browser to verify against.
fn is_valid_sri_hash(value: &str) -> bool {
    value.split_whitespace().any(|token| {
        ["sha256-", "sha384-", "sha512-"].iter().any(|prefix| {
            token
                .strip_prefix(prefix)
                .is_some_and(|hash| !hash.is_empty())
        })
    })
}

/// Walks a `<script>` tag's `start_tag` node for its `src` and `integrity`
/// attributes — split out of `html_script_src_without_sri_findings` purely
/// to keep that function's own cyclomatic/nesting complexity down; the
/// query itself can't express "has attribute X but lacks attribute Y"
/// directly, same shape as `python_yaml_load_findings`'s `Loader=` check.
///
/// Greptile review finding on PR #319: a tag with a *duplicate* `src` or
/// `integrity` attribute was resolved to the *last* occurrence here, but
/// HTML parsing keeps the *first* and ignores later duplicates outright
/// (confirmed against actual browser behavior) — so a page with a safe
/// first `integrity=""` followed by a second, real-looking
/// `integrity="sha384-..."` was flagged as safe by this function while a
/// real browser still treats the script as having no integrity check at
/// all (and vice versa for `src`). Only the first occurrence of each
/// attribute is honored below, matching that semantics exactly.
fn html_script_attrs<'a>(
    start_tag: tree_sitter::Node,
    source: &ParsedSource<'a>,
) -> (Option<&'a str>, bool) {
    let mut src = None;
    let mut src_seen = false;
    let mut integrity_value = None;
    let mut integrity_seen = false;
    let mut c = start_tag.walk();
    for attr in start_tag.named_children(&mut c) {
        if attr.kind() != "attribute" {
            continue;
        }
        let name = attr
            .named_child(0)
            .filter(|n| n.kind() == "attribute_name")
            .and_then(|n| n.utf8_text(source.content.as_bytes()).ok());
        // Third-opinion review finding on PR #319: HTML attribute names are
        // case-insensitive per spec (confirmed against tree-sitter-html's
        // actual output — it preserves the source's original case verbatim,
        // doesn't normalize it), so `<script SRC=... INTEGRITY=...>` has
        // neither attribute recognized by a lowercase-literal match.
        //
        // CodeScene "Bumpy Road Ahead" finding: the `!src_seen`/
        // `!integrity_seen` checks fold into each branch's own `if`
        // condition (rather than a separate nested `if` inside each
        // branch, as an earlier version of this had) specifically to keep
        // nesting flat — a `slot.is_none()`-based "already set" check was
        // tried instead and reverted: it can't distinguish "first
        // occurrence had no value" (a bare `integrity` attribute) from
        // "not seen yet", which would wrongly let a later duplicate's real
        // hash override a bare first `integrity` attribute's correct
        // (no-SRI) outcome.
        if name.is_some_and(|n| n.eq_ignore_ascii_case("src")) && !src_seen {
            src = html_attribute_value(attr, source);
            src_seen = true;
        } else if name.is_some_and(|n| n.eq_ignore_ascii_case("integrity")) && !integrity_seen {
            integrity_value = html_attribute_value(attr, source);
            integrity_seen = true;
        }
    }
    let has_integrity = integrity_value.is_some_and(is_valid_sri_hash);
    (src, has_integrity)
}

/// `true` if `src` points at a third-party origin (absolute `http://`/
/// `https://`, or protocol-relative `//host/...`) rather than a local/
/// relative path — split out purely to keep
/// `html_script_src_without_sri_findings`'s own cyclomatic complexity under
/// CodeScene's threshold (adding the protocol-relative check inline pushed
/// it over).
///
/// Third-opinion review finding on PR #319: URL schemes are case-insensitive
/// (`HTTPS://cdn.example.com/...` is just as external as `https://...`), so
/// the original exact-prefix check missed any non-lowercase scheme.
///
/// Greptile review finding on PR #319: `tree-sitter-html` returns an
/// attribute value's *raw* source text, HTML character references
/// un-decoded — `src="https&#58;//cdn.example.com/lib.js"` is, once a
/// browser decodes `&#58;` to `:`, the exact same external HTTPS URL as the
/// plain-spelled version, but the undecoded text doesn't start with
/// `https://` and bypassed the check entirely. Decoded here before the
/// prefix check so the two spellings are treated identically.
fn is_external_script_src(src: &str) -> bool {
    let decoded = decode_html_char_refs(src);
    let lower = decoded.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("//")
}

/// Decodes HTML character references (`&#58;`, `&#x3A;`, and the five
/// standard named entities) in `s` — the subset of HTML's character
/// reference grammar relevant to URL scheme spoofing (a reference inside a
/// `src` attribute decoding to `:` or `/`). Unrecognized/malformed
/// references are left as-is rather than guessed at.
fn decode_html_char_refs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after_amp = &rest[amp + 1..];
        let Some(semi) = after_amp.find(';') else {
            out.push('&');
            rest = after_amp;
            continue;
        };
        let entity = &after_amp[..semi];
        let decoded_char = if let Some(numeric) = entity.strip_prefix('#') {
            if let Some(hex) = numeric.strip_prefix('x').or(numeric.strip_prefix('X')) {
                u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
            } else {
                numeric.parse::<u32>().ok().and_then(char::from_u32)
            }
        } else {
            match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => None,
            }
        };
        match decoded_char {
            Some(c) => out.push(c),
            None => {
                out.push('&');
                out.push_str(entity);
                out.push(';');
            }
        }
        rest = &after_amp[semi + 1..];
    }
    out.push_str(rest);
    out
}

/// Finds `<script>` tags with an external `http://`/`https://`/protocol-
/// relative (`//host/...`) `src` but no `integrity` attribute — missing
/// Subresource Integrity (issue #265). A local/relative `src` (no host) is
/// exempt: SRI only protects against a compromised third-party host serving
/// modified content, which doesn't apply to a script served by the same
/// origin. Second-opinion review finding on PR #319: protocol-relative URLs
/// (`src="//cdn.example.com/lib.js"`) load from a third-party origin exactly
/// like `https://cdn.example.com/lib.js` does — SRI matters equally there —
/// but the original `http://`/`https://`-only prefix check missed them.
///
/// `tree-sitter-html`'s `attribute` node has no `name`/`value` fields (confirmed
/// against node-types.json — just an unordered `attribute_name` +
/// `attribute_value`/`quoted_attribute_value` child list), and "has a src
/// attribute but lacks an integrity attribute" is an absence condition
/// across sibling nodes a query can't express directly — same shape as
/// `python_yaml_load_findings`'s `Loader=` check — so this matches each
/// `script_element`'s `start_tag` generically and walks its attributes in
/// Rust.
pub(super) fn html_script_src_without_sri_findings(source: &ParsedSource) -> Vec<Finding> {
    let ts_lang: TsLanguage = tree_sitter_html::LANGUAGE.into();
    let query_src = r#"(script_element (start_tag) @tag)"#;
    let Some((query, tag_index)) = compile_query_with_capture(&ts_lang, query_src, "tag") else {
        return vec![];
    };
    let content = source.content;

    let mut findings = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, source.tree.root_node(), content.as_bytes());
    while let Some(m) = matches.next() {
        for cap in m.captures {
            if cap.index as usize != tag_index {
                continue;
            }
            let (src, has_integrity) = html_script_attrs(cap.node, source);
            let is_external = src.is_some_and(is_external_script_src);
            if is_external && !has_integrity {
                findings.push(Finding {
                    rule: "script-src-without-sri",
                    reason: "externally-hosted <script> missing Subresource Integrity (integrity attribute) — if the remote host or CDN is ever compromised, it can serve modified script content that the browser will execute unverified; add an integrity=\"sha384-...\" attribute matching the expected file hash",
                });
            }
        }
    }
    findings
}
