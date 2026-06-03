use regex::Regex;
use std::{
    env, fs,
    io::{self, Read, Write},
    path::PathBuf,
};

// ─── Decision output ──────────────────────────────────────────────────────────

fn output(decision: &str, reason: &str) {
    // Manually build JSON to avoid depending on serde_json for output
    // (we still use it for input parsing)
    let reason_escaped = reason
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    println!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"{}","permissionDecisionReason":"{}"}}}}"#,
        decision, reason_escaped
    );
}

fn log_action(decision: &str, reason: &str, command: &str) {
    let home = env::var("HOME").unwrap_or_default();
    let path = PathBuf::from(&home).join(".clawband.log");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let cmd_preview = &command[..command.len().min(200)];
    if let Ok(mut f) = fs::OpenOptions::new().append(true).create(true).open(path) {
        let _ = writeln!(
            f,
            "[{}] {} | {} | {}",
            ts,
            decision.to_uppercase(),
            reason,
            cmd_preview
        );
    }
}

// ─── Pattern ──────────────────────────────────────────────────────────────────

struct Pattern {
    label: String,
    re: Regex,
}

impl Pattern {
    fn builtin(label: &str, pat: &str) -> Self {
        Self {
            label: label.to_string(),
            re: Regex::new(&format!("(?i){}", pat))
                .unwrap_or_else(|e| panic!("invalid built-in pattern '{}': {}", pat, e)),
        }
    }

    fn from_user(raw: &str) -> Option<Self> {
        Regex::new(&format!("(?i){}", raw)).ok().map(|re| Self {
            label: raw.to_string(),
            re,
        })
    }

    fn matches(&self, text: &str) -> bool {
        self.re.is_match(text)
    }
}

// ─── Built-in deny patterns ───────────────────────────────────────────────────

fn builtin_deny() -> Vec<Pattern> {
    let specs: &[(&str, &str)] = &[
        // File system destruction — handles any flag ordering: -rf, -fr, -r -f, -f -r
        (
            "rm -rf /",
            r"\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*)\s+/",
        ),
        (
            "rm -rf ~",
            r"\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*)\s+~",
        ),
        (
            "rm -rf $HOME",
            r"\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*)\s+\$HOME",
        ),
        (
            "sudo rm -rf",
            r"\bsudo\s+rm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|-[a-z]*r[a-z]*\s+-[a-z]*f[a-z]*|-[a-z]*f[a-z]*\s+-[a-z]*r[a-z]*)",
        ),
        ("mkfs", r"\bmkfs\b"),
        ("dd if=", r"\bdd\s+if="),
        ("dd of=", r"\bdd\s+of="),
        ("> /dev/sd", r">\s*/dev/sd"),
        // Silent file truncation
        ("truncate -s 0", r"\btruncate\b.*-s\s+0\b"),
        // Infrastructure destruction
        ("terraform destroy", r"\bterraform\s+destroy\b"),
        ("terragrunt destroy", r"\bterragrunt\s+destroy\b"),
        (
            "kubectl delete namespace",
            r"\bkubectl\s+delete\s+namespace\b",
        ),
        ("kubectl delete --all", r"\bkubectl\s+delete\s+--all\b"),
        // AWS destructive ops
        (
            "aws rds delete-db-instance",
            r"\baws\s+rds\s+delete-db-instance\b",
        ),
        ("aws eks delete-cluster", r"\baws\s+eks\s+delete-cluster\b"),
        ("aws iam delete-role", r"\baws\s+iam\s+delete-role\b"),
        ("aws s3 rb", r"\baws\s+s3\s+rb(\s|$)"),
        ("aws s3 rm --recursive", r"\baws\s+s3\s+rm\b.*--recursive\b"),
        (
            "aws dynamodb delete-table",
            r"\baws\s+dynamodb\s+delete-table\b",
        ),
        (
            "aws cloudformation delete-stack",
            r"\baws\s+cloudformation\s+delete-stack\b",
        ),
        (
            "aws lambda delete-function",
            r"\baws\s+lambda\s+delete-function\b",
        ),
        // Database destruction
        ("dropdb", r"\bdropdb\b"),
        // Docker destructive ops
        ("docker system prune", r"\bdocker\s+system\s+prune\b"),
        // find -delete (anchored; avoids matching --delete-protection flags)
        ("find -delete", r"\bfind\b.*\s-delete(\s|$)"),
        // find / xargs execution escalation
        ("-exec rm", r"-exec\s+rm\b"),
        ("-exec sh", r"-exec\s+sh\b"),
        ("-exec bash", r"-exec\s+bash\b"),
        ("-exec python", r"-exec\s+python\b"),
        ("-exec zsh", r"-exec\s+zsh\b"),
        ("xargs rm", r"\bxargs\s+rm\b"),
        ("xargs sh", r"\bxargs\s+sh\b"),
        ("xargs bash", r"\bxargs\s+bash\b"),
        ("xargs python", r"\bxargs\s+python3?\b"),
        ("xargs node", r"\bxargs\s+node\b"),
        // Pipe to interpreter — supply-chain attack vector
        ("pipe to sh", r"\|\s*sh(\s|$)"),
        ("pipe to bash", r"\|\s*bash(\s|$)"),
        ("pipe to zsh", r"\|\s*zsh(\s|$)"),
        ("pipe to python", r"\|\s*python3?(\s|$)"),
        ("pipe to node", r"\|\s*node(\s|$)"),
        ("pipe to ruby", r"\|\s*ruby(\s|$)"),
        ("pipe to perl", r"\|\s*perl(\s|$)"),
        // Pipe to interpreter via sudo
        ("pipe to sudo sh", r"\|\s*sudo\s+sh(\s|$)"),
        ("pipe to sudo bash", r"\|\s*sudo\s+bash(\s|$)"),
        ("pipe to sudo zsh", r"\|\s*sudo\s+zsh(\s|$)"),
        ("pipe to sudo python", r"\|\s*sudo\s+python3?(\s|$)"),
        ("pipe to sudo node", r"\|\s*sudo\s+node(\s|$)"),
        ("pipe to sudo ruby", r"\|\s*sudo\s+ruby(\s|$)"),
        ("pipe to sudo perl", r"\|\s*sudo\s+perl(\s|$)"),
        // Heredoc to interpreter
        ("heredoc to bash", r"\bbash\s+<<"),
        ("heredoc to sh", r"\bsh\s+<<"),
        ("heredoc to zsh", r"\bzsh\s+<<"),
        ("heredoc to python", r"\bpython3?\s+<<"),
        // Pipe to database CLI
        ("pipe to psql", r"\|\s*psql(\s|$)"),
        ("pipe to mysql", r"\|\s*mysql(\s|$)"),
        ("pipe to sqlite3", r"\|\s*sqlite3(\s|$)"),
        // Pipe to system modification tools
        ("pipe to patch", r"\|\s*patch(\s|$)"),
        ("pipe to crontab", r"\|\s*crontab(\s|$)"),
        ("pipe to at", r"\|\s*at\s"),
    ];
    specs.iter().map(|(l, p)| Pattern::builtin(l, p)).collect()
}

// ─── Built-in ask patterns ────────────────────────────────────────────────────

fn builtin_ask() -> Vec<Pattern> {
    let specs: &[(&str, &str)] = &[
        // eval — common in shell init but executes arbitrary strings
        ("eval", r"\beval\s"),
        // Destructive git (local) — legitimate but irreversible without reflog
        ("git reset --hard", r"\bgit\s+reset\s+--hard\b"),
        ("git checkout -- ", r"\bgit\s+checkout\s+--\s"),
        ("git stash drop", r"\bgit\s+stash\s+drop\b"),
        ("git stash clear", r"\bgit\s+stash\s+clear\b"),
        // git clean — wipes untracked files, unrecoverable
        ("git clean", r"\bgit\s+clean\s+-[fxd]"),
        // Remote branch deletion
        ("git push --delete", r"\bgit\s+push\b.*--delete\b"),
        // git restore without --staged — discards working tree changes
        // [^-] matches a path arg; skips flags so `git restore --staged` is not caught
        ("git restore", r"\bgit\s+restore\s+[^-]"),
        // git branch -D — force-deletes branch regardless of merge status
        // (?-i:-D) disables the outer (?i) for just -D so lowercase -d isn't caught
        ("git branch -D", r"\bgit\s+branch\s+(?-i:-D)\b"),
        // docker rm -f — force-removes a running container
        (
            "docker rm -f",
            r"\bdocker\s+(?:container\s+)?rm\b.*\s-f(\s|$)",
        ),
        // Compiled/bytecode runners — can't scan the binary/JAR/module for content
        ("java -jar", r"\bjava\b.*\s-jar\s"),
        ("go run", r"\bgo\s+run\b"),
        ("cargo run", r"\bcargo\s+run\b"),
    ];
    specs.iter().map(|(l, p)| Pattern::builtin(l, p)).collect()
}

// ─── User pattern files ───────────────────────────────────────────────────────

fn load_patterns(path: &PathBuf) -> Vec<Pattern> {
    let Ok(text) = fs::read_to_string(path) else {
        return vec![];
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(Pattern::from_user)
        .collect()
}

fn config_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_default()).join(".clawband")
}

// ─── RTK prefix stripping ─────────────────────────────────────────────────────

fn strip_rtk(cmd: &str) -> String {
    // Strip "rtk " and "rtk proxy " prefixes, then the git -C <dir> wrapper RTK adds
    let rtk = Regex::new(r"^rtk\s+(?:proxy\s+)?").unwrap();
    let git_c = Regex::new(r"^git\s+-C\s+\S+\s+").unwrap();
    let s = rtk.replace(cmd, "");
    git_c.replace(&s, "git ").into_owned()
}

// ─── sqz suffix stripping ─────────────────────────────────────────────────────

fn strip_sqz(cmd: &str) -> String {
    // sqz rewrites "git status" → "git status 2>&1 | sqz compress --cmd git"
    // Strip the appended sqz pipeline so patterns match the original command.
    let sqz = Regex::new(r"\s*2>&1\s*\|\s*sqz\s+compress\b.*$").unwrap();
    sqz.replace(cmd, "").into_owned()
}

// ─── Script file scanning ────────────────────────────────────────────────────
// When an interpreter runs a script file, read it and check each line against
// deny/ask patterns. Handles shell, Python, JS/TS, Perl, and Lua files.
// Skips inline-execution flags (-c, -m, -e). Unreadable paths fail gracefully.

fn extract_script_path(command: &str) -> Option<String> {
    // Match: (bash|sh|zsh|dash|python3?|node|deno) [optional-flags] <path>
    let re = Regex::new(
        r"(?i)^\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|python3?|node|deno|perl|lua[0-9.]*)\s+((?:-[a-zA-Z]+\s+)*)(.+)$"
    ).unwrap();
    let caps = re.captures(command)?;
    let flags = &caps[1];
    // -c  → shell/python inline command string
    // -m  → python module (e.g. python3 -m pytest)
    // -e / --eval → node inline eval
    if Regex::new(r"(?:^|\s)-[a-zA-Z]*[cme][a-zA-Z]*(\s|$)")
        .unwrap()
        .is_match(flags)
    {
        return None;
    }
    let path_str = caps[2].trim().trim_matches('"').trim_matches('\'');
    // First token only — ignore script arguments after the path
    let path = path_str.split_whitespace().next()?;
    Some(path.to_string())
}

fn scan_script_file(
    path: &str,
    deny_pats: &[Pattern],
    ask_pats: &[Pattern],
    allow_pats: &[Pattern],
) -> Option<(String, String)> {
    let content = fs::read_to_string(path).ok()?;
    let is_js = path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".ts")
        || path.ends_with(".tsx");
    let is_lua = path.ends_with(".lua");
    let mut in_block_comment = false;

    for (lineno, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        // JS/TS block comment state: /* ... */
        if is_js {
            if in_block_comment {
                if line.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }
            if line.starts_with("/*") {
                in_block_comment = !line.contains("*/");
                continue;
            }
            if line.starts_with("//") || line.starts_with('*') {
                continue;
            }
        }

        // Lua comment state: --[[ ... ]] block comments and -- line comments
        if is_lua {
            if in_block_comment {
                if line.contains("]]") {
                    in_block_comment = false;
                }
                continue;
            }
            if line.starts_with("--[[") {
                in_block_comment = !line.contains("]]");
                continue;
            }
            if line.starts_with("--") {
                continue;
            }
        }

        // Shell (#) and Python (#) and Perl (#) line comments
        if line.starts_with('#') {
            continue;
        }

        // Reuse compound-command splitting so `foo && rm -rf /` is caught
        let clean = strip_safe_pipes(line);
        for segment in &split_segments(&clean) {
            if allow_pats.iter().any(|p| p.matches(segment)) {
                continue;
            }
            for pat in deny_pats {
                if pat.matches(segment) {
                    return Some((
                        "deny".into(),
                        format!(
                            "Blocked: '{}' in {}:{}: {}",
                            pat.label,
                            path,
                            lineno + 1,
                            segment
                        ),
                    ));
                }
            }
            for pat in ask_pats {
                if pat.matches(segment) {
                    return Some((
                        "ask".into(),
                        format!(
                            "Review before running — '{}' in {}:{}: {}\nTo always allow: clawband allow '{}'",
                            pat.label,
                            path,
                            lineno + 1,
                            segment,
                            pat.label
                        ),
                    ));
                }
            }
        }
    }
    None
}

// ─── Git force push check ─────────────────────────────────────────────────────

fn check_force_push(cmd: &str) -> Option<String> {
    // Only applies to git push commands
    if !Regex::new(r"(?i)\bgit\s+push\b").unwrap().is_match(cmd) {
        return None;
    }
    // Strip --force-with-lease (safe alternative) first
    let strip_fwl = Regex::new(r"(?i)--force-with-lease(?:=\S+)?").unwrap();
    let cleaned = strip_fwl.replace_all(cmd, "");
    // Then block --force or -f anywhere in the command
    if Regex::new(r"(?i)\s--force(\s|$)|\s-f(\s|$)")
        .unwrap()
        .is_match(&cleaned)
    {
        Some("Blocked: git push --force / -f (use --force-with-lease instead)".into())
    } else {
        None
    }
}

// ─── Safe inline pipe stripping ───────────────────────────────────────────────
// Remove  | python3 -c "..."  and  | python3 -m mod  before pipe checks.
// These are visible inline code, not supply-chain risks.

fn strip_safe_pipes(cmd: &str) -> String {
    let c = Regex::new(r"(?i)\|\s*(python3?|node)\s+-c\s+[^|;&`$]*").unwrap();
    let m = Regex::new(r"(?i)\|\s*(python3?|node)\s+-m\s+\S+").unwrap();
    let s = c.replace_all(cmd, "");
    m.replace_all(&s, "").into_owned()
}

// ─── Compound command splitting ───────────────────────────────────────────────
// Split on &&, ||, ; and newlines.
// Single | is NOT a splitter — keeps pipe-to-interpreter in one segment.
// \; and \| are escaped before splitting so find -exec and regex patterns survive.

fn split_segments(cmd: &str) -> Vec<String> {
    const ESC_SEMI: &str = "\x01S\x01";
    const ESC_PIPE: &str = "\x01P\x01";
    const SEP: &str = "\x01SEP\x01";

    let s = cmd.replace("\\;", ESC_SEMI).replace("\\|", ESC_PIPE);

    let splitter = Regex::new(r"[ \t]*(\|\||&&|;|\n)[ \t]*").unwrap();
    let s = splitter.replace_all(&s, SEP);

    s.split(SEP)
        .map(|seg| seg.trim().replace(ESC_SEMI, "\\;").replace(ESC_PIPE, "\\|"))
        .filter(|s| !s.is_empty())
        .collect()
}

// ─── Allow / deny commands ───────────────────────────────────────────────────

fn cmd_add_pattern(file: &str, args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: clawband allow|deny <pattern>");
        std::process::exit(1);
    }
    let pattern = args.join(" ");

    if Pattern::from_user(&pattern).is_none() {
        eprintln!("clawband: invalid regex: {}", pattern);
        std::process::exit(1);
    }

    let cfg = config_dir();
    let _ = fs::create_dir_all(&cfg);
    let path = cfg.join(file);

    match fs::OpenOptions::new().append(true).create(true).open(&path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{}", pattern);
            let g = "\x1b[32m";
            let b = "\x1b[34m";
            let r = "\x1b[0m";
            let bold = "\x1b[1m";
            println!(
                "{}Added{} {}{}{} → {}{}{}",
                g,
                r,
                bold,
                pattern,
                r,
                b,
                path.display(),
                r
            );
        }
        Err(e) => {
            eprintln!("clawband: failed to write {}: {}", path.display(), e);
            std::process::exit(1);
        }
    }
}

// ─── Stats command ────────────────────────────────────────────────────────────

fn cmd_stats() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    let cfg = config_dir();
    let home = env::var("HOME").unwrap_or_default();

    let builtin_deny_count = builtin_deny().len();
    let builtin_ask_count = builtin_ask().len();

    let count_file = |name: &str| -> (usize, bool) {
        let path = cfg.join(name);
        let exists = path.exists();
        let n = load_patterns(&path).len();
        (n, exists)
    };
    let (user_deny, deny_exists) = count_file("deny.patterns");
    let (user_ask, ask_exists) = count_file("ask.patterns");
    let (user_allow, allow_exists) = count_file("allow.patterns");

    let rtk = env::var("RTK_ENABLED").as_deref() == Ok("1");
    let sqz = env::var("SQZ_ENABLED").as_deref() == Ok("1");
    let logging = env::var("CLAWBAND_LOG").as_deref() == Ok("1");
    let log_path = PathBuf::from(&home).join(".clawband.log");

    // Parse audit log if present
    let (log_deny, log_ask) = if log_path.exists() {
        fs::read_to_string(&log_path)
            .unwrap_or_default()
            .lines()
            .fold((0u64, 0u64), |(d, a), line| {
                if line.contains("] DENY |") {
                    (d + 1, a)
                } else if line.contains("] ASK |") {
                    (d, a + 1)
                } else {
                    (d, a)
                }
            })
    } else {
        (0u64, 0u64)
    };

    let g = "\x1b[32m"; // green
    let y = "\x1b[33m"; // yellow
    let b = "\x1b[34m"; // blue
    let d = "\x1b[2m"; // dim
    let r = "\x1b[0m"; // reset
    let bold = "\x1b[1m";

    println!("\n{bold}clawband v{VERSION}{r}\n");

    println!("{bold}Built-in patterns{r}");
    println!("  {g}deny{r}   {bold}{builtin_deny_count}{r}");
    println!("  {y}ask{r}    {bold}{builtin_ask_count}{r}");

    println!("\n{bold}User patterns{r}  {d}(~/.clawband/){r}");
    let file_status = |exists: bool, n: usize| -> String {
        if !exists {
            format!("{d}file not found{r}")
        } else if n == 0 {
            format!("{d}0 patterns{r}")
        } else {
            format!("{bold}{n}{r} loaded")
        }
    };
    println!("  deny.patterns    {}", file_status(deny_exists, user_deny));
    println!("  ask.patterns     {}", file_status(ask_exists, user_ask));
    println!(
        "  allow.patterns   {}",
        file_status(allow_exists, user_allow)
    );

    println!("\n{bold}Options{r}");
    let flag = |on: bool| {
        if on {
            format!("{g}on{r}")
        } else {
            format!("{d}off{r}")
        }
    };
    println!("  RTK_ENABLED    {}", flag(rtk));
    println!("  SQZ_ENABLED    {}", flag(sqz));
    println!("  CLAWBAND_LOG   {}", flag(logging));

    println!("\n{bold}Audit log{r}");
    if log_path.exists() {
        let total = log_deny + log_ask;
        println!(
            "  {b}{}{r}  {d}({}){r}",
            log_path.display(),
            if total == 0 {
                "empty".to_string()
            } else {
                format!("{total} events")
            }
        );
        if total > 0 {
            println!("  {g}deny{r}   {bold}{log_deny}{r}");
            println!("  {y}ask{r}    {bold}{log_ask}{r}");
        }
    } else if logging {
        println!("  {d}enabled — no events yet{r}");
    } else {
        println!("  {d}set CLAWBAND_LOG=1 in clawband to activate{r}");
    }

    println!();
}

// ─── Core check logic ────────────────────────────────────────────────────────
// Returns Some(("deny"|"ask", reason)) or None for pass.
// Does NOT perform script-file scanning (requires filesystem) or subshell checks.

fn check_command<'a>(
    command: &str,
    deny_pats: &'a [Pattern],
    ask_pats: &'a [Pattern],
    allow_pats: &'a [Pattern],
) -> Option<(&'a str, String)> {
    let clean = strip_safe_pipes(command);
    let segments = split_segments(&clean);

    for segment in &segments {
        if allow_pats.iter().any(|p| p.matches(segment)) {
            continue;
        }

        if let Some(reason) = check_force_push(segment) {
            return Some(("deny", reason));
        }

        for pat in deny_pats {
            if pat.matches(segment) {
                return Some((
                    "deny",
                    format!("Blocked: '{}' matched in: {}", pat.label, segment),
                ));
            }
        }

        for pat in ask_pats {
            if pat.matches(segment) {
                return Some((
                    "ask",
                    format!(
                        "Review before running — '{}' matched in: {}\nTo always allow: clawband allow '{}'",
                        pat.label, segment, pat.label
                    ),
                ));
            }
        }
    }
    None
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    // CLI subcommands
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("stats") => {
            cmd_stats();
            return;
        }
        Some("allow") => {
            cmd_add_pattern("allow.patterns", &args[2..]);
            return;
        }
        Some("deny") => {
            cmd_add_pattern("deny.patterns", &args[2..]);
            return;
        }
        Some("--version") | Some("-v") => {
            println!("clawband v{}", env!("CARGO_PKG_VERSION"));
            return;
        }
        _ => {}
    }

    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    // Parse command from Claude Code hook JSON: {"tool_input": {"command": "..."}}
    let v: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => return,
    };
    let command = match v["tool_input"]["command"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return,
    };

    if env::var("CLAWBAND_SKIP").as_deref() == Ok("1") {
        return;
    }

    let rtk_enabled = env::var("RTK_ENABLED").as_deref() == Ok("1");
    let sqz_enabled = env::var("SQZ_ENABLED").as_deref() == Ok("1");
    let log_enabled = env::var("CLAWBAND_LOG").as_deref() == Ok("1");

    let command = if rtk_enabled {
        strip_rtk(&command)
    } else {
        command
    };
    let command = if sqz_enabled {
        strip_sqz(&command)
    } else {
        command
    };

    // Load all patterns
    let cfg = config_dir();
    let mut deny_pats = builtin_deny();
    let mut ask_pats = builtin_ask();
    let allow_pats = load_patterns(&cfg.join("allow.patterns"));
    deny_pats.extend(load_patterns(&cfg.join("deny.patterns")));
    ask_pats.extend(load_patterns(&cfg.join("ask.patterns")));

    let emit = |decision: &str, reason: &str| {
        if log_enabled {
            log_action(decision, reason, &command);
        }
        output(decision, reason);
    };

    // Core pattern check (deny/ask/pass)
    if let Some((decision, reason)) = check_command(&command, &deny_pats, &ask_pats, &allow_pats) {
        emit(decision, &reason);
        return;
    }

    // Script file scanning: if command is `bash ./foo.sh`, read and check the file.
    if let Some(script_path) = extract_script_path(&command) {
        if let Some((decision, reason)) =
            scan_script_file(&script_path, &deny_pats, &ask_pats, &allow_pats)
        {
            emit(&decision, &reason);
            return;
        }
    }

    // Subshell syntax: $() and backticks embed commands that can't be split above.
    // Ask rather than block — common in legitimate commands.
    if command.contains("$(") || command.contains('`') {
        emit(
            "ask",
            "Command contains subshell ($() or backtick) — review before running.",
        );
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn deny_pats() -> Vec<Pattern> {
        builtin_deny()
    }
    fn ask_pats() -> Vec<Pattern> {
        builtin_ask()
    }
    fn no_allow() -> Vec<Pattern> {
        vec![]
    }

    fn decision(cmd: &str) -> Option<String> {
        check_command(cmd, &deny_pats(), &ask_pats(), &no_allow()).map(|(d, _)| d.to_string())
    }

    // ── deny cases ─────────────────────────────────────────────────────────────

    #[test]
    fn rm_rf_root_denied() {
        assert_eq!(decision("rm -rf /"), Some("deny".into()));
    }

    #[test]
    fn rm_fr_root_denied() {
        assert_eq!(decision("rm -fr /"), Some("deny".into()));
    }

    #[test]
    fn rm_rf_home_tilde_denied() {
        assert_eq!(decision("rm -rf ~/"), Some("deny".into()));
    }

    #[test]
    fn git_push_force_denied() {
        assert_eq!(decision("git push --force"), Some("deny".into()));
    }

    #[test]
    fn docker_system_prune_denied() {
        assert_eq!(decision("docker system prune"), Some("deny".into()));
    }

    // ── ask cases ──────────────────────────────────────────────────────────────

    #[test]
    fn git_reset_hard_asks() {
        assert_eq!(decision("git reset --hard"), Some("ask".into()));
    }

    #[test]
    fn git_branch_uppercase_d_asks() {
        assert_eq!(decision("git branch -D mybranch"), Some("ask".into()));
    }

    #[test]
    fn docker_rm_force_asks() {
        assert_eq!(decision("docker rm -f mycontainer"), Some("ask".into()));
    }

    #[test]
    fn eval_asks() {
        assert_eq!(decision("eval something"), Some("ask".into()));
    }

    #[test]
    fn java_jar_asks() {
        assert_eq!(decision("java -jar app.jar"), Some("ask".into()));
    }

    #[test]
    fn go_run_asks() {
        assert_eq!(decision("go run ./cmd"), Some("ask".into()));
    }

    #[test]
    fn cargo_run_asks() {
        assert_eq!(decision("cargo run"), Some("ask".into()));
    }

    // ── pass cases ─────────────────────────────────────────────────────────────

    #[test]
    fn git_push_force_with_lease_passes() {
        assert_eq!(decision("git push --force-with-lease"), None);
    }

    #[test]
    fn git_branch_lowercase_d_passes() {
        // lowercase -d is a safe delete (only removes merged branches)
        assert_eq!(decision("git branch -d mybranch"), None);
    }

    #[test]
    fn git_commit_then_push_passes() {
        // no --force flag — compound command should pass
        assert_eq!(decision("git commit -F /tmp/msg.txt && git push"), None);
    }

    #[test]
    fn bash_safe_script_graceful_skip() {
        // File doesn't exist on disk — check_command should not crash
        // (script scanning is outside check_command; this just verifies no panic)
        assert_eq!(decision("bash /tmp/safe.sh"), None);
    }
}
