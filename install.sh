#!/bin/bash
# install.sh — install clawband into Claude Code
set -euo pipefail

HOOK_DIR="$HOME/.claude/hooks"
SETTINGS="$HOME/.claude/settings.json"
CONFIG_DIR="$HOME/.clawband"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }

# ── Dependencies ──────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  red "Error: jq is required but not installed."
  echo "  macOS:  brew install jq"
  echo "  Ubuntu: sudo apt install jq"
  exit 1
fi

# ── Copy hook script ──────────────────────────────────────────────────────────
mkdir -p "$HOOK_DIR"
cp "$SCRIPT_DIR/clawband.sh" "$HOOK_DIR/clawband.sh"
chmod +x "$HOOK_DIR/clawband.sh"
green "Installed: $HOOK_DIR/clawband.sh"

# ── Create config dir and example files ───────────────────────────────────────
mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/deny.patterns" ]; then
  cp "$SCRIPT_DIR/deny.patterns.example" "$CONFIG_DIR/deny.patterns"
  green "Created: $CONFIG_DIR/deny.patterns (from example — edit to customise)"
else
  yellow "Skipped: $CONFIG_DIR/deny.patterns already exists"
fi

if [ ! -f "$CONFIG_DIR/ask.patterns" ]; then
  cp "$SCRIPT_DIR/ask.patterns.example" "$CONFIG_DIR/ask.patterns"
  green "Created: $CONFIG_DIR/ask.patterns (from example — edit to customise)"
else
  yellow "Skipped: $CONFIG_DIR/ask.patterns already exists"
fi

if [ ! -f "$CONFIG_DIR/allow.patterns" ]; then
  cat > "$CONFIG_DIR/allow.patterns" << 'EOF'
# allow.patterns — patterns that override deny/ask blocks
# One pattern per line. Case-insensitive substring match.
# Lines starting with # and blank lines are ignored.
#
# Example: allow a specific git reset command
# git reset --hard HEAD
EOF
  green "Created: $CONFIG_DIR/allow.patterns"
fi

# ── Wire up settings.json ─────────────────────────────────────────────────────
HOOK_ENTRY='{"matcher":"Bash","hooks":[{"type":"command","command":"~/.claude/hooks/clawband.sh"}]}'

if [ ! -f "$SETTINGS" ]; then
  # No settings file — create minimal one
  echo '{"hooks":{"PreToolUse":[]}}' > "$SETTINGS"
fi

# Check if already registered
if grep -q "clawband.sh" "$SETTINGS" 2>/dev/null; then
  yellow "Already registered in $SETTINGS — skipping"
else
  # Use jq to prepend to PreToolUse array (or create it)
  UPDATED=$(jq --argjson entry "$HOOK_ENTRY" '
    .hooks.PreToolUse = ([$entry] + (.hooks.PreToolUse // []))
  ' "$SETTINGS")
  echo "$UPDATED" > "$SETTINGS"
  green "Registered hook in $SETTINGS"
fi

echo ""
green "Done. Run /hooks in Claude Code (or restart) to activate clawband."
echo ""
echo "  Config dir:  $CONFIG_DIR"
echo "    deny.patterns   — always block"
echo "    ask.patterns    — always prompt"
echo "    allow.patterns  — override a block"
echo ""
echo "  Options (set in clawband.sh or environment):"
echo "    CLAWBAND_LOG=1    log blocks/prompts to ~/.clawband.log"
echo "    CLAWBAND_SKIP=1   bypass all checks (trusted scripts)"
echo "    RTK_ENABLED=1     strip rtk prefix before matching"
