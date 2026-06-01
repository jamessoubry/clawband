#!/bin/bash
# install.sh — build and install clawband
set -euo pipefail

HOOK_DIR="$HOME/.claude/hooks"
SETTINGS="$HOME/.claude/settings.json"
CONFIG_DIR="$HOME/.clawband"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

green()  { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red()    { printf '\033[31m%s\033[0m\n' "$1"; }

# ── Dependencies ──────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  red "Error: jq is required."
  echo "  macOS:  brew install jq"
  echo "  Ubuntu: sudo apt install jq"
  exit 1
fi

if ! command -v cargo &>/dev/null; then
  red "Error: Rust toolchain not found."
  echo "  Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "  Then re-run this script."
  exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────────────
echo "Building clawband..."
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml" --quiet
green "Build complete"

# ── Install binary ────────────────────────────────────────────────────────────
mkdir -p "$HOOK_DIR"
cp "$SCRIPT_DIR/target/release/clawband" "$HOOK_DIR/clawband"
chmod +x "$HOOK_DIR/clawband"
green "Installed: $HOOK_DIR/clawband"

# ── Create config dir ─────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"

for f in deny ask; do
  if [ ! -f "$CONFIG_DIR/$f.patterns" ]; then
    cp "$SCRIPT_DIR/$f.patterns.example" "$CONFIG_DIR/$f.patterns"
    green "Created: $CONFIG_DIR/$f.patterns"
  else
    yellow "Skipped: $CONFIG_DIR/$f.patterns already exists"
  fi
done

if [ ! -f "$CONFIG_DIR/allow.patterns" ]; then
  cat > "$CONFIG_DIR/allow.patterns" << 'EOF'
# allow.patterns — patterns that override deny/ask blocks
# One pattern per line. Case-insensitive regex. Lines starting with # ignored.
#
# Example: allow git reset --hard only to HEAD
# git reset --hard HEAD$
EOF
  green "Created: $CONFIG_DIR/allow.patterns"
fi

# ── Wire up settings.json ─────────────────────────────────────────────────────
HOOK_ENTRY='{"matcher":"Bash","hooks":[{"type":"command","command":"~/.claude/hooks/clawband"}]}'

if [ ! -f "$SETTINGS" ]; then
  echo '{"hooks":{"PreToolUse":[]}}' > "$SETTINGS"
fi

if grep -q '"clawband"' "$SETTINGS" 2>/dev/null; then
  yellow "Already registered in $SETTINGS — skipping"
else
  UPDATED=$(jq --argjson entry "$HOOK_ENTRY" '
    .hooks.PreToolUse = ([$entry] + (.hooks.PreToolUse // []))
  ' "$SETTINGS")
  echo "$UPDATED" > "$SETTINGS"
  green "Registered hook in $SETTINGS"
fi

echo ""
green "Done. Run /hooks in Claude Code (or restart) to activate clawband."
echo ""
echo "  Config:  $CONFIG_DIR/{deny,ask,allow}.patterns"
echo "  Options: RTK_ENABLED=1   strip rtk prefix before matching"
echo "           CLAWBAND_LOG=1  append blocks/prompts to ~/.clawband.log"
echo "           CLAWBAND_SKIP=1 bypass all checks (trusted scripts)"
