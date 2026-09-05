#!/bin/bash
# install.sh — install clawband
# Options:
#   --post-hook   also register the PostToolUse hook for allow suggestions
set -euo pipefail

POST_HOOK=0
for arg in "$@"; do
  [[ "$arg" == "--post-hook" ]] && POST_HOOK=1
done

HOOK_DIR="$HOME/.claude/hooks"
SETTINGS="$HOME/.claude/settings.json"
CONFIG_DIR="$HOME/.clawband"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="jamessoubry/clawband"

green()  { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red()    { printf '\033[31m%s\033[0m\n' "$1"; }

# ── jq is always required (settings.json editing) ────────────────────────────
if ! command -v jq &>/dev/null; then
  red "Error: jq is required."
  echo "  macOS:  brew install jq"
  echo "  Ubuntu: sudo apt install jq"
  exit 1
fi

mkdir -p "$HOOK_DIR"

# ── Try pre-built binary ──────────────────────────────────────────────────────
BINARY_INSTALLED=0
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS-$ARCH" in
  linux-x86_64)   ASSET="clawband-linux-x86_64" ;;
  linux-aarch64)  ASSET="clawband-linux-arm64" ;;
  linux-arm64)    ASSET="clawband-linux-arm64" ;;
  darwin-arm64)   ASSET="clawband-macos-arm64" ;;
  darwin-x86_64)  ASSET="clawband-macos-x86_64" ;;
  *)              ASSET="" ;;
esac

if [[ -n "$ASSET" ]]; then
  echo "Checking for pre-built binary..."
  LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
    | jq -r '.tag_name // empty' 2>/dev/null || true)
  if [[ -n "$LATEST" ]]; then
    URL="https://github.com/$REPO/releases/download/$LATEST/$ASSET"
    TMP_BIN="$(mktemp)"
    TMP_SHA="$(mktemp)"
    if curl -fsSL "$URL" -o "$TMP_BIN" 2>/dev/null \
        && curl -fsSL "${URL}.sha256" -o "$TMP_SHA" 2>/dev/null; then
      # Verify SHA256 checksum before installing
      EXPECTED="$(cat "$TMP_SHA")"
      ACTUAL="$(sha256sum "$TMP_BIN" | cut -d' ' -f1)"
      if [[ "$EXPECTED" != "$ACTUAL" ]]; then
        rm -f "$TMP_BIN" "$TMP_SHA"
        red "Error: SHA256 checksum mismatch — aborting installation."
        echo "  Expected: $EXPECTED"
        echo "  Got:      $ACTUAL"
        exit 1
      fi
      cp "$TMP_BIN" "$HOOK_DIR/clawband"
      rm -f "$TMP_BIN" "$TMP_SHA"
      chmod +x "$HOOK_DIR/clawband"
      green "Installed pre-built binary ($LATEST)"
      BINARY_INSTALLED=1
    else
      rm -f "$TMP_BIN" "$TMP_SHA"
      yellow "Pre-built binary not available for this platform — building from source"
    fi
  else
    yellow "No release found — building from source"
  fi
fi

# ── Build from source (fallback) ──────────────────────────────────────────────
if [[ "$BINARY_INSTALLED" == "0" ]]; then
  if ! command -v cargo &>/dev/null; then
    red "Error: no pre-built binary available and Rust toolchain not found."
    echo "  Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "  Then re-run this script."
    exit 1
  fi
  echo "Building from source..."
  cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml" --quiet
  cp "$SCRIPT_DIR/target/release/clawband" "$HOOK_DIR/clawband"
  chmod +x "$HOOK_DIR/clawband"
  green "Built and installed from source"
fi

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
  _tmp=$(mktemp "${SETTINGS}.XXXXXX")
  echo '{"hooks":{"PreToolUse":[]}}' > "$_tmp" && mv "$_tmp" "$SETTINGS"
fi

if jq -e '.hooks.PreToolUse[]?.hooks[]? | select(.command and (.command | contains("clawband")) and (.command | contains("icm") | not) and (.command | contains("sqz") | not))' "$SETTINGS" &>/dev/null; then
  yellow "Already registered in $SETTINGS — skipping"
else
  UPDATED=$(jq --argjson entry "$HOOK_ENTRY" '
    .hooks.PreToolUse = ([$entry] + (.hooks.PreToolUse // []))
  ' "$SETTINGS")
  _tmp=$(mktemp "${SETTINGS}.XXXXXX")
  echo "$UPDATED" > "$_tmp" && mv "$_tmp" "$SETTINGS"
  green "Registered hook in $SETTINGS"
fi

# ── Optional: PostToolUse hook ───────────────────────────────────────────────
if [[ "$POST_HOOK" == "1" ]]; then
  POST_ENTRY='{"matcher":"Bash","hooks":[{"type":"command","command":"~/.claude/hooks/clawband post"}]}'
  if grep -q '"clawband post"' "$SETTINGS" 2>/dev/null; then
    yellow "PostToolUse hook already registered — skipping"
  else
    UPDATED=$(jq --argjson entry "$POST_ENTRY" '
      .hooks.PostToolUse = ([$entry] + (.hooks.PostToolUse // []))
    ' "$SETTINGS")
    _tmp=$(mktemp "${SETTINGS}.XXXXXX")
    echo "$UPDATED" > "$_tmp" && mv "$_tmp" "$SETTINGS"
    green "PostToolUse hook registered — will suggest 'clawband allow' after approvals"
  fi
fi

# ── Install slash commands ────────────────────────────────────────────────────
CMD_DIR="$HOME/.claude/commands"
mkdir -p "$CMD_DIR"
cp "$SCRIPT_DIR/.claude/commands/allow.md" "$CMD_DIR/allow.md"
cp "$SCRIPT_DIR/.claude/commands/deny.md"  "$CMD_DIR/deny.md"
green "Installed: /allow and /deny slash commands → $CMD_DIR"

echo ""
green "Done. Run /hooks in Claude Code (or restart) to activate clawband."
echo ""
echo "  Config:  $CONFIG_DIR/{deny,ask,allow}.patterns"
echo "  CLI:     clawband allow '<pattern>'  add to allow list"
echo "           clawband deny  '<pattern>'  add to deny list"
echo "  Slash:   /allow <pattern>  /deny <pattern>"
echo "  Options: RTK_ENABLED=1   strip rtk prefix before matching"
echo "           CLAWBAND_LOG=1  append blocks/prompts to ~/.clawband.log"
echo "  Skip:    clawband skip enable   bypass all checks (see README)"
echo ""
echo "  Optional: bash install.sh --post-hook"
echo "            Registers a PostToolUse hook that suggests 'clawband allow'"
echo "            in the chat after you approve a prompted command."
