# clawband — OpenCode plugin

This directory contains the OpenCode plugin that bridges the
[clawband](https://github.com/jamessoubry/clawband) guardrail binary into
OpenCode's `tool.execute.before` hook system.

## What it does

For every bash tool call OpenCode makes, the plugin:

1. Extracts the command string from `output.args.command`.
2. Spawns `clawband --mode opencode`, writing the tool input JSON to stdin.
3. Maps clawband's JSON decision:

   | clawband output | Plugin action |
   |-----------------|---------------|
   | `{"decision":"block","reason":"..."}` | `throw new Error(reason)` (blocks the call) |
   | `{}` or empty stdout | return normally (allow) |

The plugin is fail-open: if clawband is missing, crashes, or times out, it
logs a one-line warning to `console.error` and returns normally so a broken
guardrail never bricks OpenCode.

## The ask tier — folds via ask_fallback

OpenCode's `tool.execute.before` hook has no native approval path. When the
engine decides "ask", clawband applies `ask_fallback`:

- `ask_fallback = allow` (default) — the command runs. Hard deny patterns
  still block.
- `ask_fallback = deny` — ask-tier is treated as a hard block.

Set it in `~/.clawband/config`:

```
ask_fallback = deny
```

This differs from OpenClaw, which is the only non-Claude agent with a native
approval prompt. OpenCode always folds ask to allow or deny.

## Prerequisites

- **clawband binary** installed and accessible. Install via:
  ```sh
  brew install jamessoubry/clawband/clawband
  # or:
  bash install.sh
  ```
  The binary must be on `PATH` or located at `~/.claude/hooks/clawband`.

- **OpenCode** (sst/opencode) with Bun runtime.

## Installation

Copy the plugin file to OpenCode's global plugin directory:

```sh
# Global (all projects):
cp integrations/opencode/clawband.js ~/.config/opencode/plugin/

# Project-local:
cp integrations/opencode/clawband.js .opencode/plugin/
```

Or register it in your project's `opencode.json`:

```json
{
  "plugin": ["<absolute-path-to-clawband>/integrations/opencode/clawband.js"]
}
```

OpenCode loads plugin files automatically at startup — no build step is needed.

## CLAWBAND_BIN override

If the clawband binary is not on PATH and not at `~/.claude/hooks/clawband`,
set the `CLAWBAND_BIN` environment variable to its absolute path:

```sh
export CLAWBAND_BIN=/opt/homebrew/bin/clawband
```

## Known limitation

OpenCode plugin hooks do not intercept subagent tool calls
([sst/opencode#5894](https://github.com/sst/opencode/issues/5894)). This is
an upstream limitation — commands issued by subagents will not be checked by
clawband until that issue is resolved.
