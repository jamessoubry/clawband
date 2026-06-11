# clawband — OpenClaw plugin

This directory contains the OpenClaw plugin shim that bridges the
[clawband](https://github.com/jamessoubry/clawband) guardrail binary into
OpenClaw's `before_tool_call` hook system.

## What it does

For every tool call OpenClaw makes, the plugin:

1. Extracts the command string from `event.params`.
2. Spawns `clawband --mode openclaw`, writing the tool input JSON to stdin.
3. Maps clawband's JSON decision to the OpenClaw `BeforeToolCallResult`:

   | clawband output | Plugin returns |
   |-----------------|----------------|
   | `{"decision":"block","reason":"..."}` | `{ block: true, blockReason: "..." }` |
   | `{"decision":"ask","reason":"..."}` | `{ requireApproval: { description: "..." } }` |
   | `{"decision":"allow"}` or empty stdout | `{}` (pass through) |

The binary is fail-open: if clawband is missing, crashes, or times out, the
plugin logs a one-line warning to `console.error` and returns `{}` so a broken
guardrail never bricks the agent.

## The ask tier — OpenClaw native approval

OpenClaw is the **only non-Claude agent** where clawband's ask-tier maps to a
real approval prompt rather than being folded to allow/deny.

When clawband emits `{"decision":"ask",...}`, the plugin returns
`{ requireApproval: { description: "..." } }`, which pauses the run and asks
the user before the command executes. The `ask_fallback` config key has **no
effect** in Openclaw mode — ask always stays ask.

## Prerequisites

- **clawband binary** installed and accessible. Install via:
  ```sh
  brew install jamessoubry/clawband/clawband
  # or:
  bash install.sh
  ```
  The binary must be on `PATH` or located at `~/.claude/hooks/clawband`.

- **Node 22.19+** (required by OpenClaw).
- **OpenClaw** with plugin support (pluginApi >= 2026.3.24).

## Installation

```sh
# From the clawband repo root:
openclaw plugins install integrations/openclaw/

# Once published to ClawHub:
openclaw plugins install clawband
```

OpenClaw compiles the TypeScript entry point at install time — no `npm install`
or build step is needed in this directory.

## CLAWBAND_BIN override

If the clawband binary is not on PATH and not at `~/.claude/hooks/clawband`,
set the `CLAWBAND_BIN` environment variable to its absolute path before
starting OpenClaw:

```sh
export CLAWBAND_BIN=/opt/homebrew/bin/clawband
```
