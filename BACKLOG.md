# Backlog

Deferred work — not blocking, captured so it isn't lost. Open an issue/PR when picking one up.

## 1. Publish the OpenClaw & OpenCode plugins to ClawHub / npm

**What:** The agent integrations ship as plugin source in-repo today:
- `integrations/openclaw/` — OpenClaw `before_tool_call` plugin (TypeScript)
- `integrations/opencode/` — OpenCode `tool.execute.before` plugin (JavaScript)

Both currently require a manual install (copy the file into the agent's plugin dir, or register a path in its config). Publishing them as packages would enable one-line installs:
- OpenClaw: `openclaw plugins install clawhub:<org>/clawband`
- OpenCode: add the package name to `opencode.json` `"plugin": [...]`

**Why deferred:** Needs a publishing account + a chosen package name (npm org and/or ClawHub). That's an owner decision, not a code one.

**Notes / when picking up:**
- Both plugins shell out to the `clawband` binary — the package is just the bridge; the binary is still installed separately (brew / `install.sh`). Document that prerequisite in the package README.
- Pick a consistent name (e.g. `clawband-openclaw`, `clawband-opencode`, or scoped `@clawband/*`).
- Add a `clawhub package publish` / `npm publish` step; consider wiring it into a release workflow so plugin versions track the binary.
- The plugin source is the source of truth — publish *from* `integrations/*`, don't fork.

## 2. Windows-native support

**What:** A clawband binary + integration that works on native Windows (not just WSL).

**Why deferred — it's real work, not a flag:**
- **Shell semantics** — every deny/ask pattern targets `bash`/`sh` syntax (`rm -rf`, `| bash`, `&&`/`;` splitting, heredocs). Native Windows agents issue PowerShell/cmd, so the patterns wouldn't match what actually runs. A separate PowerShell/cmd pattern set would be needed.
- **Path / FS assumptions** — `~/.clawband`, path canonicalization, the `/dev/stdin` non-regular-file checks, and symlink resolution all assume POSIX.

**Current workaround (good enough for most):** Claude Code / Codex / Gemini on Windows are overwhelmingly run under **WSL2**, where the existing `clawband-linux-x86_64` (or `-arm64`) binary works unchanged. So Windows users are effectively covered today via WSL.

**When picking up:** scope as its own track — Windows target build, PowerShell/cmd pattern tier, Windows path handling — or formally declare WSL the supported path and document it. Likely warrants a tracking issue first to gauge demand before investing.
