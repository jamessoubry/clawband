// clawband plugin for OpenCode (sst/opencode)
//
// Bridges the clawband guardrail binary into OpenCode's tool.execute.before
// hook.  For every bash tool call, this plugin spawns
// `clawband --mode opencode`, feeds the tool input JSON to stdin, and maps
// the decision:
//
//   {"decision":"block","reason":"..."} → throw new Error(reason)  (blocks the call)
//   {} or empty stdout                  → return (allow)
//
// The plugin is fail-open: if the binary is missing, crashes, or times out,
// it logs a one-line warning to console.error and returns normally so a broken
// guardrail never bricks OpenCode.
//
// Ask-tier commands fold via ask_fallback (default: allow) — OpenCode has no
// native approval in tool.execute.before.  Set ask_fallback = deny in
// ~/.clawband/config to hard-block ask-tier commands instead.
//
// Runtime: Bun (used by OpenCode).  Only node: built-in modules are imported.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const ClawbandPlugin = async () => {
  return {
    "tool.execute.before": async (input, output) => {
      // ── 1. Gate: only act on shell tools with a command string ─────────────
      const toolName = input?.tool ?? "";
      const isBashTool =
        toolName === "bash" ||
        toolName === "shell" ||
        toolName === "sh";
      if (!isBashTool) {
        return;
      }

      const command = output?.args?.command;
      if (typeof command !== "string" || command.length === 0) {
        return;
      }

      // ── 2. Locate the clawband binary ───────────────────────────────────────
      // Priority: CLAWBAND_BIN env → clawband on PATH → ~/.claude/hooks/clawband
      let binary;
      const envBin = process.env["CLAWBAND_BIN"];
      if (envBin) {
        binary = envBin;
      } else {
        // Probe PATH via `which` so we don't need to parse PATH manually.
        const whichResult = spawnSync("which", ["clawband"], {
          encoding: "utf8",
          timeout: 2000,
        });
        if (whichResult.status === 0 && whichResult.stdout.trim().length > 0) {
          binary = "clawband";
        } else {
          // Final fallback: well-known Claude Code hooks install location.
          binary = join(homedir(), ".claude", "hooks", "clawband");
        }
      }

      // ── 3. Fail-open guard: non-PATH binary must exist ─────────────────────
      if (binary !== "clawband" && !existsSync(binary)) {
        console.error(
          `[clawband] binary not found at ${binary} — guardrail inactive. ` +
            `Install clawband or set CLAWBAND_BIN to its path.`
        );
        return;
      }

      // ── 4. Invoke clawband --mode opencode ──────────────────────────────────
      const payload = JSON.stringify({
        tool_name: "Bash",
        tool_input: { command },
      });

      let result;
      try {
        result = spawnSync(binary, ["--mode", "opencode"], {
          input: payload,
          encoding: "utf8",
          timeout: 5000,
        });
      } catch (err) {
        // Spawn error (ENOENT, permission denied, etc.) — fail open.
        console.error(`[clawband] spawn error: ${err}`);
        return;
      }

      // ── 5. Fail-open on infra errors ────────────────────────────────────────
      if (result.error) {
        console.error(`[clawband] execution error: ${result.error}`);
        return;
      }

      const stdout = (result.stdout ?? "").trim();

      // Empty stdout = pass-through (no pattern matched).
      if (!stdout) {
        return;
      }

      // ── 6. Parse and map the decision ───────────────────────────────────────
      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch {
        // Unparseable output — fail open with a warning.
        console.error(`[clawband] unexpected output (not JSON): ${stdout}`);
        return;
      }

      const { decision, reason } = parsed;

      if (decision === "block") {
        // Hard deny — throw to block the tool call.
        throw new Error(reason ?? "[CLAWBAND] blocked");
      }

      // Allow ({}) or any unrecognised decision → return normally (allow).
      if (decision !== undefined && decision !== "allow") {
        console.error(`[clawband] unknown decision value: ${decision}`);
      }
    },
  };
};
