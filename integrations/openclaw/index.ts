// @ts-nocheck
// ts-nocheck is required because the OpenClaw plugin SDK is only available at
// install time inside the OpenClaw runtime — it is not installed in this repo.
// The code below is valid TypeScript and will compile cleanly inside OpenClaw.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

export default definePluginEntry({
  id: "clawband",
  name: "clawband",
  description:
    "Blocks destructive shell commands via the clawband guardrail before they execute",

  register(api) {
    api.on("before_tool_call", async (event) => {
      // ── 1. Extract a command string from event.params ─────────────────────
      // params is Record<string, unknown>; try well-known keys defensively.
      const params = event.params ?? {};

      let command: string | undefined;

      // Try explicit well-known keys first.
      for (const key of ["command", "cmd", "script", "input"]) {
        const val = params[key];
        if (typeof val === "string") {
          command = val;
          break;
        }
        // Some agents pass the command as a string array (e.g. ["bash", "-c", "..."]).
        if (Array.isArray(val) && val.every((v) => typeof v === "string")) {
          command = (val as string[]).join(" ");
          break;
        }
      }

      // Fallback: if exactly one string-valued field exists, use it.
      if (command === undefined) {
        const stringFields = Object.entries(params).filter(
          ([, v]) => typeof v === "string",
        );
        if (stringFields.length === 1) {
          command = stringFields[0][1] as string;
        }
      }

      // No recognisable command string — not a shell tool; pass through.
      if (!command) {
        return {};
      }

      // ── 2. Locate the clawband binary ─────────────────────────────────────
      // Priority: CLAWBAND_BIN env var → clawband on PATH → ~/.claude/hooks/clawband
      let binary: string;
      const envBin = process.env["CLAWBAND_BIN"];
      if (envBin) {
        binary = envBin;
      } else {
        // Check PATH candidates: use `which`-style probe via spawnSync so we
        // don't need to import `which` or shell out unsafely.
        const whichResult = spawnSync("which", ["clawband"], {
          encoding: "utf8",
          timeout: 2000,
        });
        const onPath =
          whichResult.status === 0 && whichResult.stdout.trim().length > 0;
        if (onPath) {
          binary = "clawband";
        } else {
          // Final fallback: the well-known install location for Claude Code hooks.
          binary = join(homedir(), ".claude", "hooks", "clawband");
        }
      }

      // ── 3. Fail-open guard: binary must exist (for non-PATH form) ─────────
      if (binary !== "clawband" && !existsSync(binary)) {
        console.error(
          `[clawband] binary not found at ${binary} — guardrail inactive. ` +
            `Install clawband or set CLAWBAND_BIN to its path.`,
        );
        return {};
      }

      // ── 4. Invoke clawband --mode openclaw ────────────────────────────────
      const payload = JSON.stringify({
        tool_name: event.toolName,
        tool_input: { command },
      });

      let result;
      try {
        result = spawnSync(binary, ["--mode", "openclaw"], {
          input: payload,
          encoding: "utf8",
          timeout: 5000,
        });
      } catch (err) {
        // Spawn error (ENOENT, permission denied, etc.) — fail open.
        console.error(`[clawband] spawn error: ${err}`);
        return {};
      }

      // ── 5. Fail-open on infra errors ──────────────────────────────────────
      // A missing/crashed binary must never brick the agent. A *real* block
      // decision (non-zero exit with parseable JSON) still fails CLOSED — that
      // is the intended behaviour and is handled in the parse step below.
      if (result.error) {
        console.error(`[clawband] execution error: ${result.error}`);
        return {};
      }

      const stdout = (result.stdout ?? "").trim();

      // Empty stdout = pass-through (no pattern matched).
      if (!stdout) {
        return {};
      }

      // ── 6. Parse and map the decision ─────────────────────────────────────
      let parsed: { decision?: string; reason?: string };
      try {
        parsed = JSON.parse(stdout);
      } catch {
        // Unparseable output from a real run is unexpected — fail open with a
        // warning so the agent is not silently bricked.
        console.error(`[clawband] unexpected output (not JSON): ${stdout}`);
        return {};
      }

      const { decision, reason } = parsed;

      if (decision === "block") {
        // Hard deny — veto the tool call outright.
        return { block: true, blockReason: reason ?? "[CLAWBAND] blocked" };
      }

      if (decision === "ask") {
        // Native approval prompt — pause and ask the user.
        return { requireApproval: { description: reason } };
      }

      if (decision === "allow") {
        // Explicit allow — let the tool call proceed.
        return {};
      }

      // Unknown decision value — fail open.
      console.error(`[clawband] unknown decision value: ${decision}`);
      return {};
    });
  },
});
