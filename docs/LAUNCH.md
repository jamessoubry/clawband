# Launch post drafts

Reference copy for posting clawband to HN / Reddit / social. Not part of the site.

---

## Show HN

**Title:** Show HN: Clawband – run Claude Code in YOLO mode without getting nuked

**Body:**

I kept hitting the same wall with Claude Code: either I approve every single
shell command (approval fatigue, dozens of clicks an hour) or I turn approvals
off (`--dangerously-skip-permissions`) and pray it never hallucinates an
`rm -rf` or eats a prompt injection.

Claude Code has a built-in deny list, but it matches the whole command as a
glob — so it never looks inside a compound command. `echo hi && rm -rf /` sails
straight through. That's a false sense of security.

Clawband is a `PreToolUse` hook (single Rust binary, no runtime deps) that
actually parses the command before it runs:

- splits on `&&`, `||`, `;` and checks each segment
- scans script files before they execute (`bash run.sh`, `./run.sh`, `bash < x`)
- catches write-then-execute (`echo … > run.sh && bash run.sh`)
- looks inside `$()` / backticks instead of blanket-prompting
- 70+ built-in patterns: filesystem destruction, infra teardown, pipe-to-shell,
  git force-push, AWS/k8s deletes, etc.

Three verdicts: **deny** (catastrophic, hard-blocked), **ask** (risky, prompt),
**pass** (silent). You can run Claude Code fully autonomous and let clawband be
the seatbelt, or keep approvals on and use it to kill approval fatigue with an
allow-list.

It can't bypass itself, either: `CLAWBAND_SKIP=1 rm -rf /` is still blocked,
because the skip is read from the hook's environment, not the command string.

Install: `brew install jamessoubry/clawband/clawband && clawband install`

Repo: https://github.com/jamessoubry/clawband
Site: https://jamessoubry.github.io/clawband

Happy to hear what dangerous commands I'm still missing — pattern PRs welcome.

---

## Reddit (r/ClaudeAI, r/programming)

**Title:** I made a hook that lets you run Claude Code in YOLO mode safely

Same pain as everyone: Claude Code either nags you to approve every command, or
you skip permissions and hope it never runs something destructive. Its built-in
deny list is glob-based and misses `echo hi && rm -rf /`.

Clawband is a tiny Rust `PreToolUse` hook that parses commands properly — splits
compound commands, scans script files, inspects subshells, 70+ destructive
patterns, three tiers (deny / ask / pass). Run your agent autonomously with a
real backstop, or kill approval fatigue with an allow-list.

`brew install jamessoubry/clawband/clawband && clawband install`

https://github.com/jamessoubry/clawband

---

## One-liner (X / Bluesky)

Tired of approving every Claude Code command — but scared to go full YOLO?
clawband is a Rust PreToolUse hook that hard-blocks `rm -rf /` and 70+ other
destructive commands before they run, even inside `echo hi && rm -rf /`.
`brew install jamessoubry/clawband/clawband`
