# clawband

Rust PreToolUse hook for Claude Code and other AI coding agents. Guards against destructive shell commands via tiered deny/ask/allow pattern matching.

## Build

```bash
cargo build --release          # dev build
cargo test                     # run all tests (unit + e2e, ~5-10s)
cargo fmt --check              # format check
cargo clippy --all-targets -- -D warnings   # lint
```

## Install (after build)

```bash
cargo build --release && ~/.cargo/bin/clawband install
```

## Architecture

- Single binary (`src/main.rs`) — minimal runtime dependencies: `regex` and `serde_json` for the core engine, plus `sha2` (deliberate exception, added in v3.16.0) for collision-resistant SHA-256 integrity hashing of project `allow.patterns` trust records — a security boundary that should not be hand-rolled
- `builtin_deny()` / `builtin_ask()` — built-in pattern tiers
- `check_command()` — main evaluation pipeline: compound-split → deny → ask → echo-scan → write-then-exec → fetch-then-exec → subshell
- `Pattern::from_user()` — loads user patterns from `~/.clawband/{deny,ask,allow}.patterns` and `.clawband/` project dirs
- `emit_decision()` — routes output per mode (Claude, Codex, Gemini, Hermes, Openclaw, Opencode)
- Version bumps: `Cargo.toml` version field (Cargo.lock updates automatically via `cargo update -p clawband`)

## Testing

All pattern changes must include:
1. Unit tests in `src/main.rs` inside `#[cfg(test)] mod tests`
2. E2e tests in `tests/cli.rs` using the `run()` / `bash()` / `decision()` helpers

Run these in order before committing:
```bash
cargo fmt              # auto-format (NOT --check — actually apply it)
cargo test             # all tests must pass
cargo clippy --all-targets -- -D warnings  # no warnings
```

## Commit & PR conventions

- Branch: `feat/<slug>` for features, `fix/<slug>` for fixes
- Commit message: `feat:` or `fix:` prefix, version in parentheses e.g. `(v2.34.0)`
- **Always open a PR** — never push directly to master, even for trivial changes
- Tag releases after the user merges: `git tag vX.Y.Z && git push origin vX.Y.Z`

## Codex second-opinion reviews

Every open PR here also gets an independent review from a Codex CLI session (`codex-clawband` tmux, runs under James's ChatGPT plan) — a cron poller (`~/scripts/codex-pr-review.sh`, every 10 min) picks up new/updated PRs automatically. Don't wait on that poll cycle when you're the one who just acted:

- **After pushing a fix commit that replies to a Codex review comment**, nudge it immediately instead of waiting for the next poll cycle:
  `bash ~/scripts/notify-codex.sh clawband "PR #<N> has a new commit/reply addressing your review (commit <sha>) — please take another look when ready."`
- **If Codex hasn't replied after a full round of `/backlog` (i.e. you're back here for the next tick and the PR still has no new Codex comment since your reply)**, nudge again once before moving on — don't nudge repeatedly in a loop.
- Codex's review is a second opinion from a differently-trained model, not a duplicate of DeepSource/Greptile — treat disagreements on their merits, the way you would a human reviewer's comment. It signs its comments `— Codex (gpt-5.6-terra), automated second opinion`.

## Signing PR descriptions and comments

Sign every PR description and every PR comment you post (replies to Codex, DeepSource, Greptile, or James) with:

`*— Claude (Sonnet 5), clawband backlog automation*`

as the last line, separated by a blank line (and a `---` divider if the body already ends with other content). This mirrors the Codex second-opinion signature (`— Codex (gpt-5.6-terra), automated second opinion`) so it's always clear which comments are automated vs. James's own. Older PRs used the default "🤖 Generated with Claude Code" footer or no signature at all depending on which path created them (interactive vs. `/backlog`) — use the line above going forward instead, consistently, regardless of path.

## Backlog pipeline — cadence

Run one tick at a time: wait for the previous PR to be merged before running `/backlog` again. Most backlog items touch the same files (`src/main.rs`, `Cargo.toml`, `tests/cli.rs`) so concurrent open PRs will conflict. There is no automation to prevent this — it relies on the human running `/backlog` manually after each merge.

## Backlog pipeline (releaser override)

When the backlog pipeline runs a releaser agent for this project:
- **Do NOT `git push` directly to master**
- Instead, push the branch and open a PR: `git push -u origin <branch> && gh pr create --title "..." --body-file /tmp/pr-body.md`
- Do NOT run the deploy command (`cargo build --release && clawband install`) — that runs after the user merges
- Mark the release step as SUCCESS once the PR is open
- After opening the PR, run `unset GITHUB_TOKEN && gh pr checks --watch --repo jamessoubry/clawband` to verify CI passes; if checks fail, fix them before declaring SUCCESS
