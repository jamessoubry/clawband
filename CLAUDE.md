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

- Single binary (`src/main.rs`) — no runtime dependencies beyond `regex` and `serde_json`
- `builtin_deny()` / `builtin_ask()` — built-in pattern tiers
- `check_command()` — main evaluation pipeline: compound-split → deny → ask → echo-scan → write-then-exec → fetch-then-exec → subshell
- `Pattern::from_user()` — loads user patterns from `~/.clawband/{deny,ask,allow}.patterns` and `.clawband/` project dirs
- `emit_decision()` — routes output per mode (Claude, Codex, Gemini, Hermes, Openclaw, Opencode)
- Version bumps: `Cargo.toml` version field (Cargo.lock updates automatically via `cargo update -p clawband`)

## Testing

All pattern changes must include:
1. Unit tests in `src/main.rs` inside `#[cfg(test)] mod tests`
2. E2e tests in `tests/cli.rs` using the `run()` / `bash()` / `decision()` helpers

Run `cargo test` to verify — all tests must pass before committing.

## Commit & PR conventions

- Branch: `feat/<slug>` for features, `fix/<slug>` for fixes
- Commit message: `feat:` or `fix:` prefix, version in parentheses e.g. `(v2.34.0)`
- **Always open a PR** — never push directly to master, even for trivial changes
- Tag releases after the user merges: `git tag vX.Y.Z && git push origin vX.Y.Z`

## Backlog pipeline — cadence

Run one tick at a time: wait for the previous PR to be merged before running `/backlog` again. Most backlog items touch the same files (`src/main.rs`, `Cargo.toml`, `tests/cli.rs`) so concurrent open PRs will conflict. There is no automation to prevent this — it relies on the human running `/backlog` manually after each merge.

## Backlog pipeline — tag at tick start

At the very start of each tick (before creating a new branch), check if master's current version already has a release tag. If not, create and push it so release CI fires:

```bash
cd /home/ubuntu/clawband
git checkout master && git pull origin master
CURRENT_VERSION=$(grep '^version' Cargo.toml | head -1 | grep -oP '[\d.]+')
if ! git tag | grep -q "^v${CURRENT_VERSION}$"; then
  git tag "v${CURRENT_VERSION}" && git push origin "v${CURRENT_VERSION}"
  echo "Tagged v${CURRENT_VERSION}"
else
  echo "v${CURRENT_VERSION} already tagged — skipping"
fi
```

This handles the one-tick lag: user merges PR → runs `/backlog` → orchestrator tags the merged version → branches for the next issue.

## Backlog pipeline (releaser override)

When the backlog pipeline runs a releaser agent for this project:
- **Do NOT `git push` directly to master**
- Instead, push the branch and open a PR: `git push -u origin <branch> && gh pr create --title "..." --body-file /tmp/pr-body.md`
- Do NOT run the deploy command (`cargo build --release && clawband install`) — that runs after the user merges
- Mark the release step as SUCCESS once the PR is open
