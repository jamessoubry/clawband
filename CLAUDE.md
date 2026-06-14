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

## Harness output semantics

Each harness interprets clawband's stdout differently. This matters for error paths and for choosing the right decision tier.

| Harness | Empty stdout | `ask` decision | `deny` decision | bypassPermissions/YOLO risk |
|---------|-------------|----------------|-----------------|---------------------------|
| **Claude** | Claude applies own policy (not guaranteed allow) | prompts user | always blocks | **`ask` = auto-approve in YOLO** |
| **Codex** | allow | `ask_fallback` → deny (default) or allow | always blocks | None — no bypass mode |
| **Gemini** | allow | folded → block | always blocks | None known |
| **Hermes** | allow (`{}` = pass-through) | `ask_fallback` → deny or allow | always blocks | None known |
| **OpenCode** | allow (`{}` = pass-through) | `ask_fallback` → deny or allow | always blocks | None known |
| **Openclaw** | allow | approval dialog shown | always blocks | **Likely bypassed in YOLO**: Openclaw is a CC plugin; `bypassPermissions` may auto-approve `requireApproval` |

**Critical rule:** On any error path where the command is unknown, emit `"deny"` — never `"ask"`. For Claude+YOLO and likely Openclaw+YOLO, `ask` is auto-approved (functionally identical to allow). Only `deny` is universally fail-closed across all harnesses.

The `ask_fallback` system (Codex/Hermes/OpenCode) converts `ask` to `deny` or `allow` at output time because those harnesses have no native approval path. Default is `deny`.

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

## Backlog pipeline — cadence

Run one tick at a time: wait for the previous PR to be merged before running `/backlog` again. Most backlog items touch the same files (`src/main.rs`, `Cargo.toml`, `tests/cli.rs`) so concurrent open PRs will conflict. There is no automation to prevent this — it relies on the human running `/backlog` manually after each merge.

## Backlog pipeline (releaser override)

When the backlog pipeline runs a releaser agent for this project:
- **Do NOT `git push` directly to master**
- Instead, push the branch and open a PR: `git push -u origin <branch> && gh pr create --title "..." --body-file /tmp/pr-body.md`
- Do NOT run the deploy command (`cargo build --release && clawband install`) — that runs after the user merges
- Mark the release step as SUCCESS once the PR is open
- After opening the PR, run `unset GITHUB_TOKEN && gh pr checks --watch --repo jamessoubry/clawband` to verify CI passes; if checks fail, fix them before declaring SUCCESS
