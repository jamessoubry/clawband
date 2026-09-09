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

## Logging (`~/.clawband.log`)

- Opt-in only (`CLAWBAND_LOG=1` or the `clawband log --enable` marker) — off by default.
- Created via a plain `OpenOptions::append().create()` with no explicit mode set, so it inherits the process umask (typically `0644`/`0664` — group/world **readable** on most systems). It is not created `0600`; treat it as a regular file, not a secrets vault.
- Retention: none. `maybe_rotate_log()` renames the live file to a single `.clawband.log.1` backup once it exceeds the size cap — there is no pruning, deletion, or bounded history beyond that one backup.
- Since v3.17.1, `log_action()` runs `redact_secrets()` on the command preview before truncating it, stripping common secret-bearing forms (`Authorization:` headers, `Bearer <token>`, `AWS_SECRET_ACCESS_KEY=`/`AWS_SESSION_TOKEN=`, `password=`/`passwd=`/`pwd=`, `token=`, `api_key=`/`apikey=`/`api-key=`, `secret=`) to `***REDACTED***`.
- **This is best-effort pattern matching, not an exhaustive secret scanner** — same defense-in-depth spirit as the skip-flag bypass detection elsewhere in this project. On a shared machine, don't assume the log is safe from a determined reader: an unrecognized secret format, a custom env var name, or a base64/encoded blob will pass through untouched.

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
