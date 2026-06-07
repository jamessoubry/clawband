# Contributing to clawband

Thanks for helping make Claude Code safer. The most valuable contributions are
**new patterns** — destructive commands clawband should block or prompt on — and
**false-positive reports** — safe commands it wrongly stops.

## Found a dangerous command clawband misses?

Two ways to contribute it:

1. **Open an issue** — use the [New pattern](.github/ISSUE_TEMPLATE/new-pattern.md)
   template. Describe the command, whether it should `deny` or `ask`, and why it's
   dangerous. This is the lowest-effort path; no Rust required.
2. **Open a PR** — add the pattern yourself (recipe below).

## Adding a pattern (PR recipe)

Patterns live in `src/main.rs`:

- `builtin_deny()` — hard-blocked, no prompt. For **catastrophic, irreversible**
  commands (filesystem destruction, infra teardown, pipe-to-interpreter).
- `builtin_ask()` — prompts for approval. For **risky-but-legitimate** commands
  where intent is ambiguous (`git reset --hard`, `docker rm -f`).

Each entry is `(label, regex)`. The regex is compiled case-insensitively.

1. Add your `(label, pattern)` tuple to the right list, with a comment explaining
   the risk.
2. Add at least one test in the `tests` module: a case that should match, and —
   importantly — a nearby **safe** case that should *not* match (guards against
   false positives).
3. Run the checks (see below). All must pass.
4. Bump the `version` in `Cargo.toml` (patch for a single pattern, minor for a set).
5. Open the PR with a one-line rationale.

### Pattern guidelines

- **Prefer precision over breadth.** A pattern that also blocks common safe usage
  will get disabled by users and helps no one. Anchor with `\b`, match flags
  explicitly, and add a passing test for the safe lookalike.
- **deny is for the unrecoverable.** If a careful user might legitimately want to
  run it, it belongs in `ask`, not `deny`.
- **Remember compound splitting.** Commands are split on `&&`, `||`, `;` and each
  segment is checked independently — your pattern only needs to match one segment.

## Reporting a false positive

Use the [False positive](.github/ISSUE_TEMPLATE/false-positive.md) template. Include
the exact command, the decision you got, and (if you found one) the
`allow.patterns` regex that works around it.

## Development

```sh
cargo build
cargo test                  # unit tests
cargo fmt --check           # formatting (CI enforces this)
cargo clippy -- -D warnings # lints (CI enforces this)
```

CI runs `fmt --check`, `clippy -D warnings`, and `cargo test` on every PR — run
all three locally before pushing to avoid a round-trip.

To try your build against Claude Code locally:

```sh
cargo build --release
cp target/release/clawband ~/.claude/hooks/clawband
clawband verify
```

## Releasing (maintainers)

Tagging `vX.Y.Z` triggers `.github/workflows/release.yml`, which builds the
binaries, publishes a GitHub release, and bumps the Homebrew tap. Keep
`Cargo.toml`'s version in sync with the tag.

## Licence

By contributing you agree your work is licensed under the project's MIT licence.
