# Static Analysis Scanner Comparison

Testing DeepSource vs SonarQube Cloud on intentionally bad code across Rust, Java, and Python.

## Setup

- **Repo**: `trustonic-test/deepsource-test` (Bitbucket)
- **Base branch**: `clawband-base` (clawband master + pipeline config)
- **PR branch**: `clawband-pr` (clawband advisory feature + bad samples)
- **Pipeline**: Bitbucket Pipelines — SonarQube via `sonarsource/sonarcloud-scan:2.0.0` pipe; DeepSource via webhook
- **Java coverage**: JUnit 4 + JaCoCo, reported to DeepSource via CLI

---

## Results Summary

### Rust

| Finding | DeepSource | SonarQube |
|---------|-----------|-----------|
| High complexity functions | ✓ (2 flagged, threshold ~25) | ✓ (18 flagged, threshold 15) |
| `env::var` string literals | ✓ RS-W1015 | ✗ |
| Hardcoded `/tmp` paths | ✓ RS-S1003 (SECURITY) | ✗ |
| Trivial regex | ✓ RS-W1027 (PERFORMANCE) | ✗ |
| `unwrap_or` + function call | ✓ RS-W1031 (PERFORMANCE) | ✗ |
| Manual `split_once` | ✓ RS-W1066 | ✗ |
| `map` + `unwrap_or` chain | ✓ RS-W1072 | ✗ |
| Empty `Vec::new()` | ✓ RS-W1079 | ✗ |
| `unwrap()` panics | ✓ | ✗ |
| Command injection | ✓ | ✗ |
| Path traversal | ✓ | ✗ |
| Integer overflow | ✓ | ✗ |
| Hardcoded secrets (const) | ✗ | ✗ |
| **Total new issues (bad_rust.rs)** | **+6–8** | **0** |

**Verdict**: DeepSource wins comprehensively. SonarQube's Rust ruleset is limited to complexity only.

---

### Java

| Finding | DeepSource | SonarQube |
|---------|-----------|-----------|
| SQL injection | ✓ | ✓ S2077 |
| Hardcoded password | ✓ | ✓ S2068 (MAJOR) |
| Hardcoded API key | ✓ | ✓ S6418 (BLOCKER) |
| Hardcoded AWS secret | ✓ | ✓ S6418 (BLOCKER) |
| Weak MD5 hashing | ✓ | ✓ S4790 (CRITICAL) |
| Weak Random for tokens | ✓ | ✓ S2245 |
| Command injection | ✓ | ✗ |
| Path traversal | ✓ | ✗ |
| Empty catch block | ✓ | ✗ |
| Null dereference | ✓ | ✗ |
| **Resource leak (Statement)** | ✗ | ✓ S2095 (BLOCKER) |
| **Resource leak (InputStream)** | ✗ | ✓ S2095 (BLOCKER) |
| **`read()` return unchecked** | ✗ | ✓ S2674 |
| **Random object reuse** | ✗ | ✓ S2119 (CRITICAL) |
| Unused fields/variables | ✓ | ✓ |
| Missing package declaration | ✗ | ✓ S1220 |
| **Total new issues (BadJava.java)** | **+8** | **+22** (incl. test file) |

**Verdict**: SonarQube wins on Java. Bytecode analysis gives it dataflow and object lifecycle tracking that source-only analysis misses. DeepSource catches more vulnerability types (command injection, path traversal, null dereference) but misses resource leaks.

**Key gap explained**: Resource leaks, unchecked return values, and object lifecycle issues require SonarQube's bytecode-level dataflow analysis. DeepSource source-only analysis cannot track object state across method boundaries without compiled output.

---

### Secrets Detection

| Secret type | DeepSource Secrets | SonarQube S6418 |
|-------------|-------------------|-----------------|
| Hardcoded password (`"supersecret123"`) | ✗ | ✓ |
| OpenAI key format (`sk-proj-...`) | ✗ | ✓ |
| AWS key format (random high-entropy) | ✗ | ✓ |

**Verdict**: SonarQube wins. DeepSource's secrets analyzer returned +0 on all tests including randomly generated high-entropy keys in named constants (`API_KEY`, `AWS_SECRET`). SonarQube uses variable name heuristics (detects `API_KEY`, `SECRET`, `PASSWORD` field names) in addition to pattern matching.

---

### AI Review (DeepSource only)

DeepSource posted an AI review comment on the PR:
- **Grade: A** overall (Security A, Reliability A, Complexity A, Hygiene A)
- Flagged: `covered_by_permissions_allow_empty_returns_false` test doesn't actually test `covered_by_permissions_allow` — semantic reasoning a static tool can't do
- Non-deterministic — results will vary per run

SonarQube has no equivalent AI review feature (Gitar acquisition is pending integration).

---

### Bitbucket Support

| Tool | Bitbucket Cloud | Bitbucket DC |
|------|----------------|-------------|
| DeepSource | ✓ | Enterprise (self-hosted) |
| SonarQube Cloud | ✓ (via pipeline) | N/A — Cloud only |
| SonarQube DC | ✓ | ✓ (native) |
| Greptile | ✗ | ✗ |
| Gitar | ✗ | ✗ |

---

### Overall Verdict

| Dimension | Winner |
|-----------|--------|
| Rust analysis | **DeepSource** (SonarQube finds 0) |
| Java analysis (source-level) | Tied |
| Java analysis (dataflow/lifecycle) | **SonarQube** (bytecode advantage) |
| Secrets detection | **SonarQube** (variable name heuristics) |
| AI review | **DeepSource** (SonarQube has none yet) |
| Multi-language breadth | **DeepSource** |
| Deterministic gate | Both |
| Bitbucket DC support | **SonarQube DC** |

**Recommendation for Trustonic (Bitbucket DC, Java+Rust)**: Run both. DeepSource covers Rust and catches source-level Java vulnerabilities; SonarQube covers Java dataflow/lifecycle bugs and secrets. Replacing SonarQube DC with DeepSource alone would lose bytecode analysis — the right move is to evaluate DeepSource Enterprise self-hosted as a complement, not a replacement.
