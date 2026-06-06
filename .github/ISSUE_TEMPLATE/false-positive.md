---
name: False positive
about: A legitimate command that clawband incorrectly blocks or prompts
labels: false-positive
---

**Command being blocked/prompted**

```sh
# Paste the exact command
```

**Decision received**
- [ ] deny (should pass or ask)
- [ ] ask (should pass)

**Expected behaviour**
What should happen instead?

**Workaround**
Have you been able to add it to `allow.patterns`? If so, what regex did you use?

```
# ~/.clawband/allow.patterns
```

**clawband version**
```
clawband --version
```
