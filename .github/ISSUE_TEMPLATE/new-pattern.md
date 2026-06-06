---
name: New pattern
about: Suggest a command that should be blocked or prompted
labels: pattern
---

**Command / pattern**

```sh
# The command that should be caught
```

**Suggested decision**
- [ ] deny (hard-block — catastrophic or irreversible)
- [ ] ask (prompt for approval — risky but sometimes legitimate)

**Why**
What makes this dangerous? Why can't it be recovered from?

**False positive risk**
Are there common legitimate uses that would accidentally be blocked?

**Regex (optional)**
If you have a regex that matches the dangerous case without catching the safe cases, include it here.
