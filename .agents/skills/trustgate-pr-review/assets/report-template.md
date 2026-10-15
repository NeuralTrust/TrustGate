# Report template

Translate headings to the user's language. Omit empty sections.

```markdown
## Review — {pr_title} ({pr_link})

**Verdict:** REQUEST CHANGES | APPROVE WITH FIXES | APPROVE — {one sentence why}
Base `{base}` · {n_files} files · +{added}/−{removed} (non-generated)

### Evidence
| Check | Result |
|---|---|
| go build | ✅ / ❌ {first error} |
| go vet (+ functional tag) | … |
| go test -race (changed pkgs) | … |
| golangci-lint | … / not installed |

### 🔴 Blockers
1. **{title}** — [{file}:{line}]({file}:{line}) · axis {n} · {verdict}
   - Problem: {summary}
   - Scenario: {failure_scenario}
   - Fix: {fix}

### 🟡 Should fix
…same shape…

### 🔵 Nits
- [{file}:{line}]({file}:{line}) — {summary}

### Pre-existing (not blocking)
- …

### Coverage
| Axis | Findings kept / raised |
|---|---|
| 1 Bugs | x / y |
| 2 Races & leaks | … |
| 3 TrustGate rules | … |
| 4 Corner cases | … |
| 5 Anti-patterns & SOLID | … |
```

Verdict rule: any CONFIRMED 🔴 → REQUEST CHANGES; only 🟡 or PLAUSIBLE 🔴 → APPROVE WITH FIXES; otherwise APPROVE.
