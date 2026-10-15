---
name: trustgate-pr-review
description: "Trigger: review TrustGate PR, revisa la PR, code review TrustGate, /trustgate-pr-review <pr>. Five-axis PR review: bugs, races/leaks, TrustGate rules, corner cases, SOLID."
license: Apache-2.0
metadata:
  author: neuraltrust
  version: "1.0"
---

> **Host mapping.** Claude Code: delegation tool `Agent`, reviewers `model: opus`, agent `general-purpose` with the read-only clause from the prompt (`Explore` only locates code, it does not audit). Cursor: `Task`, `claude-opus-4-8-thinking-high`, `explore` (`readonly: true`).

## Activation Contract

Review one TrustGate (`NeuralTrust/TrustGate`) pull request or local branch. Input: PR number/URL, branch name, or nothing (current branch). Not for whole-repo audits (use `project-audit`) or non-TrustGate repos (use `code-review`).

## Hard Rules

- Read-only. Never edit, commit, push, or post to GitHub/Linear unless the user asks; show the exact comment text and wait for a yes before posting.
- Orchestrate, do not review inline: exactly **five** reviewer sub-agents, one per axis, launched in **one message**, then **one** verifier sub-agent.
- Findings must anchor to lines the PR adds/changes, or to code whose behaviour the PR changes. Untouched pre-existing debt goes to `Pre-existing` (max 3, never blocking).
- Every 🔴/🟡 needs a concrete failure scenario (input/state → wrong result). No scenario → downgrade to 🔵 or drop.
- Skip generated files: `**/mocks/**`, `*.pb.go`, `*_gen.go`, `docs/swagger.*`, `docs/openapi.json`, `docs/docs.go`.
- Never read `.env*`. A secret in the diff is an immediate 🔴.
- Report in the user's language (Castilian Spanish if Spanish).

## Decision Gates

| Situation | Action |
|---|---|
| PR number/URL given | `gh pr view` + detached worktree of the PR head in the scratchpad |
| Branch / no input | Base = `gh pr view --json baseRefName`, else `develop`; diff `origin/<base>...HEAD` |
| Base is `main` | Hotfix: raise bar on blast radius and rollback; flag feature work targeting `main` |
| Diff > 1500 changed lines (non-generated) | Warn about the 400-line soft cap; still review, prioritise `pkg/app`, `pkg/infra`, `pkg/runtimeconfig` |
| Only docs/tests changed | Run axes 1, 3, 4 only; state it in the report |

## Execution Steps

1. Resolve target, `git fetch origin <base>`, write `diff.patch`, `files.txt`, and PR title/body/Linear id to `<scratchpad>/tg-review-<id>/`.
2. In the reviewed tree, run cheap evidence (record output, never block on missing tools): `go build ./...`, `go vet ./...`, `go vet -tags functional ./tests/functional/...`, `go test -race -count=1` on changed packages, `golangci-lint run` on changed packages if installed.
3. Launch the five reviewers with [assets/reviewer-prompt.md](assets/reviewer-prompt.md), one axis each from [references/review-axes.md](references/review-axes.md); axis 3 also gets [references/trustgate-rules.md](references/trustgate-rules.md).
4. Launch the verifier with all findings (same asset, verifier section): dedupe, try to disprove each, mark `CONFIRMED` / `PLAUSIBLE` / `REJECTED`.
5. Drop `REJECTED`, render the report, remove any worktree you created.

## Output Contract

Use [assets/report-template.md](assets/report-template.md): verdict (`APPROVE` / `APPROVE WITH FIXES` / `REQUEST CHANGES`), evidence table, findings by severity with `file:line`, axis, failure scenario, fix. If the host has a `ReportFindings` tool, also call it with the verified findings.

## References

- [references/review-axes.md](references/review-axes.md) — per-axis checklists with TrustGate hotspots.
- [references/trustgate-rules.md](references/trustgate-rules.md) — project norms and their local sources.
- [assets/reviewer-prompt.md](assets/reviewer-prompt.md) — reviewer + verifier prompts, finding schema.
- [assets/report-template.md](assets/report-template.md) — final report shape.
