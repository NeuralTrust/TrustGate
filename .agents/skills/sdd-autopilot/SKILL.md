---
name: sdd-autopilot
description: "Trigger: autopilot, full SDD run, autonomous feature, 'implement this feature end to end', worktree-to-PR. Orchestrate the full SDD lifecycle (worktree → explore → spec+design → tasks → autonomous per-phase apply+review → PR) for one change."
license: Apache-2.0
metadata:
  author: trustgate
  version: "1.0"
---

# SDD Autopilot

You are the ORCHESTRATOR. Drive a feature from a develop worktree all the way to
an open PR, delegating each SDD phase to its sub-agent. There are exactly TWO
human gates: approving the tasks before implementation, and deciding the final
archive/worktree cleanup after the PR is open.

## Activation Contract

Use when the user asks to take a feature/change end to end autonomously, or says
"autopilot", "full SDD run", "implementá esto entero", "worktree to PR".

Do NOT use for: a single isolated SDD phase (call that sub-agent directly), a quick
edit, or work that must stay on the current branch.

## Required Input: Linear issue (mandatory)

A Linear issue is REQUIRED — the autopilot cannot run without one. If the user did
not provide a Linear issue id/url, STOP and ask for it before doing anything else.

Before any other step, read the issue via the Linear MCP (`linear.get_issue`,
including comments/sub-issues if relevant). The issue is the source of truth for the
feature: derive `change-name` from it, and pass its title + description + acceptance
criteria as the explicit context to EVERY delegated phase (explore, propose, spec,
design, tasks, apply). Record the issue id so it lands in the PR body and any
`sdd-linear-sync`.

## Hard Rules

- A Linear issue is mandatory. No issue → STOP and ask. Read it FIRST and feed its
  content into every phase.
- The repo conventions in `.agents/AGENT.md` and the `golang-pro` skill are binding
  for every phase that touches Go code (design, apply, review). Inject both as
  explicit context into those sub-agents; do NOT let a phase freelance against them.
- Keep the Linear issue status in sync as the run progresses: `In Progress` when
  implementation starts, `In Review` when the PR opens. Use the Linear MCP
  (`linear.update_issue`). If a state name does not exist on the team, pick the
  closest equivalent and note it.
- Delegate each SDD phase to its sub-agent via the Task tool: `sdd-explore`,
  `sdd-propose`, `sdd-spec`, `sdd-design`, `sdd-tasks`, `sdd-apply`. Never inline
  their instructions.
- Resolve open questions yourself by investigating the codebase. Do NOT ask the
  user to answer them. The ONLY blocking user gates are task approval (step 6)
  and final archive/worktree cleanup confirmation (step 10).
- All work happens inside the worktree. Never touch the user's current checkout.
- Honor the repo's no-comments policy (`/.agents/AGENT.md`): strip narrative code
  comments after every phase and once more before the PR.
- One `change-name` (kebab-case, derived from the request) is used for every phase
  and the branch.
- Pick the artifact mode once: `openspec` if `openspec/config.yaml` exists, else
  `hybrid` (engram + files). Pass the SAME mode to every sub-agent.

## Decision Gates

| Situation | Action |
|-----------|--------|
| `sdd-explore`/`sdd-design` return open questions | Investigate the codebase and resolve them yourself before proceeding |
| Questions cannot be resolved from the code | THEN ask the user; this does not replace the final cleanup confirmation |
| Tasks created | Show `tasks.md` to the user, request approval to implement |
| Workload forecast says >400 lines / chained PRs | Surface the chain strategy choice to the user with the tasks |
| A phase's code review finds CRITICAL/WARNING(real) | Apply fixes, re-review until clean, then advance |
| PR is open and Linear close-out comment is posted | Ask the user whether they want more changes/checks, and whether to archive + remove the worktree |

## Execution Steps

1. **Read the Linear issue (mandatory).** If no issue id/url was given, STOP and
   ask. Fetch it with `linear.get_issue`. From it derive `change-name` (kebab-case)
   and keep its title/description/acceptance criteria as the context bundle passed
   to every phase. No issue → no run.
2. **Worktree.** Build `branch=<type>/<change-name>` (type ∈
   feat|fix|refactor|chore). Then:
   ```bash
   git fetch origin
   git worktree add ../<repo>-<change-name> -b <branch> origin/develop
   ```
   Run all subsequent shell/edits with that worktree as the working directory.
3. **Explore.** Delegate to `sdd-explore` with the Linear issue context + artifact
   mode. Read its open questions; investigate the code and resolve each. Then
   delegate to `sdd-propose` to write `proposal.md` (spec/design depend on it).
4. **Spec + Design (parallel).** Launch `sdd-spec` and `sdd-design` in a single
   message (two Task calls), each with the Linear issue context. When both return,
   resolve any new open questions by investigating the codebase.
5. **Tasks.** Delegate to `sdd-tasks`. Capture the Review Workload Forecast.
6. **Human gate.** Show the user the full `tasks.md` (phases + forecast) and ask
   for permission to start implementing. STOP until approved. Do not implement
   while any open question is unresolved. Once approved, move the Linear issue to
   `In Progress` via `linear.update_issue`.
7. **Autonomous per-phase loop.** For each phase in order:
   - Delegate the phase's tasks to `sdd-apply`, instructing it to follow
     `.agents/AGENT.md` (layout, DI, DTO placement, no-comments) and `golang-pro`
     (idiomatic Go, error wrapping, context, `go vet`/`golangci-lint`, `-race` tests).
   - Run a code review of that phase's diff (Task `bugbot`, or the `code-review`
     skill) that also checks compliance with `.agents/AGENT.md` and `golang-pro`,
     and apply all CRITICAL + WARNING(real) fixes; re-review until clean.
   - Strip leftover code comments per the no-comments policy.
   - Commit the phase as one work unit, then continue to the next phase.
8. **Feature-wide review.** After every phase is applied, run a code review over
   the whole feature diff (`git diff origin/develop...HEAD`) — including
   `.agents/AGENT.md` + `golang-pro` compliance — apply the fixes, and strip any
   remaining surplus comments.
9. **Ship.** Push the branch (`git push -u origin <branch>`) and open the PR
   targeting `develop` (`gh pr create`), with the Linear issue id in the body.
   Move the Linear issue to `In Review` (`linear.update_issue`). Do NOT archive
   or remove the worktree automatically.
10. **Close out.** Post a final comment on the Linear issue
    (`linear.create_comment`) summarizing the run: what was delivered, the PR link,
    and explicitly whether everything went as planned OR which points deviated from
    the issue/proposal (and why). Then STOP and ask the user:
    - Whether they want any additional changes or checks before cleanup.
    - Whether they want to archive the SDD change and remove the worktree.
    Only if the user confirms archive/cleanup, delegate to `sdd-archive` to move
    the change folder into `openspec/changes/archive/` and merge the delta specs
    into the main specs, then remove the worktree:
    ```bash
    git worktree remove ../<repo>-<change-name>
    ```

## Output Contract

Report to the user:
- `change-name`, branch, and worktree path created.
- Linear issue id and the status transitions applied (`In Progress` → `In Review`).
- Per phase: tasks applied, review verdict, fixes applied.
- Feature-wide review verdict and final fixes.
- The PR URL and a copy of the final Linear comment (outcome + any deviations).
- The final user decision: any additional changes/checks requested, and whether
  `sdd-archive` ran and the worktree was removed.

## References

- `.agents/AGENT.md` — repo conventions, no-comments policy, branch/PR rules.
  Binding for every Go-touching phase.
- `~/.agents/skills/golang-pro/SKILL.md` — idiomatic Go standards (concurrency,
  error wrapping, context, lint/vet/race). Binding for design, apply, and review.
- `~/.cursor/skills/sdd-*/SKILL.md` — the delegated phase sub-agents, including
  `sdd-archive` when the user confirms final cleanup.
- `~/.cursor/skills/code-review/SKILL.md` — per-phase and feature-wide review axes.
- `~/.cursor/skills/sdd-linear-sync/SKILL.md` — optional Linear mirroring of tasks.
