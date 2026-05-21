# deprecate-service-entity

SDD change folder. Layout follows the OpenSpec convention.

```
deprecate-service-entity/
├── README.md          ← this file
├── proposal.md        ← intent, scope, rollout
├── design.md          ← technical approach + decisions + file map
├── specs/
│   ├── forwarding_rule/spec.md   ← delta: MODIFIED requirements
│   ├── services/spec.md          ← delta: REMOVED requirements
│   └── data-migration/spec.md    ← new full spec for the migration
└── tasks.md           ← implementation checklist (created by sdd-tasks)
```

## Status

| Phase    | Artifact                   | State                                              |
|----------|----------------------------|----------------------------------------------------|
| Proposal | `proposal.md`              | ✅ written                                          |
| Spec     | `specs/*/spec.md`          | ✅ written                                          |
| Design   | `design.md`                | ✅ written                                          |
| Tasks    | `tasks.md`                 | ✅ written, all phases complete (5.4 out of scope) |
| Apply    | code                       | ✅ done — Phases 1–6                                |
| Verify   | tests + spec match         | ✅ unit tests green; functional tests compile      |
| Archive  | sync to `openspec/specs/*` | ⏳ pending (sdd-archive)                            |

### Phase completion summary

- **Phase 1 (foundation)** ✅ — migration timeout env var, migration 20240007, domain field rename, error removal.
- **Phase 2 (core implementation)** ✅ — 11 tasks. `rule.Creator/Updater` use `upstream.Repository`; DTOs renamed; helpers + forwarded handlers rewired; cross-gateway upstream protection added.
- **Phase 3 (removal)** ✅ — 9 tasks. Service bounded context deleted (domain + app + infra + handlers + cache + DI + router).
- **Phase 4 (observability + middleware)** ✅ — Prometheus label `service` → `upstream`; middleware constant `ServiceIDKey` → `UpstreamIDKey`.
- **Phase 5 (testing)** ✅ — 6 of 7 tasks; 5.4 (migration testcontainer) explicitly out of scope per user (manual smoke test in staging).
- **Phase 6 (docs + cleanup)** ✅ — swagger/openapi regenerated; `RELEASE_NOTES.md` written with runbook + verification SQL; final grep clean (only legit references in migration files).

## Persistence Mode

Artifacts are mirrored in Engram (`sdd/deprecate-service-entity/*`) and on disk in this folder. Engram remains the primary store for the orchestrator; files here are for human review, PR diffs, and offline reading.

## Resolved Decisions

- [x] **Upstream naming**: `svc-migrated-<service_uuid>` (deterministic, collision-free).
- [x] **Drop `services` table** in the same migration. No safety-net release.
- [x] **Prometheus label rename** `service_id` → `upstream_id` approved; called out in release notes.
- [x] **No pre-flight CLI**: rely on the migration's orphan-assert; runbook documents recovery SQL.
