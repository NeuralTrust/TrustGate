# Archive Report

**Change**: `deprecate-service-entity`
**Linear**: ENG-415 (sub-issues: ENG-429, ENG-430, ENG-431, ENG-432, ENG-434, ENG-435, ENG-436)
**Type**: breaking
**Archived**: 2026-05-21
**Mode**: openspec (filesystem only)
**Verify verdict**: PASS WITH WARNINGS (no CRITICAL issues — see `verify-report.md`)

---

## Source artifacts

All artifacts were retrieved from the change folder at `openspec/changes/deprecate-service-entity/` (now archived):

| Artifact            | Source path (pre-archive)                                                                | Action  |
|---------------------|------------------------------------------------------------------------------------------|---------|
| Proposal            | `openspec/changes/deprecate-service-entity/proposal.md`                                  | Archived |
| Tasks               | `openspec/changes/deprecate-service-entity/tasks.md` (38/38 in-scope; 5.4 waived)        | Archived |
| Design              | `openspec/changes/deprecate-service-entity/design.md` (D1–D10 all resolved)              | Archived |
| Verify report       | `openspec/changes/deprecate-service-entity/verify-report.md` (PASS WITH WARNINGS)        | Archived |
| README              | `openspec/changes/deprecate-service-entity/README.md`                                    | Archived |
| Release notes       | `openspec/changes/deprecate-service-entity/RELEASE_NOTES.md`                             | Archived |
| Delta — `data-migration` | `openspec/changes/deprecate-service-entity/specs/data-migration/spec.md`            | Synced + archived |
| Delta — `services`       | `openspec/changes/deprecate-service-entity/specs/services/spec.md`                  | Synced + archived |
| Delta — `forwarding_rule`| `openspec/changes/deprecate-service-entity/specs/forwarding_rule/spec.md`           | Synced + archived |

---

## Specs synced to main

`openspec/specs/` was empty prior to archive; all three delta specs were net-new and copied directly (no merge).

| Domain            | Action  | Requirements added                                                                                                                                                                                                | Destination                                  | md5                                |
|-------------------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|------------------------------------|
| `data-migration`  | Created | 3 (`Migration MUST move every rule to an upstream without data loss`; `Migration MUST complete within elevated startup timeout`; `Down migration MUST restore service_id link (best-effort)`)                      | `openspec/specs/data-migration/spec.md`      | `56c7b0edb67662e4e4b55248c9d6714c` |
| `services`        | Created | 1 `REMOVED` (`Service CRUD endpoints`) — entire bounded context removed                                                                                                                                            | `openspec/specs/services/spec.md`            | `7c39b6d93e2668f3756106bd30e6e8a3` |
| `forwarding_rule` | Created | 2 `MODIFIED` (`Forwarding rule MUST reference an upstream directly`; `Runtime forwarding MUST resolve upstream without Service lookup`)                                                                            | `openspec/specs/forwarding_rule/spec.md`     | `2fca1e947fbea472a7e3e68fd0a6bbc9` |

md5 verification confirms each main spec is byte-identical to the delta spec it was copied from (see md5 listing in the verification step).

---

## Archive contents checklist

Archived folder: `openspec/changes/archive/2026-05-21-deprecate-service-entity/`

- [x] `proposal.md` (3,634 bytes)
- [x] `tasks.md` (8,860 bytes) — sub-issue tracking comments preserved (`<!-- ENG-429 -->` … `<!-- human-verification: ENG-436 -->`)
- [x] `design.md` (15,688 bytes)
- [x] `verify-report.md` (19,513 bytes)
- [x] `README.md` (3,093 bytes)
- [x] `RELEASE_NOTES.md` (5,893 bytes)
- [x] `specs/data-migration/spec.md` (3,765 bytes)
- [x] `specs/services/spec.md` (1,118 bytes)
- [x] `specs/forwarding_rule/spec.md` (1,871 bytes)
- [x] `archive-report.md` (this file)

Active changes directory state after archive:

```
openspec/changes/
└── archive/
    └── 2026-05-21-deprecate-service-entity/
```

No active (non-archived) changes remain in `openspec/changes/`.

---

## Source-of-truth updated paths

The following main specs now reflect the new behavior and are the source of truth going forward:

- `openspec/specs/data-migration/spec.md`
- `openspec/specs/services/spec.md`
- `openspec/specs/forwarding_rule/spec.md`

---

## Verification status (carried over)

- Build: ✅ `go build -mod=mod ./...` exit 0
- Vet: ✅ `go vet -mod=mod ./...` exit 0
- Tests: ✅ 45 packages passed / 0 failed / 0 skipped (`tests/functional` excluded — requires live Postgres + Redis; compiles cleanly under `go vet`)
- Tasks: 38 / 38 in-scope complete; task 5.4 (migration testcontainer) waived by user in favor of manual staging smoke test
- Spec compliance: 4 of 13 scenarios COMPLIANT, 9 of 13 PARTIAL (structural evidence only — see verify-report §"Spec Compliance Matrix")
- Coherence: all 10 design decisions D1–D10 implemented as designed
- CRITICAL issues: **0**
- WARNING (non-blocking): `scripts/benchmark.sh` still calls the removed `/services` endpoint — to be fixed before next benchmark run, does not block archive

---

## Risks / follow-ups

1. **`scripts/benchmark.sh`** still POSTs to `/gateways/:gateway_id/services` and sends `service_id` (verify-report §WARNING). Will 404 against any deployment with this change. Recommend a small follow-up PR to rewrite that script to use upstreams directly.
2. **Migration not exercised by automated tests** by explicit user decision (5.4 OOS). Mitigation is the manual staging smoke that the user will run before production rollout — see `RELEASE_NOTES.md` for the pre-flight orphan-rule SQL and verification queries. If a regression slips through, consider adding the testcontainers-backed migration test then.
3. **Behavioral coverage for HTTP/WS forwarded handlers' upstream-resolution path** is structural-only. Optional follow-up: a handler-level test with a fake `upstreamFinder` to lock in REQ-FR-2.

None of the above block archive.

---

## Linear

> Linear: transition ENG-415 → In Review.

(The orchestrator handles this transition — the archive sub-agent does not have Linear MCP access.)

---

## SDD cycle complete

The change `deprecate-service-entity` has been fully planned, implemented, verified, and archived. Source of truth (`openspec/specs/`) now reflects the post-change world. Ready for the next change.
