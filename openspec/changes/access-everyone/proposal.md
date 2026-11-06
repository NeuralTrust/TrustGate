# Proposal: Everyone and bulk Assign / Remove on Access › Groups

## Intent

Add **Everyone** (a set every group receives, with exclusions) and **bulk
Assign / Remove** on Access › Groups. The UI exists behind a flag; this builds
the backend. Evidence: `exploration.md`.

## Scope

### In Scope
- **MCP Everyone (TrustGate):** `GET|PUT …/store/everyone {mode, grants, excluded_groups}`, own table, in the snapshot, evaluated live.
- **Models Everyone (console):** the `ALL` row becomes Everyone; passing group keys link to its consumer at level `all`; the flag only hides the UI, and only the Everyone save may write the `ALL` row; one shared eligibility predicate everywhere. Legacy keys and the Users-side inherited view get the `ALL` row only if the owner is reached (no-op today: no `ALL` rows in production).
- **Console:** `AccessEveryone` table by group id, reader, push to `store/everyone`; bulk actions with per-group `{applied, failed}`; audit events; contract by `DirectoryGroup.id`; hybrid warning.

### Out of Scope
- Other legacy-key and Users-side rules, batch grants / ETag, pre-existing panel save issues.
- Playwright e2e, panel redesign.

## Capabilities

### New Capabilities
All three live here, the console ones included (as with `llm-store`).

- `store-everyone-access`: MCP Everyone, reach, mode precedence, grants.
- `access-everyone-models`: Models Everyone, exclusions, key eligibility.
- `access-bulk-assign`: bulk semantics, partial failure.

### Modified Capabilities
None.

## Approach

Console is the source of truth; TrustGate gets the compiled MCP object. Mode:
own policy → else `max(best group policy | fallback, Everyone if reached)`;
reached = some `StoreGroups()` group not excluded and not on `none`. Own user
`none` blocks Everyone. Bulk Remove skips groups on All.
An emptied Selected list keeps the group on Everyone: MCP stays `curated`
with no own grants; Models deletes the group's own row, confirming key
revocation only if the group ends with no models.

## Affected Areas

| Area | Impact |
|------|--------|
| TrustGate `pkg/domain/storeaccess`, `pkg/app/store`, `pkg/app/mcp` | Everyone object, precedence, grant Set |
| TrustGate migrations, repository, `configsnapshot`, DP reader | `store_everyone` table + snapshot |
| app `llm-store/lib`, `llm-store/actions`, `prisma` | `ALL` row as Everyone, predicate, `AccessEveryone` |
| app `access/actions`, `access/hooks`, `constants/audit.ts` | Everyone + bulk actions, audit |

## Risks

| Risk | Mitigation |
|------|------------|
| Sweep revokes Everyone-only group keys | predicate and linking in one PR |
| Old hybrid planes ignore Everyone | warning banner; TrustGate released before console push |
| Everyone lowers a mode | never-lower rule + truth-table tests |

## Rollback Plan

Migrations are additive. MCP: deleting the `store/everyone` object restores
today's behaviour exactly. Models: clearing the `ALL` row **or** rolling back
the code revokes group keys that exist only through Everyone, and that cannot
be undone for users. Safe order: clear Everyone through the revocation
confirm, then roll back the code; turning the flag off only hides the UI.

## Success Criteria

- [ ] No Everyone object / no `ALL` row → plans and modes identical to today (tests).
- [ ] ENG-3054 §7 QA passes for personal key, group key, default-IdP and external-IdP sessions.
- [ ] Bulk partial failure reports failed groups; retry converges.
- [ ] Audit events visible in the Audit log.
