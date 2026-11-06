# Specification: access-bulk-assign

## Purpose

Bulk Assign and bulk Remove on Access › Groups: one edit applied to many
directory groups, equal to what each group's own panel would write. Groups are
identified by directory group id. Everyone is never touched.

## Requirements

### Requirement: Assign effect per section

For each picked group, each section (MCP, Models) MUST be applied
independently:

| Section sent | Add | Replace |
| -- | -- | -- |
| Selected, no rows | no change | no change |
| Selected, with rows | level Selected; own list ∪ rows | level Selected; own list = rows |
| All | level All | level All |
| None | level None | level None |

A section with no change MUST NOT be written. Assign MUST NOT change Everyone.
An Add that narrows a group (a group on All moves to Selected, or an MCP group
with no policy on an `open` gateway gets `curated`) MUST count as taking
access away and require confirmation naming those groups.

#### Scenario: Add narrows a group on All

- GIVEN Sales has Models All
- WHEN Assign adds Models openai to Sales without confirming
- THEN it is refused, naming Sales as narrowed

#### Scenario: Add to a Selected group

- GIVEN Sales has MCP Selected with `github`
- WHEN Assign adds MCP `jira` to Sales
- THEN Sales has MCP Selected with `github` and `jira`

#### Scenario: Group on None gets Selected

- GIVEN Sales has Models None
- WHEN Assign adds Models openai to Sales
- THEN Sales has Models Selected with openai

#### Scenario: Everyone untouched

- GIVEN Everyone grants `github`
- WHEN Assign sets MCP None on Sales
- THEN Everyone still grants `github` and Sales no longer passes it

### Requirement: Remove effect per section

Remove MUST take the given rows off each picked group's own Selected list and
MUST NOT change any level, except as below. Groups on All or None, and groups
without the item, MUST be left unchanged and reported as skipped. When Remove
empties a group's own list, the group MUST keep receiving Everyone: MCP stays
on Selected with no own grants; Models drops the group's own row.

#### Scenario: Group on All

- GIVEN Sales has MCP All
- WHEN Remove takes `github` from Sales
- THEN Sales stays on All and is reported as skipped

#### Scenario: Last MCP item

- GIVEN Sales has MCP Selected with only `github` and Everyone grants `jira`
- WHEN Remove takes `github` from Sales
- THEN Sales stays Selected with no own grants and its members still get `jira` without approval

#### Scenario: Last Models provider

- GIVEN Sales has Models Selected with only openai and Everyone has anthropic
- WHEN Remove takes openai from Sales
- THEN Sales has no own row and its group keys keep anthropic

### Requirement: Confirmation

Assign MUST require confirmation when it takes access away (Replace with rows,
a section on None, or a narrowing Add); Remove MUST always require it. When the edit makes
groups lose Models key eligibility (`access-everyone-models`), the
confirmation MUST report the keys and groups affected, and the keys MUST be
revoked and audited only after confirmation.

#### Scenario: Models None with keys

- GIVEN Sales and Ops hold 5 group keys and Everyone has no models
- WHEN Assign sets Models None on both without confirming
- THEN it is refused, reporting 5 keys in 2 groups

### Requirement: Writes and partial failure

Models changes for all picked groups MUST be stored in one transaction and
reconciled once. MCP changes MUST be computed on the server from the current
gateway state: one policy write per group whose level changes, one grant
write per affected server. The result MUST report, per group and per section,
applied, skipped or failed; repeating the same edit MUST converge.

#### Scenario: One server write fails

- GIVEN Assign adds MCP `jira` and Models openai to Sales and Ops, and the `jira` grant write fails
- WHEN the result is returned
- THEN Sales and Ops are failed for MCP and applied for Models, and repeating the edit converges

### Requirement: Audit

Each affected group MUST get its own audit events: `llm_store_access.updated`
for Models, `mcp_store_access_policy.updated` for a level, and
`mcp_store_grant.updated` per changed server. No bulk summary event is logged.

#### Scenario: Bulk audit

- GIVEN Assign sets MCP All on Sales and Ops
- WHEN it succeeds
- THEN the Audit log shows one level event per group
