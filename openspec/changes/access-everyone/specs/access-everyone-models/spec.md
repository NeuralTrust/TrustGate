# Specification: access-everyone-models

## Purpose

Console behaviour of Everyone: saving it, and Models access through it. The
gateway's `ALL` access row is Everyone's Models part; exclusions are stored by
directory group id and shared with the MCP part (`store-everyone-access`).

## Requirements

### Requirement: Saving Everyone

An admin MUST be able to save Everyone per gateway: MCP mode and items, Models
mode (`ALL` / `SELECTED`, or none) and selection, and excluded group ids. The
save MUST store exclusions and the `ALL` row together, schedule one reconcile,
write the MCP object to the gateway with ids mapped to group keys, and log
`access_everyone.updated`. MCP Selected with no items MUST remove the MCP
object. If the gateway write fails, the save MUST report it, the Everyone view
MUST show MCP as not applied until a write succeeds, and a retry MUST
converge. The MCP object MUST be written again whenever an excluded group's
grant key changes (rename, directory sync). On a hybrid gateway the Models part MUST be refused
and the MCP part saved with a version warning.

#### Scenario: Gateway write fails

- GIVEN the gateway is unreachable
- WHEN an admin saves Everyone
- THEN the console part is stored, the result reports the MCP failure, and saving again converges

#### Scenario: Excluded group renamed

- GIVEN Everyone excludes Contractors, a directory group without external id
- WHEN Contractors is renamed to Vendors
- THEN the gateway's Everyone object excludes Vendors

#### Scenario: Hybrid gateway

- GIVEN a hybrid gateway
- WHEN an admin saves Everyone with models
- THEN the Models part is refused and the MCP part is saved with the warning

### Requirement: Passing groups

A directory group MUST pass Everyone's models when it is not excluded and its
own row is not `NONE`. A group with no row passes.

#### Scenario: Excluded group

- GIVEN Everyone has models and excludes Contractors
- WHEN the plan is computed
- THEN no Contractors key is linked to Everyone

### Requirement: Group key linking

A group key billed to a passing group, whose owner is an active member of
that group, MUST be linked to Everyone's consumer at level `all`, in addition
to its group's own consumer when that row is `ALL` or `SELECTED`. Personal
keys MUST NOT be linked to Everyone.

#### Scenario: Union of own and Everyone

- GIVEN Sales has `SELECTED` openai and Everyone has `SELECTED` anthropic
- WHEN a Sales group key calls models
- THEN it may use both providers, billed to Sales

### Requirement: Key eligibility

A group MUST be key-eligible when its own row is `ALL` or `SELECTED`, or when
it passes and Everyone has models. Every place that decides or displays
eligibility (key creation, Portal options and models, revocation sweep,
counts, group limits, cost filters, Access panels) MUST use this one rule.

#### Scenario: Everyone-only group

- GIVEN Marketing has no row and Everyone has models
- WHEN the revocation sweep runs
- THEN Marketing's group keys are kept and a member may create one

### Requirement: Revocation confirmation

A write that makes groups lose eligibility (removing Everyone's models, adding
an exclusion, a group write) MUST be refused until confirmed, reporting the
keys and groups affected. On confirmation the keys MUST be revoked and each
revocation audited. A write after which the group stays eligible MUST NOT ask.

#### Scenario: Adding an exclusion

- GIVEN Marketing has only Everyone's models and 3 group keys
- WHEN an admin excludes Marketing without confirming
- THEN the save is refused with 3 keys in 1 group

#### Scenario: Clearing an own row covered by Everyone

- GIVEN Sales has its own row and Everyone has models
- WHEN an admin clears Sales's own row
- THEN no confirmation is asked and no key is revoked

### Requirement: Legacy keys and user view

A legacy key and a user's inherited Models view MUST include the `ALL` row only
only when the owner is in at least one passing group. Their other rules MUST
not change.

#### Scenario: User in no group

- GIVEN Everyone has models
- WHEN a legacy key of a user in no group is planned
- THEN it is not linked to the `ALL` row

### Requirement: Invariance

With no `ALL` row, plans, eligibility, revocations and views MUST be
identical to today. The team flag MUST only hide the UI; the server logic
does not read it. The generic Models access write MUST refuse the `ALL` scope,
so only the Everyone save can create or change the `ALL` row.

#### Scenario: Generic write of the ALL row

- GIVEN any gateway
- WHEN the generic Models access write is called with the `ALL` scope
- THEN it is refused and no row changes

#### Scenario: No Everyone

- GIVEN no `ALL` row
- WHEN the plan is computed
- THEN it equals today's plan for the same input
