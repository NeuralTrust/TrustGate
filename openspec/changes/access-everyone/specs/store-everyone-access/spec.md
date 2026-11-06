# Specification: store-everyone-access

## Purpose

A per-gateway **Everyone** object for the MCP Store: a Store level and a set of
servers that every group passes on to its members, except excluded groups and
groups on `none`. It only ever adds access.

## Requirements

### Requirement: Everyone object

Each gateway MAY hold one Everyone object `{mode, grants[], excluded_groups[]}`.
`mode` MUST be `open` or `curated`; `none` MUST be rejected, and so MUST
`curated` with no grants (an empty object is the only way to say "nothing"). Each grant names a
catalog code and optionally one registry of that code, validated as Store
grants are. Group keys are matched exactly, as in grants. The admin API MUST
offer read and replace under the same gateway access as Store policies;
replacing with an empty object removes it.

#### Scenario: Invalid mode

- GIVEN a gateway
- WHEN an admin saves Everyone with mode `none`
- THEN the request is rejected and nothing is stored

#### Scenario: Curated without grants

- GIVEN a gateway
- WHEN an admin saves Everyone `curated` with no grants
- THEN the request is rejected

#### Scenario: Removal

- GIVEN a gateway with an Everyone object
- WHEN an admin replaces it with an empty object
- THEN reading it returns no Everyone

### Requirement: Reach

A caller MUST reach Everyone when at least one of its Store groups is not in
`excluded_groups` and has no own group policy `none`. A group with no policy
passes. A group key's Store groups are its own group only. A caller with no
groups MUST NOT reach Everyone.

#### Scenario: Excluded group and passing group

- GIVEN Everyone excludes Contractors and a user is in Contractors and Sales
- WHEN the user calls the Store
- THEN the user reaches Everyone

#### Scenario: Group key of an excluded group

- GIVEN Everyone excludes Contractors
- WHEN a Contractors group key calls the Store
- THEN it does not reach Everyone, whatever its owner's other groups

#### Scenario: Group on none

- GIVEN Sales has a group policy `none` and is not excluded
- WHEN a user whose only group is Sales calls the Store
- THEN the user does not reach Everyone

### Requirement: Store level precedence

The Store level MUST resolve as follows:

| Caller has | Level |
| -- | -- |
| own user policy | that policy (Everyone ignored) |
| explicit group policies | max(most permissive group policy, Everyone mode if reached) |
| no explicit group policy | max(fallback level, Everyone mode if reached) |

`open` > `curated` > `none`. The fallback is today's (legacy claim, then the
gateway default). With no Everyone object the result MUST equal today's for
every caller, and with one it MUST never be lower.

#### Scenario: Fallback is not lowered

- GIVEN the gateway default is `open`, Everyone is `curated`, and the user's groups have no policies
- WHEN the user's level is resolved
- THEN it is `open`

#### Scenario: Everyone raises a curated group

- GIVEN Sales has policy `curated` and Everyone is `open`
- WHEN a Sales member's level is resolved
- THEN it is `open`

#### Scenario: Own none wins

- GIVEN a user with own policy `none` in a group that reaches an `open` Everyone
- WHEN the user's level is resolved
- THEN it is `none`

### Requirement: Everyone grants

Under `curated`, a caller that reaches Everyone MUST be treated as granted
every server in Everyone's grants, for search, install, connect, configure and
exposure of installed instances, without creating an approval request. A
code-level Everyone grant MUST cover every instance of that code, including
future ones; an instance-level one only that registry. Callers that do not
reach Everyone MUST see no change. Reach, not the level's source, decides
this: a user whose own policy is `curated` still gets Everyone's grants.

#### Scenario: Install without approval

- GIVEN level `curated` and Everyone grants `github`
- WHEN a caller that reaches Everyone installs `github`
- THEN the install proceeds and no approval request is created

#### Scenario: Not reached

- GIVEN Everyone grants `github` and the caller is in no group
- WHEN the caller installs `github` under `curated`
- THEN an approval request is created, as today

#### Scenario: Server removed from Everyone

- GIVEN a caller has `github` installed only through Everyone
- WHEN `github` is removed from Everyone's grants
- THEN the installed instance stops being exposed to the caller, as when a grant is removed

### Requirement: Data planes

The Everyone object MUST reach data planes, hybrid ones included, through the
config snapshot and be evaluated there like policies and grants. A data plane
without it MUST behave as if no Everyone exists. A failed Everyone read on the
control plane MUST be treated as no Everyone and logged.

#### Scenario: Hybrid gateway

- GIVEN a hybrid gateway with Everyone granting `github`
- WHEN its data plane loads the snapshot
- THEN a caller that reaches Everyone may install `github` without approval
