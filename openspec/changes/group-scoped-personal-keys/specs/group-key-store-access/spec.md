# Delta for group-key-store-access

Change `group-scoped-personal-keys` (ENG-2610), slice K4 (G6). New capability. A group key opens its owner's MCP Store (`/store/mcp`) with the reach of its group alone. A personal key and a signed-in session are unchanged.

## ADDED Requirements

### Requirement: The key's group rides the principal, set by the gateway only

The principal a personal key resolves to MUST carry its `group_name` as the `key_group` claim when the key has a group. `Principal.KeyGroup()` MUST read the claim only when the principal's method is `personal_key`, so no token can claim a group. The principal's `groups` claim MUST be the owner's recorded groups plus the key's group.

#### Scenario: A token claims a group

- GIVEN an OIDC or session principal whose claims include `key_group`
- WHEN the Store asks for the principal's key group
- THEN the answer is empty

### Requirement: The Store decides for the group

`Principal.StoreSubject()` MUST be empty and `Principal.StoreGroups()` MUST be `[group_name]` for a group key, and the subject and every group otherwise. The Store's mode resolver, scoper, installer, search, install and configure paths MUST decide with them: a group key's Store mode MUST be its group's access policy, else the gateway's default, and only grants to its group MUST count. The owner's own access policy, grants that name the owner and grants to the owner's other groups MUST NOT.

#### Scenario: A grant to the owner does not reach the group key

- GIVEN a `curated` Store, alice in `eng` and `sre`, with `github` granted to alice, `linear` to `eng` and `notion` to `sre`, all three installed by alice
- WHEN alice's key for `eng` opens the Store
- THEN it reaches `linear` only, and her personal key reaches all three

#### Scenario: The group's access policy

- GIVEN an `open` policy for alice, a `none` policy for `eng` and a `curated` gateway default
- WHEN alice's key for `eng`, and her key for `data` (a group with no policy), resolve their Store mode
- THEN the first is `none` and the second `curated`, never alice's `open`

### Requirement: Installs stay the owner's and policies see every group

An install made with a group key MUST be the owner's installation, with the owner's connected accounts, matched against grants to the group only (`GroupScoped`). MCP policies scoped to groups MUST be evaluated with every group of the owner plus the key's group.

#### Scenario: A policy for another group of the owner

- GIVEN an MCP policy scoped to `sre`, and alice in `engineering` and `sre`
- WHEN alice's key for `engineering` calls a tool
- THEN the policy runs
