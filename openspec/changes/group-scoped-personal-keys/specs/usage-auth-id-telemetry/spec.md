# Delta for usage-auth-id-telemetry

Change `group-scoped-personal-keys` (ENG-2610), slice K5 (G7). LLM events say which kind of key made the request and, for a group key, which group its spend belongs to.

## ADDED Requirements

### Requirement: Key kind and group ride trace metadata, the event and OTLP

When an API key authenticates an LLM proxy request (`/store/v1` or a consumer route), the trace metadata MUST carry `AuthKind`: `personal` for a key with an owner (a personal key or a group key), `application` for any other. For a group key it MUST also carry `AuthGroupID`, the key's `group_id`. The usage event MUST carry them as `auth_kind` and `auth_group_id` (`omitempty`), and OTLP MUST map them to `trustgate.auth.kind` and `trustgate.auth.group_id`. A request no API key authenticated MUST carry neither. `docs/telemetry/otlp-metadata-contract.md` MUST list both.

#### Scenario: Group key

- GIVEN alice's key for `g-eng`
- WHEN it calls `/store/v1/chat/completions`
- THEN the record carries `trustgate.auth.kind = personal` and `trustgate.auth.group_id = g-eng`

#### Scenario: Personal and application keys

- WHEN alice's personal key calls `/store/v1`, and an application key calls its consumer's route
- THEN the first carries `trustgate.auth.kind = personal` and no group, the second `application` and no group

### Requirement: Personal key events name the group

The personal key events posted to `CONSOLE_EVENTS_URL` MUST carry `group_id` (`omitempty`). The MCP Store's page manages the personal key only, so it MUST be absent there.

#### Scenario: Event from the Store page

- WHEN alice creates her personal key from the Store page
- THEN the event body has no `group_id`
