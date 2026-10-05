# Delta for usage-auth-id-telemetry

Change `llm-store` (RUN-1763), slice S1. New capability. LLM proxy usage events carry the id of the auth that authenticated the request, so cost can be attributed to a key and, for a personal key, to its owner. Today `stampConsumerTrace` (`pkg/api/handler/http/proxy/proxy_handler.go`) never receives `authCtx`, and neither the trace metadata, the event nor the OTLP mapping has an auth id. DataCore D1 must be in production before this ships; that is a deploy-order note, not a requirement here.

## ADDED Requirements

### Requirement: The auth id rides trace metadata, the event and OTLP

`stampConsumerTrace` MUST receive the request's `authCtx` and MUST copy `authCtx.AuthID` into a new `AuthID` field of the trace metadata (`pkg/infra/trace/trace.go`). The event builder (`pkg/app/metrics/builder.go`) MUST copy it into a new event field `auth_id` (`pkg/infra/metrics/events/event.go`, `json:"auth_id,omitempty"`), and the OTLP mapping (`pkg/infra/telemetry/otlp/mapping.go`) MUST emit it as the attribute `trustgate.auth.id`.

An empty auth id MUST NOT be stamped: the event field MUST be omitted and the OTLP attribute MUST NOT be emitted, as `SetPrincipalIdentity` already does for empty principal values.

#### Scenario: Application key on a consumer

- GIVEN consumer X with `api_key` auth A
- WHEN a request authenticated by A on `/<X slug>/v1/chat/completions` completes
- THEN the usage event has `auth_id = A.ID` and the OTLP log record has `trustgate.auth.id = A.ID`

#### Scenario: No auth id

- GIVEN a request whose `authCtx.AuthID` is empty
- WHEN its usage event is built and mapped to OTLP
- THEN the JSON event has no `auth_id` key and the OTLP record has no `trustgate.auth.id` attribute

### Requirement: Principal subject is unchanged for application keys and is the owner for personal keys

`principal_subject` MUST keep coming from the context principal. For an application key it MUST stay the key name, as today. For a personal key on `/store/v1/*` the principal is built with `Subject = owner_id` (`llm-store-gateway`), so `principal_subject` MUST equal `owner_id` and `principal_method` MUST be `api_key`, with no extra code in the stamp.

#### Scenario: Application key subject

- GIVEN an application key named `billing-service`
- WHEN its request completes on `/<slug>/v1/chat/completions`
- THEN `principal_subject = billing-service`, as today

#### Scenario: Personal key subject

- GIVEN a personal key with `owner_id = user-123`
- WHEN its request completes on `/store/v1/chat/completions`
- THEN `principal_subject = user-123`, `principal_method = api_key`, `auth_id` is the personal key's auth id and `consumer.id` is the id of the personal consumer selected to serve the request (`store-consumer-selection`)

### Requirement: Contract document updated

`docs/telemetry/otlp-metadata-contract.md` MUST list `trustgate.auth.id` with source `auth_id`, and the row for `trustgate.principal.subject` MUST state that for a personal key it is the key owner.

#### Scenario: Contract row present

- GIVEN the contract document after the change
- WHEN the attribute table is read
- THEN it has a `trustgate.auth.id` row sourced from `auth_id`
