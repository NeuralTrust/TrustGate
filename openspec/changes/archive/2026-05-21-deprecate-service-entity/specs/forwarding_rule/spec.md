# Delta: forwarding_rule

## MODIFIED Requirements

### Requirement: Forwarding rule MUST reference an upstream directly

(Previously: `forwarding_rules.service_id` referenced `services`; the runtime resolved upstream via the service.)

The system MUST persist `forwarding_rules.upstream_id` as a non-nullable FK to `upstreams(id)` with `ON DELETE CASCADE`. The system MUST reject create/update requests whose `upstream_id` is empty, not a UUID, or belongs to a different gateway. The system MUST NOT accept or persist `service_id`.

#### Scenario: Create rule with valid upstream

- GIVEN a gateway G and upstream U where U.gateway_id = G.id
- WHEN POST /api/v1/gateways/G/rules with `upstream_id=U.id`
- THEN response is 201 and the row stores `upstream_id=U.id`

#### Scenario: Create rule with cross-gateway upstream

- GIVEN gateway G1 and upstream U2 where U2.gateway_id != G1.id
- WHEN POST /api/v1/gateways/G1/rules with `upstream_id=U2.id`
- THEN response is 400 `upstream not found`

#### Scenario: Create rule omitting upstream_id

- WHEN the request body lacks `upstream_id` or contains `service_id`
- THEN response is 400 `upstream_id is required`

### Requirement: Runtime forwarding MUST resolve upstream without Service lookup

The forwarded HTTP and WebSocket handlers MUST load the upstream from `forwarding_rule.upstream_id` via `upstream.Finder`. The system MUST remove the `service.Finder` dependency and the `TypeUpstream`/`TypeEndpoint` branch.

#### Scenario: HTTP forward

- GIVEN a matched rule with `upstream_id=U`
- WHEN the forwarded handler executes
- THEN it calls `upstreamFinder.Find(ctx, gatewayID, U)` exactly once and never calls `serviceFinder`

#### Scenario: Cache DTO shape

- WHEN `GatewayData.Rules` is built or read from Redis/memory cache
- THEN each `ForwardingRuleDTO` exposes `upstream_id` and MUST NOT contain `service_id`
