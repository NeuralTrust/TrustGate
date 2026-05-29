# Admin CRUD API Specification

## Purpose

Define the admin HTTP surface for the B.2 entities: REST endpoints
`POST/GET/PUT/DELETE /v1/<entity>` and `GET /v1/<entity>` listings,
backed by request DTOs in `pkg/api/handler/http/request/` and response
DTOs in `pkg/api/handler/http/response/`, with one action per handler
file in `pkg/api/handler/http/`, per `.agents/AGENT.md` §10.3 / §10.4.

## Requirements

### Requirement: One Action Per Handler File

Each `(action, entity)` pair (5 entities × 5 actions = 25 pairs) MUST
live in its own file named `<action>_<entity>_handler.go` (e.g.
`create_gateway_handler.go`). A handler file MUST contain exactly one
exported handler struct, exactly one constructor, and exactly one
exported `Handle` method.

#### Scenario: Audit of handler folder

- GIVEN `pkg/api/handler/http/`
- WHEN files are inspected
- THEN exactly 25 `<action>_<entity>_handler.go` files exist (plus the
  pre-existing `health_handler.go` and `version_handler.go`)
- AND no aggregated `<entity>_handler.go` file lists multiple actions

### Requirement: One DTO Per File

Each request DTO MUST live in
`pkg/api/handler/http/request/<action>_<entity>_request.go` (e.g.
`create_gateway_request.go`, `list_gateway_request.go`). Each response
DTO MUST live in `pkg/api/handler/http/response/<entity>_response.go`
or `list_<entity>_response.go`. A DTO file MUST contain exactly one
exported struct.

#### Scenario: Audit of request folder

- GIVEN `pkg/api/handler/http/request/`
- WHEN files are inspected
- THEN each file contains exactly one exported struct
- AND no `common_request.go` or `shared.go` aggregating multiple DTOs
  exists

### Requirement: Route Surface

The admin router MUST expose the following routes per entity (replacing
`<entity>` with `gateways`, `backends`, `consumers`, `policies`,
`auths`):

| Method | Path | Handler |
|---|---|---|
| `POST`   | `/v1/<entity>`       | Create |
| `GET`    | `/v1/<entity>`       | List   |
| `GET`    | `/v1/<entity>/:id`   | Get    |
| `PUT`    | `/v1/<entity>/:id`   | Update |
| `DELETE` | `/v1/<entity>/:id`   | Delete |

The pluralised path segment is canonical. The proxy router MUST NOT
expose any of these routes.

#### Scenario: Admin route is reachable

- GIVEN the admin server is running
- WHEN a `GET /v1/gateways` request is issued with a valid filter
- THEN the response is a JSON envelope containing `items`, `page`,
  `size`, `total`

#### Scenario: Same route on proxy is not reachable

- GIVEN the proxy server is running on its own port
- WHEN a `GET /v1/gateways` request is issued
- THEN the response is `404 Not Found`

### Requirement: Request Validation

Each request DTO MUST expose a `Validate() error` method. Handlers MUST
call it after `c.BodyParser` (or after path/query extraction) and MUST
short-circuit with HTTP `422 Unprocessable Entity` on failure.

#### Scenario: Missing required field on create

- GIVEN a `POST /v1/gateways` body with `name = ""`
- WHEN the handler runs
- THEN the response status is `422`
- AND the response body explains which field failed

#### Scenario: Invalid UUID path parameter

- GIVEN `GET /v1/gateways/not-a-uuid`
- WHEN the handler runs
- THEN the response status is `400`
- AND the response body identifies the bad parameter

### Requirement: Response Shape

| Status | Path | Body |
|---|---|---|
| `201` | `POST /v1/<entity>` | Single-item `<Entity>Response` JSON |
| `200` | `GET /v1/<entity>/:id` | Single-item `<Entity>Response` JSON |
| `200` | `GET /v1/<entity>` | `{ "items": [...], "page": N, "size": N, "total": N }` |
| `200` | `PUT /v1/<entity>/:id` | Single-item `<Entity>Response` JSON |
| `204` | `DELETE /v1/<entity>/:id` | Empty |
| `404` | any verb on missing id | `{ "error": "not_found" }` |
| `409` | create conflict / delete-with-deps | `{ "error": "already_exists" }` or `{ "error": "has_dependents" }` |
| `422` | validation failure | `{ "error": "<field>: <reason>" }` |
| `500` | unexpected | `{ "error": "internal_error" }` |

#### Scenario: Create returns 201 with body

- GIVEN a valid `POST /v1/gateways` body
- WHEN the handler runs successfully
- THEN the response status is `201`
- AND the response body matches `GatewayResponse` (id, name,
  description, created_at, updated_at)

#### Scenario: Delete returns 204

- GIVEN a valid `DELETE /v1/gateways/:id` for a present aggregate
- WHEN the handler runs successfully
- THEN the response status is `204` with an empty body

### Requirement: Domain-Error Mapping

A single helper (`pkg/api/handler/http/helpers/errors.go`) MUST map
domain sentinel errors to HTTP statuses + payloads. Handlers MUST NOT
hand-craft this mapping.

#### Scenario: Repository returns ErrNotFound

- GIVEN the use case returns `gateway.ErrNotFound`
- WHEN the handler resolves the error
- THEN `MapDomainError` returns `(404, {"error": "not_found"})`

### Requirement: Pagination Defaults

`GET /v1/<entity>` MUST default to `page=1`, `size=20`. `size` MUST be
clamped at a maximum of 200. `page=0` or `size=0` MUST be rejected with
`422`.

#### Scenario: No pagination params

- GIVEN `GET /v1/gateways` without `page` or `size`
- WHEN the handler runs
- THEN the listing uses `page=1, size=20`

#### Scenario: Size above maximum

- GIVEN `GET /v1/gateways?size=10000`
- WHEN the handler runs
- THEN the listing uses `size=200`

### Requirement: Substring Name Filter

`GET /v1/<entity>?name=<substring>` MUST return only rows whose `name`
column contains the substring (case-insensitive). An empty `name`
parameter MUST be ignored (no filter).

#### Scenario: Filtering by substring

- GIVEN gateways named `alpha`, `beta`, `alphabet`
- WHEN `GET /v1/gateways?name=alph` runs
- THEN the response contains `alpha` and `alphabet` only

### Requirement: Admin-Only Wiring

Handlers MUST be registered exclusively in the admin transport (`server_admin`
module). They MUST NOT appear in the proxy transport (`server_proxy`
module).

#### Scenario: Module audit

- GIVEN `pkg/container/modules/server_admin.go` and
  `pkg/container/modules/server_proxy.go`
- WHEN imports and provided types are inspected
- THEN the new CRUD handlers appear only in the admin module
