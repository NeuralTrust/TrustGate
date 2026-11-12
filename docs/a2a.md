# A2A agent plane

The agent plane (`./trustgate agent`) puts [A2A](https://a2a-protocol.org)
agents behind a gateway. An application calls an agent through the gateway
with its consumer credential; the gateway checks the call, runs the
consumer's policies, binds tasks to their caller and forwards the JSON-RPC
call with the registry's own credential.

The plane speaks JSON-RPC only, A2A versions 0.3 and 1.0. Each registry is
pinned to one version and the gateway never translates between them.

Everything below applies to every agent. Agents hosted on Amazon Bedrock
AgentCore, Microsoft Foundry or Google Vertex AI Agent Engine differ only as
described in [Hosted agents](#hosted-agents). Agents that do not speak A2A (an
AgentCore harness, a Databricks agent) are reached through their provider's
API, as described in [Translated agents](#translated-agents).

## Running the plane

| Variable | Where | Meaning |
|---|---|---|
| `SERVER_AGENT_PORT` | agent | Listen port. Default `8084`. |
| `AGENT_BASE_DOMAIN` | admin, MCP | Suffix of the agent host, `{gateway_slug}.{AGENT_BASE_DOMAIN}`. Unset means the environment offers no agents: `hosts.agent` is absent and `/whoami` lists no agent URLs. |
| `STS_SIGNING_KEY` | agent (and MCP) | RSA key that signs delegation tokens and backs `/.well-known/jwks.json`. With no key outside prod each pod generates its own, and `delegation` is refused (`-32092`, `signing_key_unavailable`). In prod an unset key is read from the key shared in Redis. |
| `STS_ISSUER` | agent, admin | `iss` of delegation tokens. Default `trustgate`. |
| `CONFIG_SYNC_DATA_PLANE_ENABLED` | agent | `true` runs the plane DB-less from the config snapshot, like `proxy` and `mcp`. `/readyz` answers 503 until a snapshot is loaded. |

The plane needs Redis for task ownership. Its routes:

| Route | |
|---|---|
| `GET /health`, `/healthz`, `/readyz` | Health, as on the other planes |
| `GET /.well-known/jwks.json` | Keys that verify delegation tokens |
| `GET /{consumer}/agents/{agent}/.well-known/agent-card.json` | The pinned card, rewritten |
| `POST /{consumer}/agents/{agent}` | JSON-RPC |

`{consumer}` is the consumer slug. `{agent}` is the registry id, or its name
when exactly one enabled A2A registry of the consumer has that name. Anything
else is 404.

`GET /v1/gateways/{id}` publishes the host and, with it, the issuer agents
should expect:

```json
{
  "hosts": {
    "proxy": "acme.llm.example.com",
    "mcp": "acme.mcp.example.com",
    "agent": "acme.agents.example.com"
  },
  "agent_token_issuer": "trustgate"
}
```

Both fields are absent when `AGENT_BASE_DOMAIN` is not set.

## Setup

1. Preview the card (nothing is written):

   ```http
   POST /v1/gateways/{gateway_id}/registries/preview-agent-card
   {"card_url": "https://travel.example.com"}
   ```

   ```json
   {
     "resolved_card_url": "https://travel.example.com/.well-known/agent-card.json",
     "card": {"name": "Travel planner"},
     "card_digest": "sha256:…",
     "versions": ["0.3", "1.0"],
     "default_version": "1.0"
   }
   ```

2. Register the agent:

   ```http
   POST /v1/gateways/{gateway_id}/registries
   {
     "name": "Travel planner",
     "type": "A2A",
     "a2a_target": {
       "card_url": "https://travel.example.com",
       "auth": {"mode": "exchange", "pattern": "delegation"}
     }
   }
   ```

   | `a2a_target` field | |
   |---|---|
   | `card_url` | Card URL or the agent's base URL. `https`; `http` only with `OUTBOUND_ALLOW_PRIVATE_NETWORKS`. |
   | `protocol_version` | `"0.3"` or `"1.0"`. Default: `1.0` when the card offers it, else `0.3`. |
   | `url` | `https` endpoint that replaces the one the card names. |
   | `headers` | Static headers sent to the agent. `Authorization`, `Cookie`, `Host`, `Content-Length`, `A2A-Version` and `X-AG-*` are refused. |
   | `auth` | See [Identity](#identity). Default `none`. |
   | `allowed_methods` | Forwarded methods of the pinned version. Any other method answers `-32601`. |

   The response adds the read-only `resolved_card_url`, `protocol_version`,
   `endpoint`, `card`, `card_digest` and `card_pinned_at`. Header values and
   auth secrets are encrypted at rest and masked in responses.

3. Create a consumer of type `A2A`, bind the registry and attach a key:

   ```http
   POST /v1/gateways/{gateway_id}/consumers
   {"name": "Research bot", "type": "A2A", "registries": [{"id": "{registry_id}"}]}
   ```

   An A2A consumer takes only A2A registries, and an A2A registry binds only
   to an A2A consumer.

4. Call the agent:

   ```bash
   curl https://acme.agents.example.com/research-bot/agents/{registry_id} \
     -H "X-AG-API-Key: $KEY" -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"Plan a trip"}]}}}'
   ```

   An A2A client can start from the card instead:
   `https://acme.agents.example.com/research-bot/agents/{registry_id}/.well-known/agent-card.json`.
   `GET /whoami` on the MCP host lists each A2A consumer's agents with these
   card URLs.

## Callers

The plane authenticates like the MCP plane:

- an API key in `X-AG-API-Key`, or `Authorization: Bearer ag_…`;
- a client certificate (mTLS or a trusted `X-Forwarded-Client-Cert`);
- a JWT from an identity provider configured on the gateway (`external_jwt` or introspection).

A bearer token without the `ag_` prefix is validated as a token even when an
`X-AG-API-Key` is also sent. MCP session tokens are not accepted.

With an API key or a certificate, `X-NeuralTrust-End-User: <user>` makes the
call run as that user of the application (`app:<consumer_id>:<user>`).
Without it the call runs as the application (`app:<consumer_id>`). A token
runs as its own subject.

| Status | When |
|---|---|
| 401 | No valid credential |
| 403 | The credential is not attached to the consumer, or the consumer's `auth_binding` refuses the caller |
| 404 | Unknown consumer or agent, a consumer that is not A2A, or a disabled registry |

All three are answered before the body is parsed and before any call to the agent.

`scripts/a2a-user-check.sh` calls an agent the way an application does: it
reads the card, sends a message, reads the task back, and checks the 401, the
refused methods and, with a second application's key, task ownership.

```bash
AGENT_URL=https://<gateway>.agents.<domain>/<consumer>/agents/<agent> \
API_KEY=<the application's key> \
API_KEY_2=<another application's key> \
scripts/a2a-user-check.sh
```

## Card pinning

For a `card_url` whose path ends in `.json` or `/agentCard/v1.0` the gateway
reads that URL. Otherwise it tries, in order,
`/.well-known/agent-card.json`, `/.well-known/agent.json` and
`/agentCard/v1.0` under it and keeps the first JSON object. Each read goes
through the outbound network guard, with 10 s in total and 1 MiB per
response.

The card must have `name` and offer the chosen version:

- 0.3: `url` with a `protocolVersion` starting with `0.3` (or none), or an
  `additionalInterfaces` entry with `transport: "JSONRPC"`;
- 1.0: a `supportedInterfaces` entry with `protocolBinding: "JSONRPC"` and a
  `protocolVersion` starting with `1.0`.

`card_digest` is `sha256:` over the card without `signatures`, keys sorted.

The plane always serves the pinned card, never the live one, with:

- the gateway's URL as the only JSON-RPC interface;
- the gateway API key (`X-AG-API-Key`) as the only security scheme, and no per-skill security;
- push notifications and the extended card turned off;
- `signatures` removed, and the other version's interface and security fields.

Other fields are kept. The card requires the same credential as a call.

An update re-reads and re-pins the card only when `card_url` or
`protocol_version` changes. To take a new card from the same URL:

```http
POST /v1/gateways/{gateway_id}/registries/{id}/agent-card/refresh
```

```json
{
  "changed": true,
  "pinned_digest": "sha256:…",
  "fetched_digest": "sha256:…",
  "changed_fields": ["skills"],
  "skills_added": ["refund_invoice"],
  "skills_removed": [],
  "fetched_card": {}
}
```

Refresh writes nothing. Approve pins the card only if the live card still
has the digest you reviewed:

```http
POST /v1/gateways/{gateway_id}/registries/{id}/agent-card/approve
{"digest": "sha256:…"}
```

| Answer | When |
|---|---|
| 200 | Pinned, or the digest is already pinned |
| 409 | The live card has another digest |
| 422 | The registry is not A2A, or the new card no longer offers the pinned version |

## Identity

`a2a_target.auth.mode`:

| Mode | The agent receives |
|---|---|
| `none` | No credential |
| `static` | `header: value` |
| `client_credentials` | `Authorization: Bearer` with a token from `token_url`, cached until shortly before it expires |
| `exchange` + `pattern: "delegation"` | `Authorization: Bearer` with a JWT signed by the gateway |
| `exchange` + `pattern: "obo"` | An Entra token for the user, obtained on-behalf-of (`scope` required) |
| `exchange` + `pattern: "token_exchange"` | A token from the user's IdP by RFC 8693 |

`passthrough`, `forwarded` and `exchange`/`impersonation` are refused with
422: the caller's own credential never reaches an agent, and the agent must
know which application acts.

`obo` and `token_exchange` need a caller authenticated by an identity
provider. An API key, with or without `X-NeuralTrust-End-User`, gets
`-32093`. A refused exchange answers `-32092` (`identity_exchange_failed`).

### Delegation token

| Claim | Value |
|---|---|
| `iss` | `STS_ISSUER` (`agent_token_issuer` on the gateway) |
| `aud` | `auth.audience`, else the agent endpoint the gateway calls |
| `sub` | The caller: the IdP subject, `app:<consumer_id>:<user>`, or `app:<consumer_id>` |
| `act` | `{"sub": "app:<consumer_id>"}` when `sub` is a user; absent for the application |
| `orig_iss` | The IdP issuer, only when an IdP authenticated the caller |
| `scope` | The caller's scopes, when it has any |
| `iat`, `exp`, `jti` | Lifetime 5 minutes |

Signed RS256 with the `kid` of a key in
`https://{gateway_slug}.{AGENT_BASE_DOMAIN}/.well-known/jwks.json`.

Verifying it in the agent (Python, PyJWT):

```python
import jwt

jwks = jwt.PyJWKClient("https://acme.agents.example.com/.well-known/jwks.json")

def caller(authorization: str) -> dict:
    token = authorization.removeprefix("Bearer ")
    key = jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256"],
                      issuer="trustgate",                  # agent_token_issuer
                      audience="https://travel.example.com/a2a")  # this agent's endpoint
```

## What reaches the agent

The call goes to the pinned endpoint (or `url`) with the caller's JSON-RPC
body unchanged and:

- the registry's credential and static headers;
- `Content-Type` and `Accept`;
- `A2A-Version: 1.0` on 1.0 registries;
- `X-AG-Trace-Id`;
- the caller's `X-A2A-Extensions` (0.3) or `A2A-Extensions` (1.0).

No other caller header is sent: not `Authorization`, `Cookie` or any `X-AG-*`.
The response keeps the caller's JSON-RPC `id`.

## Methods

| 0.3 | 1.0 | |
|---|---|---|
| `message/send` | `SendMessage` | Forwarded |
| `message/stream` | `SendStreamingMessage` | Forwarded as server-sent events; `-32004` when the card does not declare `capabilities.streaming` |
| `tasks/get` | `GetTask` | Forwarded |
| `tasks/cancel` | `CancelTask` | Forwarded |
| `tasks/resubscribe` | `SubscribeToTask` | Forwarded as server-sent events |
| `tasks/pushNotificationConfig/{set,get,list,delete}` | `{Create,Get,Delete}TaskPushNotificationConfig`, `ListTaskPushNotificationConfigs` | Refused, `-32003` |
| `agent/getAuthenticatedExtendedCard` | `GetExtendedAgentCard` | Refused, `-32007` |
| — | `ListTasks` | Refused, `-32004` |

A method of the other version, or an unknown one, answers `-32601`. Refused
calls never reach the agent.

## Task ownership

A task or context belongs to the consumer and subject that first received it
from the agent: the application, or the user it named, or the IdP user. Two
keys of one application share their tasks; two users of one application do
not.

- Before `tasks/get`, `tasks/cancel`, `tasks/resubscribe` (and the 1.0 names)
  and before a message that names a `taskId`, a `contextId` or tasks in
  `referenceTaskIds`, the gateway checks the owner. Another owner, or none,
  answers `TaskNotFoundError` (`-32001`) without calling the agent. A new
  conversation sends no `contextId`; the agent assigns it. A referenced task
  is only checked: the answer does not bind it again.
- Each task or context id an answer or stream event names is recorded for the
  caller in Redis for 7 days, renewed whenever an answer names it again.
- An answer naming an id another caller owns is not delivered (`-32092`,
  `ownership_conflict`), and none of the ids it names is recorded.
- Redis unreadable: `-32092` (`ownership_unavailable`), nothing sent.
  Unwritable: the answer is delivered and the failure logged; later calls on
  that task get `-32001`.

## Policies

Only plugins that declare A2A attach to an A2A consumer: `rate_limiter`,
`request_size_limiter` and `trustguard` (not `trustguard_v2`). Global
policies of other plugins are left out of A2A plans.

Plugins see a normalised body, the same for both versions:

```json
{"method": "message/send", "agent": "Travel planner",
 "parts": [{"type": "text", "text": "…"},
           {"type": "data", "data": {}},
           {"type": "file", "url": "…", "media_type": "application/pdf", "filename": "a.pdf"}]}
```

`pre_request` sees the message parts. `pre_response` sees the parts of a
Message answer, or of a Task's status message, artifacts and agent messages
in its history. `request_size_limiter` measures the JSON-RPC body as it is
sent to the agent, metadata and configuration included.

A part the gateway cannot read fails the call rather than reaching the
policies unchecked: a `parts`, `artifacts` or `history` that is not a list,
an item that is not an object, a text that is not a string, or a part of no
known kind. In a request that answers `-32602`; in an answer or a stream
event, `-32092` `invalid_upstream_response`.

A `tasks/cancel` (`CancelTask`) answer is relayed with the task's state only:
its artifacts, history and status message are removed. Read them with
`tasks/get`, where `pre_response` runs.

A block, or a mask verdict (the gateway does not rewrite parts), answers
`-32090` instead of calling the agent or instead of its answer. In a stream
each event with content is checked before it is relayed. A blocked event is
replaced by a `-32090` event, the stream is closed and the gateway sends
`tasks/cancel` (`CancelTask`) for the task to the agent. Artifact chunks
sent with `append` are checked one by one, so content split across two chunks
can pass.

## Limits

| Limit | Value | On breach |
|---|---|---|
| Request body | 8 MiB | 413 |
| Tasks one message references (`referenceTaskIds`) | 32 | `-32602` |
| Buffered answer | 8 MiB | `-32092` `response_too_large` |
| Buffered call | 300 s | `-32092` `upstream_timeout` |
| One stream event, all its `data:` lines together | 1 MiB | `-32092` `response_too_large`, stream closed |
| Agent opens no stream | 120 s | `-32092` `upstream_timeout` |
| Agent answers a stream call with a JSON body | 300 s to read it | `-32092` `upstream_timeout` |
| Silence between stream events | 120 s | `-32092` `stream_idle`, stream closed |
| Stream duration | 55 min | `-32092` `stream_max_duration`, stream closed; continue with `tasks/resubscribe` or `SubscribeToTask` |
| Ownership record | 7 days after an answer last named the id | `-32001` |

These values are fixed. Keep the load balancer's backend timeout above
55 minutes (the bundled manifests use 3600 s).

## Errors

JSON-RPC errors are answered with HTTP 200, except 401, 403 and 404 above,
413, and 402 when the gateway's usage plan is exhausted (`-32092`,
`plan_unavailable`).

| Code | Meaning | `error.data` |
|---|---|---|
| `-32700` | Body is not JSON | |
| `-32600` | Not a single JSON-RPC 2.0 request with an `id`, `Content-Type` is not `application/json`, or the request, its `params`, `message` or `configuration` or one of its parts names a key twice (ignoring case and underscores) | |
| `-32601` | Method not of the pinned version, unknown, or outside `allowed_methods` | |
| `-32602` | Params lack the message or the task `id`, `referenceTaskIds` is not a list of up to 32 strings, or a part cannot be read | |
| `-32001` | Task or context not found or not the caller's | 1.0: `ErrorInfo` with `TASK_NOT_FOUND` |
| `-32003` | Push notifications refused | |
| `-32004` | `ListTasks`, or streaming on an agent without it | |
| `-32007` | Extended card refused | |
| `-32090` | Blocked by a policy | `{"reason": "policy_blocked" \| "mask_unsupported", "plugin": "<slug>"}` |
| `-32091` | Rate limited | `{"retry_after": <seconds>}` |
| `-32092` | The gateway could not complete the call | `{"reason": "<reason>"}` |
| `-32093` | The identity mode needs an IdP user | `{"reason": "identity_required"}` |

`-32092` reasons: `upstream_unreachable`, `upstream_timeout`,
`upstream_error`, `invalid_upstream_response`, `response_too_large`,
`stream_idle`, `stream_max_duration`, `ownership_unavailable`,
`ownership_conflict`, `client_credentials_failed`,
`identity_exchange_failed`, `signing_key_unavailable`, `plan_unavailable`,
`cloud_auth_failed` and `upstream_auth_failed` (hosted agents).

An error the agent itself answers is relayed as it came.

Each call records an `a2a` span: registry, agent, method, version, task and
context ids, task state, the agent's HTTP status, outcome (`ok`, `blocked`,
`refused`, `not_found`, `upstream_error`, `upstream_timeout`), the blocking
plugin, the reason, and the identity mode and subject kind (`user` or `app`),
never the token.

## Hosted agents

`a2a_target.provider` is `bedrock_agentcore`, `azure_foundry` or
`vertex_agent_engine`. The agent is located by the provider's own ids, never a
URL; the gateway derives the card URL and the endpoint and sends cloud
credentials only to that host over HTTPS.

| | `bedrock_agentcore` | `azure_foundry` | `vertex_agent_engine` |
|---|---|---|---|
| Locator | `runtime_arn`, `qualifier` (default `DEFAULT`) | `project_endpoint` (`*.services.ai.azure.com`), `agent_name` | `project`, `location`, `reasoning_engine_id` |
| `auth.mode` | `cloud` (`cloud_auth.aws`: keys, `use_role` + `role` + `external_id`, or the pod's identity), `client_credentials`, `exchange` `obo`/`token_exchange` | `cloud` (`cloud_auth.azure`: service principal or managed identity), `exchange` `obo` | `cloud` (`cloud_auth.gcp`: `service_account_json`, `impersonate_service_account`, or ADC) |
| Gateway sends | SigV4 (`bedrock-agentcore`) or a Bearer token | Entra token, scope `https://ai.azure.com/.default`, and `A2A-Version` on every call | Google token, scope `cloud-platform` |
| Versions | From the card | 1.0 (default) and 0.3 | 0.3 |
| Streaming | As the card says | No | No |

- The card is read with the registry's credential. With `obo` or
  `token_exchange` there is no user at registration, so `card_auth`
  (`client_credentials` on AgentCore, `cloud` on Foundry) names the
  application credential that reads it.
- On SaaS gateways an assumed AWS role needs `external_id` (422 otherwise).
- AgentCore: the gateway generates `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`
  per context and keeps it with the context's owner. JSON-RPC errors are read
  from non-2xx answers; `-32054` "Session operation in progress" is retried
  twice (100 ms, 400 ms) on buffered calls; 401 is `-32093` and a bare 403 is
  `-32092` `upstream_auth_failed`.
- Vertex speaks HTTP+JSON. Callers still use JSON-RPC 0.3 (`message/send`,
  `tasks/get`, `tasks/cancel`); the gateway calls `/v1/message:send`,
  `/v1/tasks/{id}` and `/v1/tasks/{id}:cancel`. Not yet verified against a
  deployed Agent Engine.
- A credential the gateway cannot obtain answers `-32092` `cloud_auth_failed`.

## Translated agents

`a2a_target.provider` is `agentcore_harness` or `databricks_agent`. These
agents do not speak A2A: the gateway turns each `message/send` into a call to
the provider's own API and the answer into an A2A 0.3 message. They publish no
card, so the gateway builds one (the agent's name, a single `chat` skill,
A2A 0.3, no streaming) and pins it like any other.

| | `agentcore_harness` | `databricks_agent` |
|---|---|---|
| Locator | `harness_arn` (`arn:aws:bedrock-agentcore:{region}:{account}:harness/{name}-{id}`), `qualifier` (default `DEFAULT`) | `workspace_url`, and `serving_endpoint` (Model Serving) or `app_url` (`*.databricksapps.com`) |
| `auth.mode` | `cloud` (`cloud_auth.aws`, as an AgentCore runtime) | `client_credentials` (a service principal; `token_url` defaults to `{workspace_url}/oidc/v1/token`, `scopes` to `all-apis`), or `static` (`Authorization: Bearer` a personal access token) |
| Gateway calls | `POST /harnesses/invoke` (InvokeHarness), SigV4 `bedrock-agentcore` | `POST {workspace_url}/serving-endpoints/{serving_endpoint}/invocations`, or `POST {app_url}/responses` |
| Sends | `messages: [{role: user, content: [{text}]}]` | `input: [{role: user, content}]`, `context.conversation_id` |
| Reads | The text deltas of the event stream's assistant messages | The `output_text` of the `message` output items |

- Only `message/send` is forwarded. There are no tasks, so `tasks/get` and
  `tasks/cancel` answer `-32004`, and `message/stream` is refused since the
  card does not stream.
- The message's text parts, and its data parts as JSON, are sent as one text.
  A file part answers `-32005`.
- The conversation is the call's `contextId`, or a new one the reply carries.
  It is bound to its owner like any context. On a harness it is the runtime
  session (`X-Amzn-Bedrock-AgentCore-Runtime-Session-Id`), so the harness keeps
  the history. A Databricks agent gets it as `context.conversation_id` and
  keeps the history only if it stores it under that id.
- An error the agent answers (a harness `runtimeClientError`, a Databricks
  400) is `-32603` with the agent's message; a refused credential is `-32092`
  `upstream_auth_failed`.
