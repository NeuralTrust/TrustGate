# Proxy Forwarding Specification

## Purpose

Non-streaming proxy request forwarding and response handling for the AgentGateway proxy surface.

## Requirements

### Requirement: Non-Streaming Forwarding

The proxy forwarder MUST accept matched proxy requests, resolve the forwarding target through configured collaborators, and execute a non-streaming upstream/provider request. Streaming MUST NOT be activated in B.1.

#### Scenario: Forwarding succeeds

- GIVEN a proxy request resolves to an eligible target
- WHEN the forwarder handles the request
- THEN a non-streaming request is sent to the selected target
- AND the caller receives the target response

#### Scenario: Streaming is requested

- GIVEN a request asks for streaming behavior
- WHEN B.1 forwarding handles the request
- THEN streaming is not activated by the forwarder

### Requirement: Response Preservation

The proxy forwarder MUST preserve the upstream/provider response status, body, and safe response headers. Error responses MUST remain observable to the caller.

#### Scenario: Upstream returns success

- GIVEN the selected target returns a successful response
- WHEN the forwarder writes the response
- THEN the caller receives the upstream status, body, and safe headers

#### Scenario: Upstream returns an error

- GIVEN the selected target returns an error response
- WHEN the forwarder writes the response
- THEN the caller receives an error status and body derived from the upstream response

### Requirement: Deferred Behavior Guardrails

The proxy forwarder MUST NOT require plugin manager, auth, sessions, policy execution, audit SDK glue, or concrete B.2 repositories for B.1 non-streaming forwarding.

#### Scenario: Deferred collaborators are absent

- GIVEN plugin, auth, session, audit, and concrete repository collaborators are not configured
- WHEN a valid non-streaming proxy request is handled
- THEN forwarding can still complete through the configured B.1 collaborators

#### Scenario: Required B.1 collaborator is missing

- GIVEN a required forwarding collaborator is absent
- WHEN the forwarder is built or invoked
- THEN forwarding fails before sending an upstream/provider request
