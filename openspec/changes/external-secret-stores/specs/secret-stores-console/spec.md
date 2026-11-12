# Specification: secret-stores-console

## Purpose

How the console (`NeuralTrust/app`) exposes secret stores. The same code runs
on NeuralTrust SaaS and on self-hosted and central installs
(`DEPLOYMENT_MODE=external`). Whether the feature appears, and where tests run,
is decided by the admin's `supported` and `source` fields, never by the
console's own mode.

The console never asks for, stores or displays a secret value or a store
credential.

## Requirements

### Requirement: Secret stores tab

Settings → Gateway MUST show a "Secret stores" tab when
`GET /v1/gateways/:gateway_id/secret-stores` returns `supported: true`. It MUST
be hidden otherwise.

The header MUST say where the stores are configured:
- for source `data_plane`: in the Helm values of the gateway's data plane;
- for source `control_plane`: in the platform's Helm values.

Each row MUST show:
- the name;
- the type;
- the allowed paths;
- the aggregated status (`ok`, `degraded`, `down` or `not_reported`), with a
  warning when `consistent=false`;
- the number of usages;
- the time of the last check.

The row detail MUST show:
- the state of each instance, with a hint for each error class;
- the usages, each linked to its entity;
- a "Test a secret" action.

#### Scenario: NeuralTrust SaaS hosted gateway

- GIVEN a hosted gateway on NeuralTrust SaaS (`supported: false`)
- WHEN its settings are opened
- THEN no "Secret stores" tab is shown

#### Scenario: Self-hosted gateway

- GIVEN an on-prem console whose admin returns `supported: true, source: control_plane`
- WHEN any gateway's settings are opened
- THEN the tab is shown, and its header points to the platform's Helm values

### Requirement: Tests run where the store lives

"Test a secret" MUST be routed the same way as registry test-connection:
- **Hybrid gateway:** a server action calls the data plane's
  `/__diagnostics/gateways/:gateway_id/secret-stores/:name/test` on the
  configured data-plane URL, with a diagnostics token.
- **Any other gateway:** the console calls the admin's
  `POST /v1/gateways/:gateway_id/secret-stores/:name/test`.

The result MUST show the outcome, the error class mapped to a message, the
version and the latency. It MUST NOT show a secret value.

#### Scenario: Hybrid data plane unreachable

- GIVEN a hybrid gateway whose data-plane URL does not answer
- WHEN a secret is tested
- THEN the console reports that the data plane did not answer, and nothing is tested on the control plane

### Requirement: Add a secret store generator

"Add a secret store" MUST be a generator that saves nothing.

Inputs:
- name, type, allowed paths and the type's connection and auth fields;
- *Gateways*, prefilled with the current gateway;
- advanced cache settings.

No input MUST accept a secret value. Static Vault credentials MUST be
referenced by Kubernetes Secret name and key. The default auth MUST be the
type's keyless method.

Output:
- the `agentgateway.secretStores` snippet, plus the ServiceAccount annotation
  when needed;
- least-privilege prerequisites built from the allowed paths;
- the `helm upgrade` command;
- which values file the snippet belongs to: the data plane's values for
  `data_plane`, the platform's values for `control_plane`.

The generator MUST then poll the listing until the store is reported `ok`, or
show the reported error class.

#### Scenario: AWS store generated

- GIVEN type AWS Secrets Manager, name `aws`, region `eu-west-1`, allowed path `prod/llm/`, role ARN R, and current gateway G
- WHEN the output is shown
- THEN it includes the store with `gateways: [G]`, the annotation `eks.amazonaws.com/role-arn: R`, and an IAM policy granting `secretsmanager:GetSecretValue` on `arn:aws:secretsmanager:eu-west-1:<account>:secret:prod/llm/*`

### Requirement: SecretInput

When the gateway is `supported`, every form field marked `secret: true` MUST
render a `SecretInput` with two modes: "Value" and "From secret store".
- **Phase 1:** provider auth, the GCP service account, MCP secret headers and
  the OAuth client secret.
- **Phase 2:** policy credentials and telemetry headers.

The "From secret store" mode MUST offer:
- a store selector, listing the gateway's available stores with their status;
- a path field, with the allowed prefixes as a hint and an inline check;
- an optional key;
- an optional version, under an advanced section;
- a read-only preview of the `secret://…` reference;
- a "Test" action, routed as in the tab.

A stored reference MUST open in "From secret store" mode, already filled in. A
literal MUST open in "Value" mode, masked as today. When the source is
`data_plane` and no connection is live, the store name MUST be accepted as free
text, with a warning.

#### Scenario: Editing a referenced key

- GIVEN registry R whose `api_key` is `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN R is opened for editing
- THEN the field is in "From secret store" mode, with store `corp-vault`, path `ai-gateway/openai` and key `api_key`

#### Scenario: Path outside the allowed prefixes

- GIVEN store `corp-vault` with `allowed_paths: ["ai-gateway/"]`
- WHEN the user types path `payments/db`
- THEN an inline error is shown and submit is disabled

### Requirement: Indicators and audit

- Registry and MCP cards whose credentials are references MUST show a "from
  `<store>`" badge.
- From Phase 2, those cards MUST show a warning when a reference is reported as
  failing.
- Console actions that set a reference MUST be audited through
  `logV2AuditEvent`. The audit entry MUST carry the store and the path, and no
  value.

#### Scenario: Failing reference warning

- GIVEN R's reference is reported as `not_found` (Phase 2)
- WHEN the registry list is shown
- THEN R's card shows a warning that links to the store and the path
