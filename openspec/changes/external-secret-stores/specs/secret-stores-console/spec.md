# Specification: secret-stores-console

## Purpose

How the console (`NeuralTrust/app`) exposes secret stores for hybrid gateways.
It shows:
- what the data plane reports;
- a guided generator for the Helm values and vault-side prerequisites;
- a secret input that can switch between a value and a reference.

The console never asks for, stores or displays a secret value or a store
credential.

## Requirements

### Requirement: Secret stores tab

Settings → Gateway MUST show a "Secret stores" tab for hybrid gateways when the
feature is enabled. The tab MUST be hidden for hosted and dedicated gateways.
- The tab MUST list the stores returned by `GET /v1/gateways/:gateway_id/secret-stores`.
- Each row MUST show:
  - name;
  - type;
  - allowed paths;
  - aggregated status (`ok`, `degraded`, `down` or `not_reported`), with a
    warning when `consistent=false`;
  - usages count;
  - last check.
- The row detail MUST show:
  - the per-instance state and a human hint for each error class;
  - the usages, each linking to its entity;
  - a "Test a secret" action.

#### Scenario: Hosted gateway

- GIVEN a hosted gateway
- WHEN its settings are opened
- THEN no "Secret stores" tab is shown

#### Scenario: Store reported with an auth error

- GIVEN the data plane reports `corp-vault` with state `auth_failed`
- WHEN the tab is opened
- THEN the row shows status `down`, and the detail suggests checking the vault auth role bound to the data plane's ServiceAccount

### Requirement: Test runs on the data plane

"Test a secret" MUST call the data plane's
`/__diagnostics/gateways/:gateway_id/secret-stores/:name/test` through a server
action, using the gateway's configured data-plane URL and a diagnostics token,
as hybrid test-connection does.
- The result MUST show the outcome, the error class mapped to a message, the
  version and the latency.
- It MUST NOT show a secret value.

#### Scenario: Data plane unreachable

- GIVEN the hybrid data plane URL does not answer
- WHEN a secret is tested
- THEN the console reports that the data plane did not answer, and nothing is tested from the control plane

### Requirement: Add a secret store generator

"Add a secret store" MUST be a generator that saves nothing in NeuralTrust.
- **Inputs.** Name, type, allowed paths, the connection and auth fields of the
  type, and advanced cache settings.
- **No secret inputs.** No input MUST accept a secret value. Static Vault
  credentials MUST be referenced by the name and key of a Kubernetes Secret.
- **Default auth.** It MUST be the type's keyless method: Vault Kubernetes auth,
  IRSA/Pod Identity, GKE Workload Identity or AKS Workload Identity.
- **Output:**
  - the `agentgateway.secretStores` values snippet, plus the ServiceAccount
    annotation when needed;
  - the vault-side least-privilege prerequisites built from the allowed paths:
    a Vault policy and role command, an IAM policy JSON, a `gcloud` binding or
    an `az role assignment`;
  - the `helm upgrade` command.
- **Waiting.** It MUST then poll the listing and show "waiting for your data
  plane to report `<name>`". It turns to success when the store is reported
  `ok`, or shows the reported error class.

#### Scenario: AWS store generated

- GIVEN type AWS Secrets Manager, name `aws`, region `eu-west-1`, allowed path `prod/llm/` and IAM role ARN R
- WHEN the generator output is shown
- THEN it includes a values snippet with the store and the annotation `eks.amazonaws.com/role-arn: R`, and an IAM policy granting `secretsmanager:GetSecretValue` on `arn:aws:secretsmanager:eu-west-1:<account>:secret:prod/llm/*`

### Requirement: SecretInput

On hybrid gateways with the feature enabled, every form field marked
`secret: true` MUST render a `SecretInput` with two modes: "Value" and "From
secret store". Phase 1 covers provider auth fields, the GCP service-account
field, MCP secret headers and the OAuth client secret. Phase 2 adds policy
credentials and telemetry headers.

"From secret store" mode MUST offer:
- a store selector listing the reported stores with their status;
- a path, with the store's allowed prefixes as a hint and an inline check;
- an optional key;
- an advanced, optional version with a type-aware placeholder;
- a read-only preview of the `secret://…` string;
- a "Test" action that runs on the data plane.

The mode MUST round-trip:
- a stored reference MUST open in "From secret store" mode, already filled in;
- a literal MUST open in "Value" mode, masked as today.

When no data plane is live, a free-text store name MUST be allowed with a
warning.

#### Scenario: Editing a referenced key

- GIVEN registry R whose `api_key` is `secret://corp-vault/ai-gateway/openai#api_key`
- WHEN R is opened for edit
- THEN the API key field is in "From secret store" mode with store `corp-vault`, path `ai-gateway/openai` and key `api_key`

#### Scenario: Path outside the allowed prefixes

- GIVEN store `corp-vault` reported with `allowed_paths: ["ai-gateway/"]`
- WHEN the user types path `payments/db`
- THEN the input shows an error before submit, and submit is disabled

### Requirement: Indicators and audit

Registry and MCP server cards whose credentials are references MUST show a
"from `<store>`" badge. From Phase 2, they MUST show a warning when the data
plane reports one of their references as failing. Every console action that
sets a reference MUST be audited through `logV2AuditEvent`, with the store and
the path and without any value.

#### Scenario: Failing reference warning

- GIVEN the heartbeat reports R's reference as `not_found` (Phase 2)
- WHEN the registry list is shown
- THEN R's card shows a warning that links to the reference's store and path
