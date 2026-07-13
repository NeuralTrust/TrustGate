---
type: feat
changelog: "Add Databricks, Fireworks, Oracle OCI, and Perplexity LLM registry providers."
---

# Proposal: Tier-2 LLM providers (Databricks, Fireworks, Oracle, Perplexity)

## Why

TrustGate v2 needs first-class registry providers for tier-2 upstreams exercised by the
multi-agent compatibility matrix: Databricks Model Serving, Fireworks, Oracle OCI
Generative AI (OpenAI-compatible), and Perplexity.

## What changes

- **Provider clients** under `pkg/infra/providers/{databricks,fireworks,oracle,perplexity}/`
- **Options decoding** in `pkg/infra/providers/options.go` (base URL, region, project)
- **Factory registration** and adapter format routing for OpenAI-compatible wire paths
- **Catalog** auth/options seeds for registry create UI and API validation

## Out of scope

- OAuth token refresh for Databricks route-optimized endpoints
- Oracle IAM signing (Generative AI API keys only)

## QA checklist

- [ ] `go test ./pkg/infra/providers/databricks/... ./pkg/infra/providers/fireworks/... ./pkg/infra/providers/oracle/... ./pkg/infra/providers/perplexity/...`
- [ ] Registry create with each provider via admin API or Postman
- [ ] `ag-matrix` cross-format cells for each new upstream (multi-agent-tests repo)
