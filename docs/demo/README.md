# TrustGate — Demo bootstrap (orchestrated from TrustGuard)

The **demo orchestrator lives in TrustGuard**, not in this repo:

```bash
# In TrustGuard repo
./scripts/demo/run.sh --env dev --team <APP_TEAM_UUID> --pack sales
```

TrustGate is provisioned via admin API calls from `TrustGuard/scripts/demo/lib/apply_gate.py`.

## Required deployment wiring

For Gateway → Runtime inspection (`trustguard` plugin), the TrustGate deployment must have platform OAuth credentials that match TrustGuard:

| TrustGate env | TrustGuard env |
|---------------|----------------|
| `TRUSTGUARD_CLIENT_ID` | `TRUSTGUARD_PLATFORM_CLIENT_ID` |
| `TRUSTGUARD_CLIENT_SECRET` | `TRUSTGUARD_PLATFORM_CLIENT_SECRET` |
| `TRUSTGUARD_BASE_URL` | Guard admin/public URL |

Without this, the plugin cannot call `/v1/evaluate` on behalf of the gateway.

## Variables for TrustGuard `profiles/dev.env`

Copy `docs/demo/dev.env.example` into TrustGuard `scripts/demo/profiles/dev.env` together with Guard vars.

| Variable | Description |
|----------|-------------|
| `GATE_ADMIN_URL` | Admin plane URL (e.g. `https://trustgate-admin.develop.neuraltrust.ai`) |
| `GATE_PROXY_URL` | Proxy plane URL (e.g. `https://trustgate.develop.neuraltrust.ai`) |
| `GATE_ADMIN_TOKEN` | Bearer JWT for admin API |
| `OPENAI_API_KEY` | Upstream OpenAI key for allow scenarios (block scenarios work without it) |

### Obtaining `GATE_ADMIN_TOKEN`

Use the same admin JWT flow as TrustGate Postman collections, or `scripts/generate_jwt_token.sh` in this repo with `SERVER_SECRET_KEY` matching the admin server.

## Smoke check (optional)

```bash
curl -sf "$GATE_ADMIN_URL/readyz"
curl -sf -H "Authorization: Bearer $GATE_ADMIN_TOKEN" "$GATE_ADMIN_URL/v1/gateways"
```

## Reference

- Postman: `postman/TrustGate-TrustGuard-E2E.postman_collection.json`
- TrustGuard demo docs: `TrustGuard/scripts/demo/docs/README.md`
- Linear: [RUN-957](https://linear.app/neuraltrust/issue/RUN-957)
