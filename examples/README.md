# TrustGate Examples

Runnable examples for common TrustGate use cases.

## Prerequisites

All examples assume TrustGate is running locally:

```bash
# From the repo root
make up
```

This starts Admin (`:8080`), Proxy (`:8081`), and MCP (`:8082`) planes.

## Examples

| Example | Description |
|---------|-------------|
| [curl-first-request/](curl-first-request/) | Shell script: set up a gateway + consumer and make your first chat completion |
| [openai-sdk/](openai-sdk/) | Python: use the OpenAI SDK through TrustGate |
| [mcp-cursor/](mcp-cursor/) | Configure Cursor IDE to use TrustGate's MCP plane |

## Environment Variables

Most examples use these env vars (see `.env.example` in repo root):

| Variable | Description |
|----------|-------------|
| `ADMIN_TOKEN` | JWT for Admin API (see [Admin token](#admin-token)) |
| `OPENAI_API_KEY` | Your upstream OpenAI key (stored in the registry) |
| `CONSUMER_API_KEY` | Consumer API key (created via Admin API) |

### Admin Token

The Admin API requires a JWT signed with `SERVER_SECRET_KEY`:

```bash
export SERVER_SECRET_KEY="$(grep ^SERVER_SECRET_KEY .env | cut -d= -f2-)"
export ADMIN_TOKEN=$(python3 - <<'PY'
import jwt, os, time
secret = os.environ["SERVER_SECRET_KEY"]
print(jwt.encode({"sub": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600}, secret, algorithm="HS256"))
PY
)
```

Or use the helper script:

```bash
source scripts/generate_jwt_token.sh
```

## Adding Examples

We welcome new examples! Good candidates:
- Other language SDKs (TypeScript, Go, Java)
- Framework integrations (LangChain, LlamaIndex)
- Specific provider setups (Anthropic, Bedrock)

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
