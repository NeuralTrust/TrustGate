# TrustGate quickstart demo

Short terminal walkthrough: bring up the stack, health-check the three planes, then send a chat completion through the proxy.

## Watch (placeholder)

A recorded GIF will land at [`assets/demo-quickstart.gif`](../../assets/demo-quickstart.gif) once recorded.

Until then, run the script below (or record it with [asciinema](https://asciinema.org/)):

```bash
# From repo root, with Docker available:
./docs/demo/record-quickstart.sh
```

## Record with asciinema

```bash
# Install: https://docs.asciinema.org/manual/cli/installation/
cd "$(git rev-parse --show-toplevel)"
asciinema rec docs/demo/quickstart.cast -c './docs/demo/record-quickstart.sh'
# Optional GIF (requires agg): agg docs/demo/quickstart.cast assets/demo-quickstart.gif
```

The cast file is optional to commit; the shell script is the source of truth so the demo stays honest as the CLI evolves.

## What the script shows

1. `make up` (or skip if already healthy)
2. `curl` healthz on Admin `:8080`, Proxy `:8081`, MCP `:8082`
3. Pointer to `examples/curl-first-request/` for a full chat completion (needs `OPENAI_API_KEY`)

No invented features — only commands already documented in the README and examples.
