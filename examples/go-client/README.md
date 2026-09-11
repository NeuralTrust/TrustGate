# Go Client Example

Use [`sashabaranov/go-openai`](https://github.com/sashabaranov/go-openai) through TrustGate — set the base URL and TrustGate headers, then call chat completions as usual.

## Prerequisites

- TrustGate running locally (`make up` from repo root)
- A configured gateway, registry, and consumer (see [curl-first-request](../curl-first-request/) to set these up)
- Go 1.22+

## Setup

```bash
cd examples/go-client
go mod tidy
```

## Usage

Set your consumer credentials and run:

```bash
export CONSUMER_API_KEY="your-consumer-api-key"
export CONSUMER_SLUG="my-app"
export GATEWAY_SLUG="demo"

go run .
```

## How it works

TrustGate's proxy plane is OpenAI-compatible. Point go-openai at it and send the TrustGate routing headers on every request:

```go
cfg := openai.DefaultConfig("unused") // provider key lives in the registry
cfg.BaseURL = "http://localhost:8081/my-app" // /{consumer_slug}
cfg.HTTPClient = &http.Client{
    Transport: &headerRoundTripper{
        base: http.DefaultTransport,
        headers: map[string]string{
            "X-AG-Gateway-Slug": "demo",
            "X-AG-API-Key":     "<consumer api key>",
        },
    },
}
client := openai.NewClientWithConfig(cfg)
```

The SDK's `api_key` / config token is ignored for upstream auth — your provider key (OpenAI, Anthropic, etc.) is stored in the registry you configured via the Admin API.

## Headers

| Header | Purpose |
|--------|---------|
| `X-AG-Gateway-Slug` | Selects the gateway that owns the route |
| `X-AG-API-Key` | Authenticates the consumer |

## Other endpoints

The same consumer slug works for other OpenAI-compatible routes TrustGate exposes (chat, models, audio, images). See the [Python OpenAI SDK example](../openai-sdk/) for the full list.
