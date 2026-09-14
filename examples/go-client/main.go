// TrustGate + go-openai example.
//
// Point sashabaranov/go-openai at TrustGate's proxy plane.
//
// Prerequisites:
//   - TrustGate running (make up)
//   - Gateway, registry, and consumer configured
//   - Environment variables:
//       CONSUMER_API_KEY - your consumer API key (required)
//       CONSUMER_SLUG    - consumer slug (default: my-app)
//       GATEWAY_SLUG    - gateway slug (default: demo)
//       PROXY_URL       - proxy URL (default: http://localhost:8081)
//
// Usage:
//   go run .
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	openai "github.com/sashabaranov/go-openai"
)

func main() {
	proxyURL := envOr("PROXY_URL", "http://localhost:8081")
	consumerSlug := envOr("CONSUMER_SLUG", "my-app")
	gatewaySlug := envOr("GATEWAY_SLUG", "demo")
	consumerAPIKey := os.Getenv("CONSUMER_API_KEY")
	if consumerAPIKey == "" {
		log.Fatal("CONSUMER_API_KEY environment variable is required.\n" +
			"Run examples/curl-first-request/first-request.sh to create one.")
	}

	cfg := openai.DefaultConfig("unused") // provider key lives in the registry
	cfg.BaseURL = fmt.Sprintf("%s/%s", proxyURL, consumerSlug)
	cfg.HTTPClient = &http.Client{
		Transport: &headerRoundTripper{
			base: http.DefaultTransport,
			headers: map[string]string{
				"X-AG-Gateway-Slug": gatewaySlug,
				"X-AG-API-Key":     consumerAPIKey,
			},
		},
	}

	client := openai.NewClientWithConfig(cfg)
	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: "You are a helpful assistant."},
			{Role: openai.ChatMessageRoleUser, Content: "What is TrustGate in one sentence?"},
		},
	})
	if err != nil {
		log.Fatalf("chat completion failed: %v", err)
	}
	if len(resp.Choices) == 0 {
		log.Fatal("chat completion returned no choices")
	}
	fmt.Println(resp.Choices[0].Message.Content)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// headerRoundTripper injects TrustGate routing headers on every request.
type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	for k, v := range t.headers {
		r.Header.Set(k, v)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}
