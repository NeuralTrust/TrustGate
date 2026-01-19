package functional_test

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenRateLimiter(t *testing.T) {
	defer RunTest(t, "TokenRateLimiter", time.Now())()
	subdomain := fmt.Sprintf("token-rl-%d", time.Now().Unix())

	gatewayPayload := map[string]interface{}{
		"name":      "Token Rate Limiter Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "token_rate_limiter",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"tokens_per_request":  5,
					"tokens_per_minute":   0,
					"bucket_size":         5,
					"requests_per_minute": 10,
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("echo-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/ping",
				"weight":   100,
				"priority": 1,
			},
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	servicePayload := map[string]interface{}{
		"name":        fmt.Sprintf("token-rl-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Token RL test service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/tokens",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)
	// wait a little for propagation
	time.Sleep(2 * time.Second)

	client := &http.Client{}

	// First request should pass (consume all 5 tokens)
	{
		body := bytes.NewBufferString("{\"input\":\"hello\"}")
		req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/tokens", body)
		assert.NoError(t, err)
		req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
		req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		// Basic headers should be present (set in PostResponse stage)
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Limit-Requests"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Limit-Tokens"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Remaining-Requests"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Remaining-Tokens"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Reset-Tokens"))
		assert.NotEmpty(t, resp.Header.Get("X-Tokens-Consumed"))
	}

	// Second request should be blocked due to insufficient tokens
	{
		body := bytes.NewBufferString("{\"input\":\"hello again\"}")
		req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/tokens", body)
		assert.NoError(t, err)
		req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
		req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
		// PreRequest stage sets headers too when limiting
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Limit-Requests"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Limit-Tokens"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Remaining-Requests"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Remaining-Tokens"))
		assert.NotEmpty(t, resp.Header.Get("X-Ratelimit-Reset-Tokens"))
	}

	fmt.Println("\n✅ Token Rate Limiter Functional Test Completed")
}
