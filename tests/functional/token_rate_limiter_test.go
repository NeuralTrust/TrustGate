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
					"window": map[string]interface{}{
						"unit": "minute",
						"max":  100,
					},
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
	time.Sleep(2 * time.Second)

	client := &http.Client{}

	t.Run("non-provider request passes through", func(t *testing.T) {
		body := bytes.NewBufferString(`{"input":"hello"}`)
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
	})

	t.Run("multiple non-provider requests all pass through", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			body := bytes.NewBufferString(fmt.Sprintf(`{"input":"request-%d"}`, i))
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/tokens", body)
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"request %d should pass through (no provider = no token limiting)", i+1)
		}
	})

	fmt.Println("\n Token Rate Limiter Functional Test Completed")
}

func TestTokenRateLimiterWithIdentifierHeader(t *testing.T) {
	defer RunTest(t, "TokenRateLimiter", time.Now())()
	subdomain := fmt.Sprintf("token-rl-hdr-%d", time.Now().Unix())

	gatewayPayload := map[string]interface{}{
		"name":      "Token RL Header Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "token_rate_limiter",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"identifier_header": "X-Client-ID",
					"window": map[string]interface{}{
						"unit": "hour",
						"max":  1000,
					},
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("echo-upstream-hdr-%d", time.Now().Unix()),
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
		"name":        fmt.Sprintf("token-rl-hdr-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Token RL header test service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/tokens-hdr",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)
	time.Sleep(2 * time.Second)

	client := &http.Client{}

	t.Run("requests with identifier header pass through (non-provider)", func(t *testing.T) {
		for _, clientID := range []string{"client-a", "client-b"} {
			body := bytes.NewBufferString(`{"input":"hello"}`)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/tokens-hdr", body)
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("X-Client-ID", clientID)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"client %s should pass through (no provider)", clientID)
		}
	})

	fmt.Println("\n Token Rate Limiter with Identifier Header Functional Test Completed")
}
