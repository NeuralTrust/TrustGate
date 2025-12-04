package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestProviderLoadBalancer(t *testing.T) {
	subdomain := fmt.Sprintf("gateway-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      fmt.Sprintf("multi-provider-gateway-%d", time.Now().Unix()),
		"subdomain": subdomain,
	}
	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("ai-providers-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"provider":      "openai",
				"weight":        50,
				"priority":      1,
				"stream":        false,
				"default_model": "gpt-4o-mini",
				"models":        []string{"gpt-3.5-turbo", "gpt-4", "gpt-4o-mini"},
				"credentials":   map[string]string{"api_key": os.Getenv("OPENAI_API_KEY")},
			},
			// {
			// 	"provider":      "anthropic",
			// 	"weight":        50,
			// 	"priority":      1,
			// 	"stream":        false,
			// 	"default_model": "claude-sonnet-4-0",
			// 	"models":        []string{"claude-sonnet-4-0"},
			// 	"headers":       map[string]string{"anthropic-version": "2023-06-01"},
			// 	"credentials":   map[string]string{"api_key": os.Getenv("ANTHROPIC_API_KEY")},
			// },
			{
				"provider":      "google",
				"weight":        50,
				"priority":      1,
				"stream":        false,
				"default_model": "gemini-2.0-flash-001",
				"models":        []string{"gemini-2.0-flash-001"},
				"credentials":   map[string]string{"api_key": os.Getenv("GOOGLE_API_KEY")},
			},
		},
		"health_checks": map[string]interface{}{
			"passive":   true,
			"threshold": 3,
			"interval":  60,
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	servicePayload := map[string]interface{}{
		"name":        fmt.Sprintf("ai-chat-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Load balanced AI chat completion service",
		"upstream_id": upstreamID,
		"tags":        []string{"ai", "chat"},
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/v1",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)

	fmt.Println("Testing Provider Load Balancing...")
	openaiCount, googleCount := 0, 0
	totalRequests := 5

	for i := 1; i <= totalRequests; i++ {
		reqBody, err := json.Marshal(map[string]interface{}{
			"model":      "gpt-4o-mini",
			"messages":   []map[string]string{{"role": "user", "content": "Hello"}},
			"max_tokens": 1024,
		})
		assert.NoError(t, err, "Failed to marshal request body")

		req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/v1", bytes.NewReader(reqBody))
		assert.NoError(t, err, "Failed to create request")

		req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
		req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err, "Request execution failed")

		defer func() { _ = resp.Body.Close() }()

		assert.NotNil(t, resp, "Response should not be nil")
		assert.Contains(t, []int{http.StatusOK, http.StatusTooManyRequests}, resp.StatusCode, "Unexpected status code")

		selectedProvider := resp.Header.Get("X-Selected-Provider")
		assert.NotEmpty(t, selectedProvider, "X-Selected-Provider header should not be empty")

		switch selectedProvider {
		case "openai":
			openaiCount++
			fmt.Print("O")
		case "google":
			googleCount++
			fmt.Print("G")
		default:
			t.Fatalf("❌ Unexpected provider received: %s", selectedProvider)
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Validate Load Balancer Distribution
	fmt.Printf("\n✅ Results: OpenAI: %d, Google: %d\n", openaiCount, googleCount)
	assert.Greater(t, openaiCount, 0, "OpenAI should receive at least one request")
	assert.Greater(t, googleCount, 0, "Google should receive at least one request")
	assert.Equal(t, totalRequests, openaiCount+googleCount, "Total request count mismatch")

}
