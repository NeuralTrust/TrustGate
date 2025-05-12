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
				"path":          "/v1/chat/completions",
				"provider":      "openai",
				"weight":        50,
				"priority":      1,
				"stream":        true,
				"default_model": "gpt-4o-mini",
				"models":        []string{"gpt-3.5-turbo", "gpt-4", "gpt-4o-mini"},
				"credentials":   map[string]string{"header_name": "Authorization", "header_value": fmt.Sprintf("Bearer %s", os.Getenv("OPENAI_API_KEY"))},
			},
			{
				"path":          "/v1/messages",
				"provider":      "anthropic",
				"weight":        50,
				"priority":      1,
				"stream":        true,
				"default_model": "claude-3-5-sonnet-20241022",
				"models":        []string{"claude-3-5-sonnet-20241022"},
				"headers":       map[string]string{"anthropic-version": "2023-06-01"},
				"credentials":   map[string]string{"header_name": "x-api-key", "header_value": os.Getenv("ANTHROPIC_API_KEY")},
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
	openaiCount, anthropicCount := 0, 0
	totalRequests := 5

	for i := 1; i <= totalRequests; i++ {
		reqBody, err := json.Marshal(map[string]interface{}{
			"model":      "gpt-4o-mini",
			"messages":   []map[string]string{{"role": "user", "content": "Hello"}},
			"max_tokens": 1024,
			"stream":     true,
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

		defer resp.Body.Close()

		assert.NotNil(t, resp, "Response should not be nil")
		assert.Contains(t, []int{http.StatusOK, http.StatusTooManyRequests}, resp.StatusCode, "Unexpected status code")

		selectedProvider := resp.Header.Get("X-Selected-Provider")
		assert.NotEmpty(t, selectedProvider, "X-Selected-Provider header should not be empty")

		if selectedProvider == "openai" {
			openaiCount++
			fmt.Print("O")
		} else if selectedProvider == "anthropic" {
			anthropicCount++
			fmt.Print("A")
		} else {
			t.Fatalf("❌ Unexpected provider received: %s", selectedProvider)
		}

		time.Sleep(100 * time.Millisecond)
	}

	// Validate Load Balancer Distribution
	fmt.Printf("\n✅ Results: OpenAI: %d, Anthropic: %d\n", openaiCount, anthropicCount)
	assert.Greater(t, openaiCount, 0, "OpenAI should receive at least one request")
	assert.Greater(t, anthropicCount, 0, "Anthropic should receive at least one request")
	assert.Equal(t, totalRequests, openaiCount+anthropicCount, "Total request count mismatch")

}
