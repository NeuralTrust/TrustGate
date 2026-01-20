package functional_test

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNeuralTrustModerationPlugin_KeyReg(t *testing.T) {
	defer RunTest(t, "NeuraltrustModeration", time.Now())()
	subdomain := fmt.Sprintf("neuraltrust-moderation-keyreg-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "NeuralTrust Moderation KeyReg Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "neuraltrust_moderation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"keyreg_moderation": map[string]interface{}{
						"enabled":              true,
						"similarity_threshold": 0.8,
						"keywords":             []string{"password", "secret", "api_key"},
						"regex":                []string{"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
						"actions": map[string]interface{}{
							"type":    "block",
							"message": "Content contains sensitive information",
						},
					},
					"mapping_field": "input.text",
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("echo-upstream-keyreg-%d", time.Now().Unix()),
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
		"name":        fmt.Sprintf("keyreg-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "NeuralTrust KeyReg Test Service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/post",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)
	time.Sleep(2 * time.Second) // Wait for propagation

	testCases := []struct {
		name       string
		input      string
		expectCode int
	}{
		{
			"Safe Content",
			"{\"input\": {\"text\": \"I like Cats\"}}",
			http.StatusOK,
		},
		{
			"Content with Keyword",
			"{\"input\": {\"text\": \"My password is 12345\"}}",
			http.StatusForbidden,
		},
		{
			"Content with Similar Word",
			"{\"input\": {\"text\": \"My passw0rd is 12345\"}}",
			http.StatusForbidden,
		},
		{
			"Content with Regex Match",
			"{\"input\": {\"text\": \"My email is test@example.com\"}}",
			http.StatusForbidden,
		},
		{
			"Direct Text with Keyword ",
			"My secret is 12345",
			http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := []byte(tc.input)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}

func TestNeuralTrustModerationPlugin_NTTopic(t *testing.T) {
	defer RunTest(t, "NeuraltrustModeration_NTTopic", time.Now())()
	subdomain := fmt.Sprintf("neuraltrust-moderation-nttopic-%d", time.Now().Unix())

	gatewayPayload := map[string]interface{}{
		"name":      "NeuralTrust Moderation NTTopic Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "neuraltrust_moderation",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"credentials": map[string]interface{}{
						"base_url": os.Getenv("NEURAL_TRUST_FIREWALL_URL"),
						"token":    os.Getenv("NEURAL_TRUST_FIREWALL_API_KEY"),
					},
					"nt_topic_moderation": map[string]interface{}{
						"enabled": true,
						"topics":  []string{"code_generation"},
						"thresholds": map[string]interface{}{
							"code_generation": 0.5,
						},
					},
					"mapping_field": "input.text",
				},
			},
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("echo-upstream-nttopic-%d", time.Now().Unix()),
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
		"name":        fmt.Sprintf("nttopic-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "NeuralTrust NTTopic Test Service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/post",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)
	time.Sleep(2 * time.Second)

	testCases := []struct {
		name       string
		input      string
		expectCode int
	}{
		{
			"Safe Content - No Code",
			"{\"input\": {\"text\": \"I like cats and dogs\"}}",
			http.StatusOK,
		},
		{
			"Code Generation Request",
			"{\"input\": {\"text\": \"Write me a Python function to sort an array\"}}",
			http.StatusForbidden,
		},
		{
			"Code Generation Request - Direct",
			"Generate JavaScript code to fetch data from an API",
			http.StatusForbidden,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody := []byte(tc.input)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-TG-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
