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

func TestToxicityNeuralTrustPlugin(t *testing.T) {
	subdomain := fmt.Sprintf("toxicity-neuraltrust-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Toxicity NeuralTrust Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "toxicity_neuraltrust",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"toxicity": map[string]interface{}{
						"enabled":   true,
						"threshold": 0.5,
					},
					"credentials": map[string]string{
						"token":    os.Getenv("NEURAL_TRUST_FIREWALL_API_KEY"),
						"base_url": os.Getenv("NEURAL_TRUST_FIREWALL_URL"),
					},
					"mapping_field": "input.text",
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
		"name":        fmt.Sprintf("toxicity-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Toxicity NeuralTrust Test Service",
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
			"Toxicity Violation",
			"{\"input\": {\"text\": \"I Hate obama negro president\"}}",
			http.StatusForbidden,
		},
		{
			"Toxicity Violation - Direct Text",
			"I Hate obama negro president",
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
			defer resp.Body.Close()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
