package functional_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRequiredPlugins_Failed(t *testing.T) {
	subdomain := fmt.Sprintf("test-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Contextual Security Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "contextual_security",
				"enabled":  true,
				"priority": 0,
				"stage":    "pre_request",
				"parallel": false,
				"settings": map[string]interface{}{
					"max_failures":                5,
					"block_duration":              600,
					"rate_limit_mode":             "block",
					"similar_malicious_threshold": 2,
					"similar_blocked_threshold":   2,
				},
			},
		},
	}

	t.Run("it should fail when missing required plugin", func(t *testing.T) {
		status, _ := sendRequest(t, "POST", fmt.Sprintf("%s/gateways", AdminUrl), gatewayPayload)
		assert.Equal(t, 400, status)
	})
}

func TestRequiredPlugins_Success(t *testing.T) {
	subdomain := fmt.Sprintf("test-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Contextual Security Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "neuraltrust_guardrail",
				"enabled":  true,
				"priority": 1,
				"stage":    "pre_request",
				"parallel": false,
				"settings": map[string]interface{}{
					"credentials": map[string]interface{}{
						"token":    os.Getenv("NEURAL_TRUST_FIREWALL_API_KEY"),
						"base_url": os.Getenv("NEURAL_TRUST_FIREWALL_URL"),
					},
					"toxicity": map[string]interface{}{
						"enabled":   true,
						"threshold": 0.6,
					},
					"jailbreak": map[string]interface{}{
						"enabled":   true,
						"threshold": 0.6,
					},
					"mapping_field":    "input.test",
					"retention_period": 600,
				},
			},
		},
	}
	gatewayID := CreateGateway(t, gatewayPayload)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("echo-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "httpbin.org",
				"port":     443,
				"protocol": "https",
				"path":     "/post",
				"weight":   100,
				"priority": 1,
			},
		},
	}

	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	servicePayload := map[string]interface{}{
		"name":        fmt.Sprintf("bedrock-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Bedrock Guardrail Test Service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/post",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
		"plugin_chain": []map[string]interface{}{
			{
				"name":     "contextual_security",
				"enabled":  true,
				"priority": 0,
				"stage":    "pre_request",
				"parallel": false,
				"settings": map[string]interface{}{
					"max_failures":                5,
					"block_duration":              600,
					"rate_limit_mode":             "block",
					"similar_malicious_threshold": 2,
					"similar_blocked_threshold":   2,
				},
			},
		},
	}

	t.Run("it should fail when missing required plugin", func(t *testing.T) {
		status, _ := sendRequest(t, "POST", fmt.Sprintf("%s/gateways/%s/rules", AdminUrl, gatewayID), rulePayload)
		assert.Equal(t, 201, status)
	})

}
