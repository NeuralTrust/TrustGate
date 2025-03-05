package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDataMasking(t *testing.T) {
	subdomain := fmt.Sprintf("datamask-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Data Masking Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "data_masking",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"similarity_threshold": 0.8,
					"predefined_entities": []map[string]interface{}{
						{"entity": "credit_card", "enabled": true, "mask_with": "[MASKED_CC]", "preserve_len": false},
						{"entity": "email", "enabled": true, "mask_with": "[MASKED_EMAIL]", "preserve_len": false},
						{"entity": "iban", "enabled": true, "mask_with": "[MASKED_IBAN]", "preserve_len": false},
						{"entity": "swift_bic", "enabled": true, "mask_with": "[MASKED_BIC]", "preserve_len": false},
						{"entity": "crypto_wallet", "enabled": true, "mask_with": "[MASKED_WALLET]", "preserve_len": false},
						{"entity": "tax_id", "enabled": true, "mask_with": "[MASKED_TAX_ID]", "preserve_len": true},
					},
					"rules": []map[string]interface{}{
						{"pattern": "secret_key", "type": "keyword", "mask_with": "****", "preserve_len": true},
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
		"name":        fmt.Sprintf("echo-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Echo test service",
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
		input      map[string]interface{}
		expectCode int
	}{
		{"Masking Test", map[string]interface{}{
			"credit_card":   "4111-2222-3333-4444",
			"email":         "test@example.com",
			"iban":          "DE89370400440532013000",
			"swift_bic":     "DEUTDEFF500",
			"crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			"tax_id":        "12-3456789",
			"secret_key":    "this_is_secret",
		}, http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, err := json.Marshal(tc.input)
			assert.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader(reqBody))
			assert.NoError(t, err)
			req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
			req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
			req.Header.Set("X-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectCode, resp.StatusCode)
		})
	}
}
