package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
						{"entity": "stripe_key", "enabled": true, "mask_with": "[MASKED_API_KEY]", "preserve_len": true},
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
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/mirror",
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
		input      string
		expected   string
		expectCode int
	}{
		{
			name: "Masking Test",
			input: `{
				"credit_card": "this is a credit card 4111-2222-3333-4444",
				"email": "test@example.com",
				"iban": "DE89370400440532013000",
				"swift_bic": "DEUTDEFF500",
				"crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
				"tax_id": "12-3456789",
				"stripe_key": "I logged in using the API key: sk_test_4eC39HqLyjWDarjtT1zdp7dc",
				"secret_key": "and my secret_key is this_is_secret"
			}`,
			expected:   `{"body":"{\"credit_card\":\"this is a credit card [MASKED_CC]\",\"crypto_wallet\":\"[MASKED_WALLET]\",\"email\":\"[MASKED_EMAIL]\",\"iban\":\"[MASKED_IBAN]\",\"secret_key\":\"and my **** is this_is_secret\",\"stripe_key\":\"I logged in using the API key: [MASKED_API_KEY]\",\"swift_bic\":\"[MASKED_BIC]\",\"tax_id\":\"[MASKED_TAX_ID]\"}"}`,
			expectCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader([]byte(tc.input)))
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
			respBody, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			actualResponse := string(respBody)
			assert.Equal(t, tc.expected, actualResponse)
		})
	}
}

func TestDataMaskingApplyAll(t *testing.T) {
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
					"apply_all":            true,
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
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/mirror",
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
		input      string
		expected   string
		expectCode int
	}{
		{
			name: "Masking Test",
			input: `{
				"credit_card": "this is a credit card 4111-2222-3333-4444",
				"email": "test@example.com",
				"iban": "DE89370400440532013000",
				"swift_bic": "DEUTDEFF500",
				"crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
				"tax_id": "12-3456789",
				"stripe_key": "I logged in using the API key: sk_test_4eC39HqLyjWDarjtT1zdp7dc",
 			"secret_key": "and my secret_key is this_is_secret"
			}`,
			expected:   `{"body":"{\"credit_card\":\"this is a credit card *****\",\"crypto_wallet\":\"*****\",\"email\":\"*****\",\"iban\":\"*****\",\"secret_key\":\"and my **** is this_is_secret\",\"stripe_key\":\"I logged in using the API key: *****\",\"swift_bic\":\"*****\",\"tax_id\":\"*****\"}"}`,
			expectCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader([]byte(tc.input)))
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
			respBody, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			actualResponse := string(respBody)
			assert.Equal(t, tc.expected, actualResponse)
		})
	}
}

func TestDataMaskingReversibleHash(t *testing.T) {
	subdomain := fmt.Sprintf("datamask-rev-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Data Masking Reversible Hash Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "data_masking",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"similarity_threshold": 0.8,
					"reversible_hashing": map[string]interface{}{
						"enabled": true,
						"secret":  "test-secret-key",
					},
					"predefined_entities": []map[string]interface{}{
						{"entity": "credit_card", "enabled": true, "mask_with": "[MASKED_CC]", "preserve_len": false},
						{"entity": "email", "enabled": true, "mask_with": "[MASKED_EMAIL]", "preserve_len": false},
					},
					"rules": []map[string]interface{}{
						{"pattern": "secret_key", "type": "keyword", "mask_with": "****", "preserve_len": true},
					},
				},
			},
			{
				"name":     "data_masking",
				"enabled":  true,
				"stage":    "post_response",
				"priority": 1,
				"settings": map[string]interface{}{
					"similarity_threshold": 0.8,
					"reversible_hashing": map[string]interface{}{
						"enabled": true,
						"secret":  "test-secret-key",
					},
					"predefined_entities": []map[string]interface{}{
						{"entity": "credit_card", "enabled": true, "mask_with": "[MASKED_CC]", "preserve_len": false},
						{"entity": "email", "enabled": true, "mask_with": "[MASKED_EMAIL]", "preserve_len": false},
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
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/mirror",
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
		input      string
		expected   string
		expectCode int
	}{
		{
			name: "Reversible Hashing Test",
			input: `{
				"credit_card": "4111-2222-3333-4444",
				"email": "test@example.com",
				"secret_key": "this_is_secret"
			}`,
			// In the response, we expect the original values to be restored
			expected:   `{"body":"{\"credit_card\":\"4111-2222-3333-4444\",\"email\":\"test@example.com\",\"secret_key\":\"this_is_secret\"}"}`,
			expectCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader([]byte(tc.input)))
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
			respBody, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			actualResponse := string(respBody)
			assert.Equal(t, tc.expected, actualResponse)
		})
	}
}

func assertMirroredJSONBody(t *testing.T, respBody []byte, expected map[string]interface{}) {
	var outer map[string]interface{}
	assert.NoError(t, json.Unmarshal(respBody, &outer))
	bodyStr, ok := outer["body"].(string)
	assert.True(t, ok, "response should contain body as string")
	var inner map[string]interface{}
	assert.NoError(t, json.Unmarshal([]byte(bodyStr), &inner))
	assert.Equal(t, expected, inner)
}

func TestDataMaskingPostResponse(t *testing.T) {
	subdomain := fmt.Sprintf("datamask-postresponse-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Data Masking Post Response Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "data_masking",
				"enabled":  true,
				"stage":    "post_response",
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
						{"entity": "stripe_key", "enabled": true, "mask_with": "[MASKED_API_KEY]", "preserve_len": true},
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
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/mirror",
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
		input      string
		expected   map[string]interface{}
		expectCode int
	}{
		{
			name: "Post Response Masking Test",
			input: `{
				"credit_card": "this is a credit card 4111-2222-3333-4444",
				"email": "test@example.com",
				"iban": "DE89370400440532013000",
				"swift_bic": "DEUTDEFF500",
				"crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
				"tax_id": "12-3456789",
				"stripe_key": "I logged in using the API key: sk_test_4eC39HqLyjWDarjtT1zdp7dc",
				"secret_key": "and my secret_key is this_is_secret"
			}`,
			expected: map[string]interface{}{
				"credit_card":   "this is a credit card [MASKED_CC]",
				"crypto_wallet": "[MASKED_WALLET]",
				"email":         "[MASKED_EMAIL]",
				"iban":          "[MASKED_IBAN]",
				"secret_key":    "and my **** is this_is_secret",
				"stripe_key":    "I logged in using the API key: [MASKED_API_KEY]",
				"swift_bic":     "[MASKED_BIC]",
				"tax_id":        "[MASKED_TAX_ID]",
			},
			expectCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader([]byte(tc.input)))
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
			respBody, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assertMirroredJSONBody(t, respBody, tc.expected)
		})
	}
}

func TestDataMaskingPreResponse(t *testing.T) {
	subdomain := fmt.Sprintf("datamask-preresponse-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Data Masking Pre Response Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "data_masking",
				"enabled":  true,
				"stage":    "pre_response",
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
						{"entity": "stripe_key", "enabled": true, "mask_with": "[MASKED_API_KEY]", "preserve_len": true},
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
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"path":     "/__/mirror",
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
		input      string
		expected   map[string]interface{}
		expectCode int
	}{
		{
			name: "Pre Response Masking Test",
			input: `{
				"credit_card": "this is a credit card 4111-2222-3333-4444",
				"email": "test@example.com",
				"iban": "DE89370400440532013000",
				"swift_bic": "DEUTDEFF500",
				"crypto_wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
				"tax_id": "12-3456789",
				"stripe_key": "I logged in using the API key: sk_test_4eC39HqLyjWDarjtT1zdp7dc",
				"secret_key": "and my secret_key is this_is_secret"
			}`,
			expected: map[string]interface{}{
				"credit_card":   "this is a credit card [MASKED_CC]",
				"crypto_wallet": "[MASKED_WALLET]",
				"email":         "[MASKED_EMAIL]",
				"iban":          "[MASKED_IBAN]",
				"secret_key":    "and my **** is this_is_secret",
				"stripe_key":    "I logged in using the API key: [MASKED_API_KEY]",
				"swift_bic":     "[MASKED_BIC]",
				"tax_id":        "[MASKED_TAX_ID]",
			},
			expectCode: http.StatusOK,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, ProxyUrl+"/post", bytes.NewReader([]byte(tc.input)))
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
			respBody, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)
			assertMirroredJSONBody(t, respBody, tc.expected)
		})
	}
}
