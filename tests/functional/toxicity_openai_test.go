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

func TestOpenAIToxicityDetection(t *testing.T) {
	subdomain := fmt.Sprintf("toxicity-openai-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "OpenAI Toxicity Detection Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "toxicity_openai",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"openai_key": os.Getenv("OPENAI_API_KEY"),
					"actions": map[string]interface{}{
						"type":    "block",
						"message": "Content contains violence or hate speech",
					},
					"categories": []string{"hate", "hate/threatening", "violence", "violence/graphic"},
					"thresholds": map[string]float64{
						"hate":             0.15,
						"hate/threatening": 0.15,
						"violence":         0.15,
						"violence/graphic": 0.15,
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
	time.Sleep(2 * time.Second)

	testCases := []struct {
		name       string
		input      map[string]interface{}
		expectCode int
	}{
		{"Safe Text", map[string]interface{}{"messages": []map[string]interface{}{{"role": "user", "content": []map[string]string{{"type": "text", "text": "Hello! How are you today?"}}}}}, http.StatusOK},
		{"Hate Speech", map[string]interface{}{"messages": []map[string]interface{}{{"role": "user", "content": []map[string]string{{"type": "text", "text": "I hate all people from that country and want them gone!"}}}}}, http.StatusForbidden},
		{"Violence", map[string]interface{}{"messages": []map[string]interface{}{{"role": "user", "content": []map[string]string{{"type": "text", "text": "I will violently attack and hurt everyone!"}}}}}, http.StatusForbidden},
		{"Violent Image", map[string]interface{}{"messages": []map[string]interface{}{{"role": "user", "content": []map[string]interface{}{{"type": "image_url", "image_url": map[string]string{"url": "https://www.shutterstock.com/image-photo/violent-young-man-threatening-his-260nw-790887175.jpg"}}}}}}, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqBody, err := json.Marshal(tc.input)
			assert.NoError(t, err)
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

	fmt.Println("\n✅ OpenAI Toxicity Detection Test Completed")
}
