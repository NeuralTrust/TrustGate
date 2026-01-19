package functional_test

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBotDetectorPlugin(t *testing.T) {
	defer RunTest(t, "BotDetector", time.Now())()
	subdomain := fmt.Sprintf("botdetector-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Bot Detector Gateway",
		"subdomain": subdomain,
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
		"name":        fmt.Sprintf("botdetector-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Bot Detector Test Service",
		"upstream_id": upstreamID,
	}
	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/botcheck",
		"service_id": serviceID,
		"methods":    []string{"POST"},
		"strip_path": false,
		"active":     true,
		"plugin_chain": []map[string]interface{}{
			{
				"name":     "bot_detector",
				"enabled":  true,
				"priority": 0,
				"stage":    "pre_request",
				"parallel": true,
				"settings": map[string]interface{}{
					"threshold":        0.5,
					"action":           "block",
					"retention_period": 600,
				},
			},
		},
	}
	CreateRules(t, gatewayID, rulePayload)
	time.Sleep(2 * time.Second) // Wait for propagation

	highBotData := map[string]interface{}{
		"automationDetection": map[string]interface{}{
			"webdriver":      true,
			"chromeHeadless": true,
			"automationProperties": map[string]interface{}{
				"property1": true,
				"property2": true,
			},
			"inconsistencies": map[string]interface{}{
				"exactCommonResolution":      true,
				"utcTimezone":                true,
				"missingHardwareConcurrency": true,
				"missingDeviceMemory":        true,
				"platformInconsistency":      true,
			},
		},
		"persistenceChecker": map[string]interface{}{
			"cookiesEnabled": false,
			"localStorage":   false,
			"sessionStorage": false,
		},
		"environment": map[string]interface{}{
			"userAgent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			"languages": []interface{}{},
		},
		"visualFingerprint": map[string]interface{}{
			"canvasFingerprint": "",
			"webglFingerprint": map[string]interface{}{
				"supported": false,
			},
		},
	}
	highBotJson, err := json.Marshal(highBotData)
	if err != nil {
		t.Fatalf("Failed to marshal high bot data: %v", err)
	}

	// Compress the data with zlib
	var highBotBuffer bytes.Buffer
	highBotWriter := zlib.NewWriter(&highBotBuffer)
	_, err = highBotWriter.Write(highBotJson)
	if err != nil {
		t.Fatalf("Failed to write compressed high bot data: %v", err)
	}
	err = highBotWriter.Close()
	if err != nil {
		t.Fatalf("Failed to close zlib writer for high bot data: %v", err)
	}

	highBotEncoded := base64.StdEncoding.EncodeToString(highBotBuffer.Bytes())

	safeBotData := map[string]interface{}{
		"automationDetection": map[string]interface{}{
			"webdriver":      false,
			"chromeHeadless": false,
			"automationProperties": map[string]interface{}{
				"property1": false,
				"property2": false,
			},
			"inconsistencies": map[string]interface{}{
				"exactCommonResolution":      false,
				"utcTimezone":                false,
				"missingHardwareConcurrency": false,
				"missingDeviceMemory":        false,
				"platformInconsistency":      false,
			},
		},
		"persistenceChecker": map[string]interface{}{
			"cookiesEnabled": true,
			"localStorage":   true,
			"sessionStorage": true,
		},
		"environment": map[string]interface{}{
			"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"languages": []interface{}{"en-US", "en"},
		},
		"visualFingerprint": map[string]interface{}{
			"canvasFingerprint": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA",
			"webglFingerprint": map[string]interface{}{
				"supported": true,
			},
		},
	}
	safeBotJson, err := json.Marshal(safeBotData)
	if err != nil {
		t.Fatalf("Failed to marshal safe bot data: %v", err)
	}

	// Compress the data with zlib
	var safeBotBuffer bytes.Buffer
	safeBotWriter := zlib.NewWriter(&safeBotBuffer)
	_, err = safeBotWriter.Write(safeBotJson)
	if err != nil {
		t.Fatalf("Failed to write compressed safe bot data: %v", err)
	}
	err = safeBotWriter.Close()
	if err != nil {
		t.Fatalf("Failed to close zlib writer for safe bot data: %v", err)
	}

	safeBotEncoded := base64.StdEncoding.EncodeToString(safeBotBuffer.Bytes())

	proxyUrl := ProxyUrl + "/botcheck"
	host := fmt.Sprintf("%s.%s", subdomain, BaseDomain)

	t.Run("should block high bot score request", func(t *testing.T) {
		body := []byte(`{"test": "block"}`)
		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
		assert.NoError(t, err)
		req.Host = host
		req.Header.Set("Host", host)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-trustgate-data", highBotEncoded)

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Equal(t, "true", resp.Header.Get("bot_detected"))
	})

	t.Run("should allow safe request", func(t *testing.T) {
		body := []byte(`{"test": "allow"}`)
		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
		assert.NoError(t, err)
		req.Host = host
		req.Header.Set("Host", host)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-trustgate-data", safeBotEncoded)

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("bot_detected"))
	})
}
