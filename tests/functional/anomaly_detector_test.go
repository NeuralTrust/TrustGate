package functional_test

//
//import (
//	"bytes"
//	"fmt"
//	"net/http"
//	"testing"
//	"time"
//
//	"github.com/stretchr/testify/assert"
//)
//
//func TestAnomalyDetectorPlugin(t *testing.T) {
//	subdomain := fmt.Sprintf("anomalydetector-%d", time.Now().Unix())
//	gatewayPayload := map[string]interface{}{
//		"name":      "Anomaly Detector Gateway",
//		"subdomain": subdomain,
//	}
//	gatewayID := CreateGateway(t, gatewayPayload)
//	apiKey := CreateApiKey(t, gatewayID)
//
//	upstreamPayload := map[string]interface{}{
//		"name":      fmt.Sprintf("echo-upstream-%d", time.Now().Unix()),
//		"algorithm": "round-robin",
//		"targets": []map[string]interface{}{
//			{
//				"host":     "localhost",
//				"port":     8081,
//				"protocol": "http",
//				"path":     "/__/ping",
//				"weight":   100,
//				"priority": 1,
//			},
//		},
//	}
//	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)
//
//	servicePayload := map[string]interface{}{
//		"name":        fmt.Sprintf("anomalydetector-service-%d", time.Now().Unix()),
//		"type":        "upstream",
//		"description": "Anomaly Detector Test Service",
//		"upstream_id": upstreamID,
//	}
//	serviceID := CreateService(t, gatewayID, servicePayload)
//
//	rulePayload := map[string]interface{}{
//		"path":       "/anomalycheck",
//		"service_id": serviceID,
//		"methods":    []string{"POST"},
//		"strip_path": false,
//		"active":     true,
//		"plugin_chain": []map[string]interface{}{
//			{
//				"name":     "anomaly_detector",
//				"enabled":  true,
//				"priority": 0,
//				"stage":    "pre_request",
//				"parallel": true,
//				"settings": map[string]interface{}{
//					"threshold":                 0.5,
//					"action":                    "block",
//					"retention_period":          600,
//					"timing_pattern_weight":     0.25,
//					"content_similarity_weight": 0.25,
//					"suspicious_headers_weight": 0.25,
//					"token_usage_weight":        0.25,
//					"min_time_between_requests": 1,
//					"max_requests_to_analyze":   10,
//				},
//			},
//		},
//	}
//	CreateRules(t, gatewayID, rulePayload)
//	time.Sleep(2 * time.Second) // Wait for propagation
//
//	proxyUrl := ProxyUrl + "/anomalycheck"
//	host := fmt.Sprintf("%s.%s", subdomain, BaseDomain)
//
//	// Test 1: First request should pass (not enough data for anomaly analysis)
//	t.Run("first request should pass (not enough data)", func(t *testing.T) {
//		body := []byte(`{"test": "first_request"}`)
//		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
//		assert.NoError(t, err)
//		req.Host = host
//		req.Header.Set("Host", host)
//		req.Header.Set("X-TG-API-Key", apiKey)
//		req.Header.Set("Content-Type", "application/json")
//		req.Header.Set("User-Agent", "TestUserAgent/1.0")
//		req.Header.Set("Accept", "application/json")
//		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
//		req.Header.Set("Referer", "https://test.com")
//		req.Header.Set("Origin", "https://test.com")
//		req.Header.Set("X-Forwarded-For", "192.168.1.1")
//
//		client := &http.Client{}
//		resp, err := client.Do(req)
//		assert.NoError(t, err)
//		defer resp.Body.Close()
//
//		assert.Equal(t, http.StatusOK, resp.StatusCode)
//		assert.Empty(t, resp.Header.Get("anomaly_detected"))
//	})
//
//	// Test 2: Second request with same content should pass (still building baseline)
//	t.Run("second request should pass (still building baseline)", func(t *testing.T) {
//		body := []byte(`{"test": "second_request"}`)
//		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
//		assert.NoError(t, err)
//		req.Host = host
//		req.Header.Set("Host", host)
//		req.Header.Set("X-TG-API-Key", apiKey)
//		req.Header.Set("Content-Type", "application/json")
//		req.Header.Set("User-Agent", "TestUserAgent/1.0")
//		req.Header.Set("Accept", "application/json")
//		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
//		req.Header.Set("Referer", "https://test.com")
//		req.Header.Set("Origin", "https://test.com")
//		req.Header.Set("X-Forwarded-For", "192.168.1.1")
//
//		client := &http.Client{}
//		resp, err := client.Do(req)
//		assert.NoError(t, err)
//		defer resp.Body.Close()
//
//		assert.Equal(t, http.StatusOK, resp.StatusCode)
//		assert.Empty(t, resp.Header.Get("anomaly_detected"))
//	})
//
//	// Test 3: Multiple rapid requests with identical content (should trigger anomaly)
//	t.Run("multiple rapid identical requests should be detected as anomalous", func(t *testing.T) {
//		// Send several identical requests in rapid succession
//		for i := 0; i < 5; i++ {
//			body := []byte(`{"test": "identical_content"}`)
//			req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
//			assert.NoError(t, err)
//			req.Host = host
//			req.Header.Set("Host", host)
//			req.Header.Set("X-TG-API-Key", apiKey)
//			req.Header.Set("Content-Type", "application/json")
//			req.Header.Set("User-Agent", "TestUserAgent/1.0")
//			req.Header.Set("Accept", "application/json")
//			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
//			req.Header.Set("Referer", "https://test.com")
//			req.Header.Set("Origin", "https://test.com")
//			req.Header.Set("X-Forwarded-For", "192.168.1.1")
//
//			client := &http.Client{}
//			resp, err := client.Do(req)
//			assert.NoError(t, err)
//			resp.Body.Close()
//		}
//
//		// The last request should trigger anomaly detection
//		body := []byte(`{"test": "identical_content"}`)
//		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
//		assert.NoError(t, err)
//		req.Host = host
//		req.Header.Set("Host", host)
//		req.Header.Set("X-TG-API-Key", apiKey)
//		req.Header.Set("Content-Type", "application/json")
//		req.Header.Set("User-Agent", "TestUserAgent/1.0")
//		req.Header.Set("Accept", "application/json")
//		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
//		req.Header.Set("Referer", "https://test.com")
//		req.Header.Set("Origin", "https://test.com")
//		req.Header.Set("X-Forwarded-For", "192.168.1.1")
//
//		client := &http.Client{}
//		resp, err := client.Do(req)
//		assert.NoError(t, err)
//		defer resp.Body.Close()
//
//		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
//		assert.Equal(t, "true", resp.Header.Get("anomaly_detected"))
//	})
//
//	// Test 4: Request with suspicious headers should be detected as anomalous
//	t.Run("request with suspicious headers should be detected as anomalous", func(t *testing.T) {
//		// First, send a few normal requests to establish a baseline
//		for i := 0; i < 3; i++ {
//			normalBody := []byte(fmt.Sprintf(`{"test": "baseline_request_%d"}`, i))
//			normalReq, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(normalBody))
//			assert.NoError(t, err)
//			normalReq.Host = host
//			normalReq.Header.Set("Host", host)
//			normalReq.Header.Set("X-TG-API-Key", apiKey)
//			normalReq.Header.Set("Content-Type", "application/json")
//			normalReq.Header.Set("User-Agent", "TestUserAgent/1.0")
//			normalReq.Header.Set("Accept", "application/json")
//			normalReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
//			normalReq.Header.Set("Referer", "https://test.com")
//			normalReq.Header.Set("Origin", "https://test.com")
//			normalReq.Header.Set("X-Forwarded-For", "192.168.1.1")
//
//			client := &http.Client{}
//			normalResp, err := client.Do(normalReq)
//			assert.NoError(t, err)
//			normalResp.Body.Close()
//			time.Sleep(100 * time.Millisecond) // Small delay between requests
//		}
//
//		// Now send the suspicious request
//		body := []byte(`{"test": "suspicious_headers"}`)
//		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
//		assert.NoError(t, err)
//		req.Host = host
//		req.Header.Set("Host", host)
//		req.Header.Set("X-TG-API-Key", apiKey)
//		req.Header.Set("Content-Type", "application/json")
//		// Missing many standard headers that browsers typically send
//		// No User-Agent, Accept, Accept-Language, Referer, Origin
//
//		client := &http.Client{}
//		resp, err := client.Do(req)
//		assert.NoError(t, err)
//		defer resp.Body.Close()
//
//		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
//		assert.Equal(t, "true", resp.Header.Get("anomaly_detected"))
//	})
//
//	// Test 5: Normal request with varied content should pass
//	t.Run("normal request with varied content should pass", func(t *testing.T) {
//		// Wait a bit to avoid timing pattern detection
//		time.Sleep(2 * time.Second)
//
//		body := []byte(`{"test": "normal_request", "timestamp": "` + time.Now().String() + `"}`)
//		req, err := http.NewRequest(http.MethodPost, proxyUrl, bytes.NewReader(body))
//		assert.NoError(t, err)
//		req.Host = host
//		req.Header.Set("Host", host)
//		req.Header.Set("X-TG-API-Key", apiKey)
//		req.Header.Set("Content-Type", "application/json")
//		req.Header.Set("User-Agent", "TestUserAgent/1.0")
//		req.Header.Set("Accept", "application/json")
//		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
//		req.Header.Set("Referer", "https://test.com/page")
//		req.Header.Set("Origin", "https://test.com")
//
//		client := &http.Client{}
//		resp, err := client.Do(req)
//		assert.NoError(t, err)
//		defer resp.Body.Close()
//
//		assert.Equal(t, http.StatusOK, resp.StatusCode)
//		assert.Empty(t, resp.Header.Get("anomaly_detected"))
//	})
//}
