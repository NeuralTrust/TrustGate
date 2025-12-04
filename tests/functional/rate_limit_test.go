package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimit(t *testing.T) {
	subdomain := fmt.Sprintf("gateway-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Multi Rate Limited Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "rate_limiter",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"limits": map[string]interface{}{
						"global":   map[string]interface{}{"limit": 15, "window": "1m"},
						"per_ip":   map[string]interface{}{"limit": 5, "window": "1m"},
						"per_user": map[string]interface{}{"limit": 5, "window": "1m"},
					},
					"actions": map[string]interface{}{
						"type":        "reject",
						"retry_after": "60",
					},
				},
			},
		},
	}
	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("httpbin-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"weight":   100,
				"path":     "/__/ping",
				"priority": 1,
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
		"name":        fmt.Sprintf("httpbin-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "HTTPBin test service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/path1",
		"service_id": serviceID,
		"methods":    []string{"GET"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)

	fmt.Println("Testing Rate Limiter (Per IP: Limit 5/min)")

	for i := 1; i <= 10; i++ {
		startTime := time.Now()

		req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/path1", nil)
		assert.NoError(t, err)
		req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
		req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
		req.Header.Set("X-TG-API-Key", apiKey)

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)

		duration := time.Since(startTime)
		defer func() { _ = resp.Body.Close() }()

		switch resp.StatusCode {
		case http.StatusOK:
			t.Logf("✅ Request %d: Success (Time: %v)", i, duration)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected HTTP 200 for successful requests")
		case http.StatusTooManyRequests:
			if i <= 5 {
				t.Fatalf("❌ Request %d: Unexpected Rate Limit Too Early! Expected at 6th request, got at %d", i, i)
			}
			t.Logf("⛔ Request %d: Rate Limited (Expected after 5 requests)", i)
			assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Expected HTTP 429 when hitting rate limit")
		default:
			t.Fatalf("❌ Request %d: Unexpected Status Code: %d", i, resp.StatusCode)
		}

		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("\n✅ Rate Limiter Test Completed")
}

func TestRateLimitPerFingerprint(t *testing.T) {
	subdomain := fmt.Sprintf("gateway-fp-%d", time.Now().Unix())
	gatewayPayload := map[string]interface{}{
		"name":      "Fingerprint Rate Limited Gateway",
		"subdomain": subdomain,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "rate_limiter",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 1,
				"settings": map[string]interface{}{
					"limits": map[string]interface{}{
						"per_fingerprint": map[string]interface{}{"limit": 3, "window": "1m"},
						"per_ip":          map[string]interface{}{"limit": 10, "window": "1m"},
						"global":          map[string]interface{}{"limit": 20, "window": "1m"},
					},
					"actions": map[string]interface{}{
						"type":        "reject",
						"retry_after": "60",
					},
				},
			},
		},
	}
	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("httpbin-upstream-fp-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     8081,
				"protocol": "http",
				"weight":   100,
				"path":     "/__/ping",
				"priority": 1,
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
		"name":        fmt.Sprintf("httpbin-service-fp-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "HTTPBin test service for fingerprint rate limiting",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/path2",
		"service_id": serviceID,
		"methods":    []string{"GET"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)

	fmt.Println("Testing Rate Limiter (Per Fingerprint: Limit 3/min)")

	// Test with same fingerprint (same User-Agent, same IP simulation)
	for i := 1; i <= 5; i++ {
		startTime := time.Now()

		req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/path2", nil)
		assert.NoError(t, err)
		req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
		req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
		req.Header.Set("X-TG-API-Key", apiKey)
		// Use consistent User-Agent to ensure same fingerprint
		req.Header.Set("User-Agent", "TestClient/1.0")

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)

		duration := time.Since(startTime)
		defer func() { _ = resp.Body.Close() }()

		switch resp.StatusCode {
		case http.StatusOK:
			t.Logf("✅ Request %d: Success (Time: %v)", i, duration)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected HTTP 200 for successful requests")
		case http.StatusTooManyRequests:
			if i <= 3 {
				t.Fatalf("❌ Request %d: Unexpected Rate Limit Too Early! Expected at 4th request, got at %d", i, i)
			}
			t.Logf("⛔ Request %d: Rate Limited by fingerprint (Expected after 3 requests)", i)
			assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Expected HTTP 429 when hitting fingerprint rate limit")
		default:
			t.Fatalf("❌ Request %d: Unexpected Status Code: %d", i, resp.StatusCode)
		}

		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("\n✅ Fingerprint Rate Limiter Test Completed")
}
