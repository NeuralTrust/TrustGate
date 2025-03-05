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
				"host":     "httpbin.org",
				"port":     443,
				"protocol": "https",
				"weight":   100,
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
		req.Header.Set("X-API-Key", apiKey)

		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)

		duration := time.Since(startTime)
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Logf("✅ Request %d: Success (Time: %v)", i, duration)
			assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected HTTP 200 for successful requests")
		} else if resp.StatusCode == http.StatusTooManyRequests {
			if i <= 5 {
				t.Fatalf("❌ Request %d: Unexpected Rate Limit Too Early! Expected at 6th request, got at %d", i, i)
			}
			t.Logf("⛔ Request %d: Rate Limited (Expected after 5 requests)", i)
			assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "Expected HTTP 429 when hitting rate limit")
		} else {
			t.Fatalf("❌ Request %d: Unexpected Status Code: %d", i, resp.StatusCode)
		}

		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("\n✅ Rate Limiter Test Completed")
}
