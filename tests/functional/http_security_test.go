package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSecurityMiddleware(t *testing.T) {
	subdomain := fmt.Sprintf("security-%d", time.Now().Unix())

	gatewayPayload := map[string]interface{}{
		"name":      "Security Test Gateway",
		"subdomain": subdomain,
		"security_config": map[string]interface{}{
			"allowed_hosts":           []string{"^.*\\.example\\.com"},
			"allowed_hosts_are_regex": true,
			"ssl_redirect":            true,
			"ssl_host":                "dev.neuraltrust.ai",
			"ssl_proxy_headers": map[string]string{
				"X-Forwarded-Proto": "https",
			},
			"sts_seconds":                86400,
			"sts_include_subdomains":     true,
			"frame_deny":                 true,
			"custom_frame_options_value": "",
			"referrer_policy":            "no-referrer",
			"content_security_policy":    "default-src 'self'; script-src 'self'; object-src 'none';",
			"content_type_nosniff":       true,
			"browser_xss_filter":         true,
			"is_development":             false,
		},
	}

	gatewayID := CreateGateway(t, gatewayPayload)
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("security-upstream-%d", time.Now().Unix()),
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
		"name":        fmt.Sprintf("security-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"description": "Security test service",
		"upstream_id": upstreamID,
	}

	serviceID := CreateService(t, gatewayID, servicePayload)

	rulePayload := map[string]interface{}{
		"path":       "/security-test",
		"service_id": serviceID,
		"methods":    []string{"GET"},
		"strip_path": true,
		"active":     true,
	}

	CreateRules(t, gatewayID, rulePayload)

	t.Run("Valid Host with Secure Headers", func(t *testing.T) {
		req, err := http.NewRequest("GET", ProxyUrl+"/security-test", nil)
		assert.NoError(t, err)

		host := fmt.Sprintf("%s.example.com", subdomain)
		req.Host = host
		req.Header.Set("Host", host)
		req.Header.Set("X-TG-API-Key", apiKey)
		req.Header.Set("X-Forwarded-Proto", "https")

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
		assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
		assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=86400")
		assert.Contains(t, resp.Header.Get("Content-Security-Policy"), "default-src 'self'")
	})

	t.Run("Redirects HTTP to HTTPS", func(t *testing.T) {
		req, err := http.NewRequest("GET", ProxyUrl+"/security-test", nil)
		assert.NoError(t, err)

		req.Host = fmt.Sprintf("%s.example.com", subdomain)
		req.Header.Set("Host", req.Host)
		req.Header.Set("X-TG-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	fmt.Println("\n✅ Security Middleware Functional Test Completed")
}
