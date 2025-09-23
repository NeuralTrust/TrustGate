package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIPWhitelist(t *testing.T) {
	sub := fmt.Sprintf("ipwl-%d", time.Now().UnixNano())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "IP Whitelist Gateway",
		"subdomain": sub,
		"required_plugins": []map[string]interface{}{
			{
				"name":     "ip_whitelist",
				"enabled":  true,
				"stage":    "pre_request",
				"priority": 0,
				"settings": map[string]interface{}{
					"enabled": true,
					"ips":     []string{"127.0.0.1"},
				},
			},
		},
	})

	upstreamID := CreateUpstream(t, gatewayID, map[string]interface{}{
		"name":      "Echo",
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{{
			"host": "localhost", "port": 8081, "protocol": "http", "path": "/__/ping",
		}},
	})
	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name": "svc", "type": "upstream", "upstream_id": upstreamID,
	})
	CreateRules(t, gatewayID, map[string]interface{}{
		"path": "/ipwl", "service_id": serviceID, "methods": []string{"GET"},
	})

	apiKey := CreateApiKey(t, gatewayID)

	// Allowed from 127.0.0.1 (tests run locally)
	req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/ipwl", nil)
	assert.NoError(t, err)
	req.Host = fmt.Sprintf("%s.%s", sub, BaseDomain)
	req.Header.Set("Host", fmt.Sprintf("%s.%s", sub, BaseDomain))
	req.Header.Set("X-TG-API-Key", apiKey)

	// Spoof IP through standard header used by tracker
	req.Header.Set("X-Real-IP", "127.0.0.1")

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Now block by setting a non-allowed IP
	req2, err := http.NewRequest(http.MethodGet, ProxyUrl+"/ipwl", nil)
	assert.NoError(t, err)
	req2.Host = fmt.Sprintf("%s.%s", sub, BaseDomain)
	req2.Header.Set("Host", fmt.Sprintf("%s.%s", sub, BaseDomain))
	req2.Header.Set("X-TG-API-Key", apiKey)
	req2.Header.Set("X-Real-IP", "10.9.9.9")

	resp2, err := http.DefaultClient.Do(req2)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	_ = resp2.Body.Close()
}
