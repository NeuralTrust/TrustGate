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

func setupWireMockProtectedEndpoint(t *testing.T) {
	resp, err := http.Get("http://localhost:9090/__admin/")
	if err != nil || resp.StatusCode >= 500 {
		t.Skip("WireMock (OAuth dummy) not available on localhost:9090; skipping OAuth functional test")
		return
	}
	_ = resp.Body.Close()

	mapping := map[string]interface{}{
		"request": map[string]interface{}{
			"method":  "GET",
			"urlPath": "/protected",
			"headers": map[string]interface{}{
				"Authorization": map[string]interface{}{
					"matches": "Bearer ci-dummy-token",
				},
			},
		},
		"response": map[string]interface{}{
			"status": 200,
			"headers": map[string]interface{}{
				"Content-Type": "application/json",
			},
			"jsonBody": map[string]interface{}{"ok": true},
		},
	}
	body, err := json.Marshal(mapping)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9090/__admin/mappings", bytes.NewReader(body))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
	assert.True(t, res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusOK)

	// Stub token endpoint for client credentials: POST /oauth/token -> {access_token, expires_in}
	tokenMapping := map[string]interface{}{
		"request": map[string]interface{}{
			"method":  "POST",
			"urlPath": "/oauth/token",
		},
		"response": map[string]interface{}{
			"status": 200,
			"headers": map[string]interface{}{
				"Content-Type": "application/json",
			},
			"jsonBody": map[string]interface{}{
				"access_token": "ci-dummy-token",
				"expires_in":   3600,
			},
		},
	}
	tb, err := json.Marshal(tokenMapping)
	assert.NoError(t, err)
	treq, err := http.NewRequest(http.MethodPost, "http://localhost:9090/__admin/mappings", bytes.NewReader(tb))
	assert.NoError(t, err)
	treq.Header.Set("Content-Type", "application/json")
	tres, err := http.DefaultClient.Do(treq)
	assert.NoError(t, err)
		defer func() { _ = tres.Body.Close() }()
	assert.True(t, tres.StatusCode == http.StatusCreated || tres.StatusCode == http.StatusOK)
}

// Stubs WireMock token endpoint requiring form params: client_id/secret, scope, audience
func setupWireMockTokenFormExpectation(t *testing.T, clientID, clientSecret string, scopes []string, audience string) {
	resp, err := http.Get("http://localhost:9090/__admin/")
	if err != nil || resp.StatusCode >= 500 {
		t.Skip("WireMock (OAuth dummy) not available on localhost:9090; skipping OAuth functional test with form credentials")
		return
	}
	_ = resp.Body.Close()

	bodyPatterns := []map[string]interface{}{
		{"contains": "grant_type=client_credentials"},
		{"contains": "client_id=" + clientID},
		{"contains": "client_secret=" + clientSecret},
	}

	// scopes encoded with '+' between values by url.Values.Encode
	if len(scopes) > 0 {
		joined := scopes[0]
		for i := 1; i < len(scopes); i++ {
			joined += "+" + scopes[i]
		}
		bodyPatterns = append(bodyPatterns, map[string]interface{}{"contains": "scope=" + joined})
	}

	if audience != "" {
		bodyPatterns = append(bodyPatterns, map[string]interface{}{"contains": "audience=" + audience})
	}

	mapping := map[string]interface{}{
		"request": map[string]interface{}{
			"method":       "POST",
			"urlPath":      "/oauth/token",
			"bodyPatterns": bodyPatterns,
		},
		"response": map[string]interface{}{
			"status": 200,
			"headers": map[string]interface{}{
				"Content-Type": "application/json",
			},
			"jsonBody": map[string]interface{}{
				"access_token": "ci-dummy-token",
				"expires_in":   3600,
			},
		},
	}

	b, err := json.Marshal(mapping)
	assert.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "http://localhost:9090/__admin/mappings", bytes.NewReader(b))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
		defer func() { _ = res.Body.Close() }()
	assert.True(t, res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusOK)
}

func TestUpstreamTargetOAuth_ClientCredentials_WithClientSecretAudienceScopes(t *testing.T) {
	// Token endpoint should require form-encoded credentials, scopes and audience
	clientID := "my-client"
	clientSecret := "my-secret"
	scopes := []string{"read", "write"}
	audience := "my-api"

	setupWireMockProtectedEndpoint(t)
	setupWireMockTokenFormExpectation(t, clientID, clientSecret, scopes, audience)

	subdomain := fmt.Sprintf("oauth2-form-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "OAuth Target Gateway Form",
		"subdomain": subdomain,
	})
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("oauth-upstream-form-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     9090,
				"protocol": "http",
				"path":     "/protected",
				"weight":   100,
				"priority": 1,
				"auth": map[string]interface{}{
					"type": "oauth2",
					"oauth": map[string]interface{}{
						"token_url":      "http://localhost:9090/oauth/token",
						"grant_type":     "client_credentials",
						"use_basic_auth": false,
						"client_id":      clientID,
						"client_secret":  clientSecret,
						"scopes":         scopes,
						"audience":       audience,
					},
				},
			},
		},
	}
	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("oauth-service-form-%d", time.Now().Unix()),
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"path":       "/oauth-proxy-form",
		"service_id": serviceID,
		"methods":    []string{"GET"},
		"active":     true,
	}
	CreateRules(t, gatewayID, rulePayload)

	time.Sleep(2 * time.Second)

	req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/oauth-proxy-form", nil)
	assert.NoError(t, err)
	req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
	req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
	req.Header.Set("X-TG-API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Contains(t, string(b), "\"ok\":true")
}

func TestUpstreamTargetOAuth_ClientCredentials(t *testing.T) {
	setupWireMockProtectedEndpoint(t)

	subdomain := fmt.Sprintf("oauth-%d", time.Now().Unix())
	gatewayID := CreateGateway(t, map[string]interface{}{
		"name":      "OAuth Target Gateway",
		"subdomain": subdomain,
	})
	apiKey := CreateApiKey(t, gatewayID)

	upstreamPayload := map[string]interface{}{
		"name":      fmt.Sprintf("oauth-upstream-%d", time.Now().Unix()),
		"algorithm": "round-robin",
		"targets": []map[string]interface{}{
			{
				"host":     "localhost",
				"port":     9090, // WireMock
				"protocol": "http",
				"path":     "/protected",
				"weight":   100,
				"priority": 1,
				"auth": map[string]interface{}{
					"type": "oauth2",
					"oauth": map[string]interface{}{
						"token_url":      "http://localhost:9090/oauth/token",
						"grant_type":     "client_credentials",
						"use_basic_auth": true,
						"scopes":         []string{"read"},
					},
				},
			},
		},
	}
	upstreamID := CreateUpstream(t, gatewayID, upstreamPayload)

	serviceID := CreateService(t, gatewayID, map[string]interface{}{
		"name":        fmt.Sprintf("oauth-service-%d", time.Now().Unix()),
		"type":        "upstream",
		"upstream_id": upstreamID,
	})

	rulePayload := map[string]interface{}{
		"path":       "/oauth-proxy",
		"service_id": serviceID,
		"methods":    []string{"GET"},
		"active":     true,
	}
	CreateRules(t, gatewayID, rulePayload)

	time.Sleep(2 * time.Second)

	req, err := http.NewRequest(http.MethodGet, ProxyUrl+"/oauth-proxy", nil)
	assert.NoError(t, err)
	req.Host = fmt.Sprintf("%s.%s", subdomain, BaseDomain)
	req.Header.Set("Host", fmt.Sprintf("%s.%s", subdomain, BaseDomain))
	req.Header.Set("X-TG-API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	assert.Contains(t, string(b), "\"ok\":true")
}
