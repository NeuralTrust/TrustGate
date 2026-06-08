//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateAuth_Success(t *testing.T) {
	defer Track(t, "UpdateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-upd")})
	id, _ := CreateAPIKeyAuth(t, gwID, uniqueName("api-key"))

	newName := uniqueName("renamed")
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil,
		map[string]any{
			"name":    newName,
			"type":    "api_key",
			"enabled": false,
		},
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, newName, body["name"])
	assert.Equal(t, false, body["enabled"])

	// Update never rotates or re-reveals the key: no plaintext and no config
	// secret come back.
	_, hasTopLevelKey := body["api_key"]
	assert.False(t, hasTopLevelKey, "update must not re-reveal the api_key: %v", body)
	cfg, _ := body["config"].(map[string]any)
	_, hasAPIKeyCfg := cfg["api_key"]
	assert.False(t, hasAPIKeyCfg, "api_key auth must not carry a config.api_key block: %v", cfg)
}

func TestUpdateAuth_Partial_OAuth2PreservesConfig(t *testing.T) {
	defer Track(t, "UpdateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-upd-oauth-gw")})
	id := CreateAuth(t, gwID, map[string]any{
		"name": uniqueName("oauth-cred"),
		"type": "oauth2",
		"config": map[string]any{
			"oauth2": map[string]any{
				"issuer":        "https://issuer.example.com",
				"jwks_url":      "https://issuer.example.com/jwks",
				"client_id":     "client-123",
				"client_secret": "super-secret",
			},
		},
	})

	renamed := uniqueName("oauth-renamed")
	url := fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id)
	status, body := sendRequest(t, http.MethodPut, url, nil, map[string]any{"name": renamed})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, renamed, body["name"])
	assert.Equal(t, "oauth2", body["type"], "type must be preserved on a partial update")

	cfg, ok := body["config"].(map[string]any)
	require.True(t, ok, "config must be preserved on a partial update: %v", body)
	oauth2, ok := cfg["oauth2"].(map[string]any)
	require.True(t, ok, "oauth2 config block must be preserved: %v", cfg)
	assert.Equal(t, "https://issuer.example.com", oauth2["issuer"])
}

func TestUpdateAuth_Validation(t *testing.T) {
	defer Track(t, "UpdateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-upd-val")})
	id := CreateAuth(t, gwID, validAuthPayload(uniqueName("api-key")))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil,
		map[string]any{"name": "", "type": "api_key"},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
