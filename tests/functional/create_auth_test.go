//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuth_Success_GeneratesKey(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-create")})
	name := uniqueName("api-key")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		validAuthPayload(name),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "api_key", body["type"])
	assert.Equal(t, true, body["enabled"])
	assert.NotEmpty(t, body["id"])

	// The plaintext key is generated server-side and returned exactly once.
	key, ok := body["api_key"].(string)
	require.True(t, ok, "create must surface the generated api_key: %v", body)
	assert.True(t, strings.HasPrefix(key, "ag_"), "generated key must carry the ag_ prefix: %q", key)

	// The secret never lives inside config: api_key auth carries no config block.
	cfg, ok := body["config"].(map[string]any)
	require.True(t, ok, "config missing: %v", body)
	_, hasAPIKeyCfg := cfg["api_key"]
	assert.False(t, hasAPIKeyCfg, "api_key auth must not echo a config.api_key block: %v", cfg)
}

func TestCreateAuth_OAuth2(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-oauth")})
	name := uniqueName("oauth")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": name,
			"type": "oauth2",
			"config": map[string]any{
				"oauth2": map[string]any{
					"issuer":        "https://issuer.example.com",
					"audiences":     []string{"gateway"},
					"jwks_url":      "https://issuer.example.com/.well-known/jwks.json",
					"client_secret": "topsecretclientvalue",
				},
			},
		},
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	cfg, _ := body["config"].(map[string]any)
	oauth, ok := cfg["oauth2"].(map[string]any)
	require.True(t, ok, "oauth2 config missing: %v", cfg)
	assert.Equal(t, "https://issuer.example.com", oauth["issuer"])
	assert.Equal(t, "***alue", oauth["client_secret"], "client_secret must be masked with a short tail")
}

func TestCreateAuth_OAuth2RequiresAudiences(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-oauth-aud")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{
			"name": uniqueName("oauth"),
			"type": "oauth2",
			"config": map[string]any{
				"oauth2": map[string]any{
					"issuer":   "https://issuer.example.com",
					"jwks_url": "https://issuer.example.com/.well-known/jwks.json",
				},
			},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateAuth_Conflict(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-dup")})
	name := uniqueName("api-key")
	_ = CreateAuth(t, gwID, validAuthPayload(name))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		validAuthPayload(name),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateAuth_InvalidType(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-val")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{"name": uniqueName("bad"), "type": "bogus"},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateAuth_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-noname")})

	payload := validAuthPayload("")
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
