//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuth_Success_MasksSecret(t *testing.T) {
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

	cfg, ok := body["config"].(map[string]any)
	require.True(t, ok, "config missing: %v", body)
	apiKey, ok := cfg["api_key"].(map[string]any)
	require.True(t, ok, "api_key config missing: %v", cfg)
	assert.Equal(t, "sk...key", apiKey["key"], "secret must be partially masked")
	assert.NotEqual(t, "sk-supersecretclientkey", apiKey["key"], "full secret must never be returned")
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
	assert.Equal(t, "to...lue", oauth["client_secret"], "client_secret must be masked")
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

func TestCreateAuth_ValidationMissingConfig(t *testing.T) {
	defer Track(t, "CreateAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-val")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gwID), nil,
		map[string]any{"name": uniqueName("bad"), "type": "api_key"},
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
