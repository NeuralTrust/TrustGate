//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAuth_Success_NeverReturnsSecret(t *testing.T) {
	defer Track(t, "GetAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-get")})
	name := uniqueName("api-key")
	id, _ := CreateAPIKeyAuth(t, gwID, name)

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, id, body["id"])
	assert.Equal(t, name, body["name"])

	// The key is hash-only storage: GET never returns the plaintext, neither at
	// the top level nor inside a config block.
	_, hasTopLevelKey := body["api_key"]
	assert.False(t, hasTopLevelKey, "GET must not return the api_key (shown only once at creation): %v", body)
	cfg, _ := body["config"].(map[string]any)
	_, hasAPIKeyCfg := cfg["api_key"]
	assert.False(t, hasAPIKeyCfg, "api_key auth must not carry a config.api_key block: %v", cfg)
}

func TestGetAuth_NotFound(t *testing.T) {
	defer Track(t, "GetAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-get-404")})
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, uuid.NewString()), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestGetAuth_InvalidUUID(t *testing.T) {
	defer Track(t, "GetAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-get-bad")})
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/not-a-uuid", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
