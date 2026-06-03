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

func TestGetAuth_Success_MasksSecret(t *testing.T) {
	defer Track(t, "GetAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-get")})
	name := uniqueName("api-key")
	id := CreateAuth(t, gwID, validAuthPayload(name))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, id, body["id"])
	assert.Equal(t, name, body["name"])

	cfg, _ := body["config"].(map[string]any)
	apiKey, ok := cfg["api_key"].(map[string]any)
	require.True(t, ok, "api_key config missing: %v", cfg)
	assert.Equal(t, "sk...key", apiKey["key"], "GET must also mask the secret")
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
