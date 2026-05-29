package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateAuth_Success(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-upd")})
	id := CreateAuth(t, gwID, validAuthPayload(uniqueName("api-key")))

	newName := uniqueName("renamed")
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil,
		map[string]any{
			"name":    newName,
			"type":    "api_key",
			"enabled": false,
			"config": map[string]any{
				"api_key": map[string]any{"key": "sk-rotatedsecretvalue"},
			},
		},
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, newName, body["name"])
	assert.Equal(t, false, body["enabled"])

	cfg, _ := body["config"].(map[string]any)
	apiKey, ok := cfg["api_key"].(map[string]any)
	require.True(t, ok, "api_key config missing: %v", cfg)
	assert.Equal(t, "sk...lue", apiKey["key"], "rotated secret must be masked")
}

func TestUpdateAuth_Validation(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-upd-val")})
	id := CreateAuth(t, gwID, validAuthPayload(uniqueName("api-key")))

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil,
		map[string]any{"name": "", "type": "api_key"},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}
