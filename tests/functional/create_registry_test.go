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

func TestCreateRegistry_Success(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-create-gw")})
	name := uniqueName("be-create-ok")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil,
		validRegistryPayload(name),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	assert.NotEmpty(t, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "openai", body["provider"])
	assert.NotEmpty(t, body["created_at"])
	assert.NotEmpty(t, body["updated_at"])

	auth, ok := body["auth"].(map[string]any)
	require.True(t, ok, "auth missing or wrong type: %v", body)
	assert.Equal(t, "api_key", auth["type"])
	apiKey, _ := auth["api_key"].(map[string]any)
	assert.Equal(t, "***", apiKey["api_key"], "api key must be redacted in response")
}

func TestCreateRegistry_ConflictSameGateway(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-conflict-gw")})
	name := uniqueName("be-conflict")

	_ = CreateRegistry(t, gwID, validRegistryPayload(name))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil,
		validRegistryPayload(name),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateRegistry_SameNameDifferentGatewaysAllowed(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("be-shared-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("be-shared-b")})
	shared := uniqueName("be-shared-name")

	_ = CreateRegistry(t, gwA, validRegistryPayload(shared))
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwB),
		nil,
		validRegistryPayload(shared),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
}

func TestCreateRegistry_GatewayDoesNotExist(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	missingGW := uuid.NewString()
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, missingGW),
		nil,
		validRegistryPayload(uniqueName("be-no-gw")),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateRegistry_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/registries",
		nil,
		validRegistryPayload(uniqueName("be-invalid-uuid")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestCreateRegistry_ValidationEmptyName(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-emptyname-gw")})
	payload := validRegistryPayload("")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateRegistry_ValidationNoProvider(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-noprovider-gw")})

	payload := validRegistryPayload(uniqueName("be-noprovider"))
	delete(payload, "provider")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateRegistry_ValidationNoAuth(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-noauth-gw")})

	payload := validRegistryPayload(uniqueName("be-noauth"))
	delete(payload, "auth")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateRegistry_InvalidBody(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-badbody-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil, "not-an-object",
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateRegistry_WithHealthChecks(t *testing.T) {
	defer Track(t, "CreateRegistry")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("be-hc-gw")})
	payload := validRegistryPayload(uniqueName("be-hc"))
	payload["health_checks"] = map[string]any{
		"passive":   true,
		"threshold": 3,
		"interval":  30,
	}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/registries", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	hc, ok := body["health_checks"].(map[string]any)
	require.True(t, ok, "health_checks missing: %v", body)
	assert.Equal(t, true, hc["passive"])
	assert.Equal(t, float64(3), hc["threshold"])
	assert.Equal(t, float64(30), hc["interval"])
}
