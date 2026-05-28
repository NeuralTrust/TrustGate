package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateBackend_Success(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-create-gw")})
	name := uniqueName("be-create-ok")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil,
		validBackendPayload(name),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	assert.NotEmpty(t, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "round-robin", body["algorithm"])
	assert.NotEmpty(t, body["created_at"])
	assert.NotEmpty(t, body["updated_at"])

	targets, ok := body["targets"].([]any)
	require.True(t, ok, "targets missing or wrong type: %v", body)
	require.Len(t, targets, 1)
	first, _ := targets[0].(map[string]any)
	assert.Equal(t, "openai", first["provider"])

	auth, ok := first["auth"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "api_key", auth["type"])
	apiKey, _ := auth["api_key"].(map[string]any)
	assert.Equal(t, "***", apiKey["api_key"], "api key must be redacted in response")
}

func TestCreateBackend_ConflictSameGateway(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-conflict-gw")})
	name := uniqueName("be-conflict")

	_ = CreateBackend(t, gwID, validBackendPayload(name))

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil,
		validBackendPayload(name),
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestCreateBackend_SameNameDifferentGatewaysAllowed(t *testing.T) {
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("be-shared-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("be-shared-b")})
	shared := uniqueName("be-shared-name")

	_ = CreateBackend(t, gwA, validBackendPayload(shared))
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwB),
		nil,
		validBackendPayload(shared),
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
}

func TestCreateBackend_GatewayDoesNotExist(t *testing.T) {
	missingGW := uuid.NewString()
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, missingGW),
		nil,
		validBackendPayload(uniqueName("be-no-gw")),
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateBackend_InvalidGatewayUUID(t *testing.T) {
	status, body := sendRequest(t, http.MethodPost,
		AdminURL+"/v1/gateways/not-a-uuid/backends",
		nil,
		validBackendPayload(uniqueName("be-invalid-uuid")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestCreateBackend_ValidationEmptyName(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-emptyname-gw")})
	payload := validBackendPayload("")

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateBackend_ValidationNoTargets(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-notargets-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil,
		map[string]any{
			"name":      uniqueName("be-notargets"),
			"algorithm": "round-robin",
			"targets":   []map[string]any{},
		},
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateBackend_ValidationUnknownAlgorithm(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-badalg-gw")})

	payload := validBackendPayload(uniqueName("be-badalg"))
	payload["algorithm"] = "least-conn"

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateBackend_SemanticRequiresEmbeddingAndDescriptions(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-semantic-gw")})

	payload := validBackendPayload(uniqueName("be-semantic-noembed"))
	payload["algorithm"] = "semantic"
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateBackend_InvalidBody(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-badbody-gw")})

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil, "not-an-object",
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestCreateBackend_WithHealthChecks(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-hc-gw")})
	payload := validBackendPayload(uniqueName("be-hc"))
	payload["health_checks"] = map[string]any{
		"passive":   true,
		"threshold": 3,
		"interval":  30,
	}

	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwID),
		nil, payload,
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)

	hc, ok := body["health_checks"].(map[string]any)
	require.True(t, ok, "health_checks missing: %v", body)
	assert.Equal(t, true, hc["passive"])
	assert.Equal(t, float64(3), hc["threshold"])
	assert.Equal(t, float64(30), hc["interval"])
}
