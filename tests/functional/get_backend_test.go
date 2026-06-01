package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBackend_Success(t *testing.T) {
	defer Track(t, "GetBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-get-gw")})
	name := uniqueName("be-get-ok")
	beID := CreateBackend(t, gwID, validBackendPayload(name))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, beID, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "openai", body["provider"])
}

func TestGetBackend_NotFound(t *testing.T) {
	defer Track(t, "GetBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-get-notfound-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestGetBackend_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "GetBackend")()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/backends/%s", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestGetBackend_InvalidBackendUUID(t *testing.T) {
	defer Track(t, "GetBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-get-baduuid-gw")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends/not-a-uuid", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
