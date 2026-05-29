package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteBackend_Success(t *testing.T) {
	defer Track(t, "DeleteBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("be-del-ok")))

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteBackend_NotFound(t *testing.T) {
	defer Track(t, "DeleteBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-notfound-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteBackend_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "DeleteBackend")()
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/backends/%s", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestDeleteBackend_InvalidBackendUUID(t *testing.T) {
	defer Track(t, "DeleteBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-baduuid-gw")})

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/backends/not-a-uuid", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestDeleteGateway_FailsWhenItHasBackends(t *testing.T) {
	defer Track(t, "DeleteBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-cascade-gw")})
	_ = CreateBackend(t, gwID, validBackendPayload(uniqueName("be-del-cascade-be")))

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "has_dependents", body["error"])
}
