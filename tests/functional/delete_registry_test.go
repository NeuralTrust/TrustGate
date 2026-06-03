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

func TestDeleteRegistry_Success(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("be-del-ok")))

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteRegistry_NotFound(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-notfound-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteRegistry_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/registries/%s", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestDeleteRegistry_InvalidRegistryUUID(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-baduuid-gw")})

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/registries/not-a-uuid", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestDeleteGateway_FailsWhenItHasBackends(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-cascade-gw")})
	_ = CreateRegistry(t, gwID, validRegistryPayload(uniqueName("be-del-cascade-be")))

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "has_dependents", body["error"])
}
