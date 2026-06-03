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

func TestGetRegistry_Success(t *testing.T) {
	defer Track(t, "GetRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-get-gw")})
	name := uniqueName("be-get-ok")
	beID := CreateRegistry(t, gwID, validRegistryPayload(name))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, beID, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "openai", body["provider"])
}

func TestGetRegistry_NotFound(t *testing.T) {
	defer Track(t, "GetRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-get-notfound-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestGetRegistry_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "GetRegistry")()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/registries/%s", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestGetRegistry_InvalidRegistryUUID(t *testing.T) {
	defer Track(t, "GetRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-get-baduuid-gw")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/registries/not-a-uuid", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
