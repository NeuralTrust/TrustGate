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

func TestDeleteRegistry_CascadesConsumerAttachment(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-casc-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("be-del-casc-be")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("be-del-casc-cons")))
	AttachRegistry(t, gwID, coID, beID)

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status, "an attached registry must be deletable, body=%v", body)

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "the consumer must survive the registry deletion, body=%v", body)
	assert.Empty(t, body["registry_ids"], "the consumer_registry relation must be removed in cascade")
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

func TestDeleteGateway_CascadesRegistries(t *testing.T) {
	defer Track(t, "DeleteRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-del-cascade-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("be-del-cascade-be")))

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status, "deleting a gateway must cascade to its registries, body=%v", body)

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "the registry must be gone after the gateway deletion, body=%v", body)
}
