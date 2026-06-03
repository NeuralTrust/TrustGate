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

func TestDeleteConsumer_Success(t *testing.T) {
	defer Track(t, "DeleteConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-del-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-del-be")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("co-del-ok"), beID))

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteConsumer_NotFound(t *testing.T) {
	defer Track(t, "DeleteConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-del-notfound-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteConsumer_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "DeleteConsumer")()
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/consumers/%s", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestDeleteConsumer_InvalidConsumerUUID(t *testing.T) {
	defer Track(t, "DeleteConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-del-baduuid-gw")})

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/not-a-uuid", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestDeleteGateway_FailsWhenItHasConsumers(t *testing.T) {
	defer Track(t, "DeleteConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-del-gw-cascade")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-del-gw-cascade-be")))
	_ = CreateConsumer(t, gwID, validConsumerPayload(uniqueName("co-del-gw-cascade-co"), beID))

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "has_dependents", body["error"])
}

func TestDeleteRegistry_FailsWhenReferencedByConsumer(t *testing.T) {
	defer Track(t, "DeleteConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-del-be-ref-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("co-del-be-ref-be")))
	_ = CreateConsumer(t, gwID, validConsumerPayload(uniqueName("co-del-be-ref"), beID))

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "has_dependents", body["error"])
}
