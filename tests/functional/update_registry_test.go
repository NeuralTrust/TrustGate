package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateRegistry_Success(t *testing.T) {
	defer Track(t, "UpdateRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-gw")})
	original := uniqueName("be-upd-from")
	beID := CreateRegistry(t, gwID, validRegistryPayload(original))

	updatedName := uniqueName("be-upd-to")
	payload := validRegistryPayload(updatedName)
	payload["provider"] = "anthropic"

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, updatedName, body["name"])
	assert.Equal(t, "anthropic", body["provider"])

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, updatedName, body["name"])
	assert.Equal(t, "anthropic", body["provider"])
}

func TestUpdateRegistry_NotFound(t *testing.T) {
	defer Track(t, "UpdateRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-missing-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, missing),
		nil,
		validRegistryPayload(uniqueName("be-upd-missing")),
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestUpdateRegistry_ValidationEmptyName(t *testing.T) {
	defer Track(t, "UpdateRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-val-gw")})
	beID := CreateRegistry(t, gwID, validRegistryPayload(uniqueName("be-upd-val")))

	payload := validRegistryPayload("")
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, beID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateRegistry_NameConflictSameGateway(t *testing.T) {
	defer Track(t, "UpdateRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-conflict-gw")})
	a := uniqueName("be-upd-a")
	b := uniqueName("be-upd-b")
	_ = CreateRegistry(t, gwID, validRegistryPayload(a))
	bID := CreateRegistry(t, gwID, validRegistryPayload(b))

	payload := validRegistryPayload(a)
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/registries/%s", AdminURL, gwID, bID),
		nil, payload,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestUpdateRegistry_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "UpdateRegistry")()
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/registries/%s", AdminURL, uuid.NewString()),
		nil,
		validRegistryPayload(uniqueName("be-upd-bad-gw")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestUpdateRegistry_InvalidRegistryUUID(t *testing.T) {
	defer Track(t, "UpdateRegistry")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-bad-be-gw")})

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/registries/not-a-uuid", AdminURL, gwID),
		nil,
		validRegistryPayload(uniqueName("be-upd-bad-be")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
