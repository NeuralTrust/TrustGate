package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateBackend_Success(t *testing.T) {
	defer Track(t, "UpdateBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-gw")})
	original := uniqueName("be-upd-from")
	beID := CreateBackend(t, gwID, validBackendPayload(original))

	updatedName := uniqueName("be-upd-to")
	payload := validBackendPayload(updatedName)
	payload["provider"] = "anthropic"

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, beID),
		nil, payload,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, updatedName, body["name"])
	assert.Equal(t, "anthropic", body["provider"])

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, beID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, updatedName, body["name"])
	assert.Equal(t, "anthropic", body["provider"])
}

func TestUpdateBackend_NotFound(t *testing.T) {
	defer Track(t, "UpdateBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-missing-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, missing),
		nil,
		validBackendPayload(uniqueName("be-upd-missing")),
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestUpdateBackend_ValidationEmptyName(t *testing.T) {
	defer Track(t, "UpdateBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-val-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("be-upd-val")))

	payload := validBackendPayload("")
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, beID),
		nil, payload,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "validation_failed", body["error"])
}

func TestUpdateBackend_NameConflictSameGateway(t *testing.T) {
	defer Track(t, "UpdateBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-conflict-gw")})
	a := uniqueName("be-upd-a")
	b := uniqueName("be-upd-b")
	_ = CreateBackend(t, gwID, validBackendPayload(a))
	bID := CreateBackend(t, gwID, validBackendPayload(b))

	payload := validBackendPayload(a)
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/backends/%s", AdminURL, gwID, bID),
		nil, payload,
	)
	require.Equal(t, http.StatusConflict, status, "body=%v", body)
	assert.Equal(t, "already_exists", body["error"])
}

func TestUpdateBackend_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "UpdateBackend")()
	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/backends/%s", AdminURL, uuid.NewString()),
		nil,
		validBackendPayload(uniqueName("be-upd-bad-gw")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestUpdateBackend_InvalidBackendUUID(t *testing.T) {
	defer Track(t, "UpdateBackend")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-upd-bad-be-gw")})

	status, body := sendRequest(t, http.MethodPut,
		fmt.Sprintf("%s/v1/gateways/%s/backends/not-a-uuid", AdminURL, gwID),
		nil,
		validBackendPayload(uniqueName("be-upd-bad-be")),
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
