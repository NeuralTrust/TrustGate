package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeletePolicy_Success(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("pold-gw")})
	id := CreatePolicy(t, gwID, validPolicyPayload(uniqueName("pold-ok")))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, id)
	status, _ := sendRequest(t, http.MethodDelete, url, nil, nil)
	require.Equal(t, http.StatusNoContent, status)

	status, body := sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeletePolicy_NotFound(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("pold-gw2")})
	missing := uuid.NewString()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, missing)
	status, body := sendRequest(t, http.MethodDelete, url, nil, nil)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeletePolicy_InvalidUUID(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("pold-gw3")})
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/not-a-uuid", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodDelete, url, nil, nil)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
