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

func TestGetPolicy_Success(t *testing.T) {
	defer Track(t, "GetPolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polg-gw")})
	name := uniqueName("polg-ok")
	id := CreatePolicy(t, gwID, validPolicyPayload(name))

	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, id)
	status, body := sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, id, body["id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, gwID, body["gateway_id"])
}

func TestGetPolicy_NotFound(t *testing.T) {
	defer Track(t, "GetPolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polg-gw2")})
	missing := uuid.NewString()
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/%s", AdminURL, gwID, missing)
	status, body := sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestGetPolicy_InvalidUUID(t *testing.T) {
	defer Track(t, "GetPolicy")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("polg-gw3")})
	url := fmt.Sprintf("%s/v1/gateways/%s/policies/not-a-uuid", AdminURL, gwID)
	status, body := sendRequest(t, http.MethodGet, url, nil, nil)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
