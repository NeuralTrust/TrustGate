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

func TestGetGateway_Success(t *testing.T) {
	defer Track(t, "GetGateway")()
	name := uniqueName("get-ok")
	id := CreateGateway(t, map[string]any{"name": name})

	status, body := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, id, body["id"])
	assert.Equal(t, name, body["name"])
}

func TestGetGateway_NotFound(t *testing.T) {
	defer Track(t, "GetGateway")()
	missing := uuid.NewString()
	status, body := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s", AdminURL, missing), nil, nil)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestGetGateway_InvalidUUID(t *testing.T) {
	defer Track(t, "GetGateway")()
	status, body := sendRequest(t, http.MethodGet, AdminURL+"/v1/gateways/not-a-uuid", nil, nil)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
