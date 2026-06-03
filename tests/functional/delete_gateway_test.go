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

func TestDeleteGateway_Success(t *testing.T) {
	defer Track(t, "DeleteGateway")()
	id := CreateGateway(t, map[string]any{"name": uniqueName("del-ok")})

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id), nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, id), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteGateway_NotFound(t *testing.T) {
	defer Track(t, "DeleteGateway")()
	missing := uuid.NewString()
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s", AdminURL, missing), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteGateway_InvalidUUID(t *testing.T) {
	defer Track(t, "DeleteGateway")()
	status, body := sendRequest(t, http.MethodDelete,
		AdminURL+"/v1/gateways/not-a-uuid", nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
