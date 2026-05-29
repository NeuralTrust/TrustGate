package functional_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteAuth_Success(t *testing.T) {
	defer Track(t, "DeleteAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-del")})
	id := CreateAuth(t, gwID, validAuthPayload(uniqueName("api-key")))

	status, _ := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status)

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, id), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestDeleteAuth_NotFound(t *testing.T) {
	defer Track(t, "DeleteAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-del-404")})
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, uuid.NewString()), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}
