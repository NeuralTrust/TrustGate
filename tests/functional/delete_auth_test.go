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

func TestDeleteAuth_Success(t *testing.T) {
	defer Track(t, "DeleteAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-del")})
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

func TestDeleteAuth_WhileAttachedAutoDetachesFromConsumer(t *testing.T) {
	defer Track(t, "DeleteAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-del-ref")})
	authID := CreateAuth(t, gwID, validAuthPayload(uniqueName("api-key-ref")))
	coID := CreateConsumer(t, gwID, validConsumerPayload(uniqueName("auth-del-ref-cons")))
	AttachAuth(t, gwID, coID, authID)

	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, authID), nil, nil,
	)
	require.Equal(t, http.StatusNoContent, status, "an attached auth must be deletable and auto-detached, body=%v", body)

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, authID), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "the deleted auth must be gone, body=%v", body)
	assert.Equal(t, "not_found", body["error"])

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID), nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "the consumer must survive the auth deletion, body=%v", body)
	assert.Empty(t, body["auth_ids"], "the auth must no longer be attached to the consumer")
}

func TestDeleteAuth_NotFound(t *testing.T) {
	defer Track(t, "DeleteAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-del-404")})
	status, body := sendRequest(t, http.MethodDelete,
		fmt.Sprintf("%s/v1/gateways/%s/auths/%s", AdminURL, gwID, uuid.NewString()), nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}
