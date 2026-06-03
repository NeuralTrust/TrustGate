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

func TestGetConsumer_Success(t *testing.T) {
	defer Track(t, "GetConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-get-gw")})
	name := uniqueName("co-get-ok")
	coID := CreateConsumer(t, gwID, validConsumerPayload(name))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, coID),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, coID, body["id"])
	assert.Equal(t, gwID, body["gateway_id"])
	assert.Equal(t, name, body["name"])
	assert.Equal(t, "LLM", body["type"])
}

func TestGetConsumer_NotFound(t *testing.T) {
	defer Track(t, "GetConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-get-notfound-gw")})
	missing := uuid.NewString()

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/%s", AdminURL, gwID, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusNotFound, status, "body=%v", body)
	assert.Equal(t, "not_found", body["error"])
}

func TestGetConsumer_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "GetConsumer")()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/not-a-uuid/consumers/%s", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestGetConsumer_InvalidConsumerUUID(t *testing.T) {
	defer Track(t, "GetConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-get-baduuid-gw")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers/not-a-uuid", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}
