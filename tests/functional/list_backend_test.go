package functional_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListBackends_Pagination(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-list-gw")})
	prefix := uniqueName("be-list-page")
	created := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		id := CreateBackend(t, gwID, validBackendPayload(fmt.Sprintf("%s-%d", prefix, i)))
		created = append(created, id)
	}

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends?name=%s&page=1&size=10",
			AdminURL, gwID, url.QueryEscape(prefix)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	items, ok := body["items"].([]any)
	require.True(t, ok, "items missing or wrong type: %v", body)
	assert.Equal(t, float64(3), body["total"])
	assert.Equal(t, float64(1), body["page"])
	assert.Equal(t, float64(10), body["size"])
	assert.Len(t, items, 3)

	gotIDs := make(map[string]struct{}, len(items))
	for _, raw := range items {
		obj, ok := raw.(map[string]any)
		require.True(t, ok)
		id, _ := obj["id"].(string)
		gotIDs[id] = struct{}{}
	}
	for _, id := range created {
		assert.Contains(t, gotIDs, id, "expected id %s in list", id)
	}
}

func TestListBackends_FilterByName(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-list-filter-gw")})
	uniq := uniqueName("be-list-needle")
	id := CreateBackend(t, gwID, validBackendPayload(uniq))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends?name=%s",
			AdminURL, gwID, url.QueryEscape(uniq)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(1), body["total"])

	items, _ := body["items"].([]any)
	require.Len(t, items, 1)
	obj, _ := items[0].(map[string]any)
	assert.Equal(t, id, obj["id"])
}

func TestListBackends_ScopedByGateway(t *testing.T) {
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("be-scope-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("be-scope-b")})

	idA := CreateBackend(t, gwA, validBackendPayload(uniqueName("be-scope-be-a")))
	idB := CreateBackend(t, gwB, validBackendPayload(uniqueName("be-scope-be-b")))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, gwA),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	items, _ := body["items"].([]any)
	var sawA, sawB bool
	for _, raw := range items {
		obj, _ := raw.(map[string]any)
		switch obj["id"] {
		case idA:
			sawA = true
		case idB:
			sawB = true
		}
	}
	assert.True(t, sawA, "expected backend from gateway A in its list")
	assert.False(t, sawB, "backend from gateway B must not appear in gateway A's list")
}

func TestListBackends_InvalidPagination(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("be-list-badpage-gw")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends?page=-1", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_pagination", body["error"])
}

func TestListBackends_InvalidGatewayUUID(t *testing.T) {
	status, body := sendRequest(t, http.MethodGet,
		AdminURL+"/v1/gateways/not-a-uuid/backends", nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestListBackends_UnknownGatewayReturnsEmpty(t *testing.T) {
	missing := uuid.NewString()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/backends", AdminURL, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(0), body["total"])
	items, _ := body["items"].([]any)
	assert.Empty(t, items)
}
