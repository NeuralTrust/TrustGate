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

func TestListConsumers_Pagination(t *testing.T) {
	defer Track(t, "ListConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-list-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-list-be")))
	prefix := uniqueName("co-list-page")
	created := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		id := CreateConsumer(t, gwID, validConsumerPayload(fmt.Sprintf("%s-%d", prefix, i), beID))
		created = append(created, id)
	}

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers?name=%s&page=1&size=10",
			AdminURL, gwID, url.QueryEscape(prefix)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	items, ok := body["items"].([]any)
	require.True(t, ok, "items missing: %v", body)
	assert.Equal(t, float64(3), body["total"])
	assert.Equal(t, float64(1), body["page"])
	assert.Equal(t, float64(10), body["size"])
	assert.Len(t, items, 3)

	got := make(map[string]struct{}, len(items))
	for _, raw := range items {
		obj, _ := raw.(map[string]any)
		id, _ := obj["id"].(string)
		got[id] = struct{}{}
	}
	for _, id := range created {
		assert.Contains(t, got, id, "expected id %s in list", id)
	}
}

func TestListConsumers_FilterByName(t *testing.T) {
	defer Track(t, "ListConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-list-filter-gw")})
	beID := CreateBackend(t, gwID, validBackendPayload(uniqueName("co-list-filter-be")))
	uniq := uniqueName("co-list-needle")
	id := CreateConsumer(t, gwID, validConsumerPayload(uniq, beID))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers?name=%s",
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

func TestListConsumers_ScopedByGateway(t *testing.T) {
	defer Track(t, "ListConsumer")()
	gwA := CreateGateway(t, map[string]any{"name": uniqueName("co-scope-a")})
	gwB := CreateGateway(t, map[string]any{"name": uniqueName("co-scope-b")})
	beA := CreateBackend(t, gwA, validBackendPayload(uniqueName("co-scope-be-a")))
	beB := CreateBackend(t, gwB, validBackendPayload(uniqueName("co-scope-be-b")))

	idA := CreateConsumer(t, gwA, validConsumerPayload(uniqueName("co-scope-co-a"), beA))
	idB := CreateConsumer(t, gwB, validConsumerPayload(uniqueName("co-scope-co-b"), beB))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, gwA),
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
	assert.True(t, sawA, "expected consumer from gateway A in its list")
	assert.False(t, sawB, "consumer from gateway B must not appear in gateway A's list")
}

func TestListConsumers_InvalidPagination(t *testing.T) {
	defer Track(t, "ListConsumer")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("co-list-badpage-gw")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers?page=-1", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_pagination", body["error"])
}

func TestListConsumers_InvalidGatewayUUID(t *testing.T) {
	defer Track(t, "ListConsumer")()
	status, body := sendRequest(t, http.MethodGet,
		AdminURL+"/v1/gateways/not-a-uuid/consumers", nil, nil,
	)
	require.Equal(t, http.StatusBadRequest, status, "body=%v", body)
	assert.Equal(t, "invalid_uuid", body["error"])
}

func TestListConsumers_UnknownGatewayReturnsEmpty(t *testing.T) {
	defer Track(t, "ListConsumer")()
	missing := uuid.NewString()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/consumers", AdminURL, missing),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(0), body["total"])
	items, _ := body["items"].([]any)
	assert.Empty(t, items)
}
