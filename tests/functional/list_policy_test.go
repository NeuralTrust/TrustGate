package functional_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListPolicies_Pagination(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("poll-gw")})

	prefix := uniqueName("poll-page")
	created := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		id := CreatePolicy(t, gwID, validPolicyPayload(fmt.Sprintf("%s-%d", prefix, i)))
		created = append(created, id)
	}

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/policies?name=%s&page=1&size=10",
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

func TestListPolicies_ScopedToGateway(t *testing.T) {
	gw1 := CreateGateway(t, map[string]any{"name": uniqueName("poll-gw1")})
	gw2 := CreateGateway(t, map[string]any{"name": uniqueName("poll-gw2")})

	_ = CreatePolicy(t, gw1, validPolicyPayload(uniqueName("poll-g1a")))
	_ = CreatePolicy(t, gw1, validPolicyPayload(uniqueName("poll-g1b")))
	_ = CreatePolicy(t, gw2, validPolicyPayload(uniqueName("poll-g2")))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/policies?page=1&size=50", AdminURL, gw1),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(2), body["total"])

	items, _ := body["items"].([]any)
	for _, raw := range items {
		obj, _ := raw.(map[string]any)
		assert.Equal(t, gw1, obj["gateway_id"], "list should only return policies for the gateway in the path")
	}
}

func TestListPolicies_FilterByName(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("poll-gw3")})

	uniq := uniqueName("poll-needle")
	id := CreatePolicy(t, gwID, validPolicyPayload(uniq))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/policies?name=%s",
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

func TestListPolicies_InvalidPagination(t *testing.T) {
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("poll-gw4")})
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/policies?page=-1", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_pagination", body["error"])
}
