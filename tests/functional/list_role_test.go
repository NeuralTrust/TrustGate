//go:build functional

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

func TestListRoles_Pagination(t *testing.T) {
	defer Track(t, "ListRole")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("role-list-gw")})
	prefix := uniqueName("role-list-page")
	created := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		id := CreateRole(t, gwID, map[string]any{"name": fmt.Sprintf("%s-%d", prefix, i)})
		created = append(created, id)
	}

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/roles?search=%s&page=1&size=10",
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
		assert.Contains(t, got, id)
	}
}

func TestListRoles_SearchAliasName(t *testing.T) {
	defer Track(t, "ListRole")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("role-search-gw")})
	uniq := uniqueName("role-needle")
	id := CreateRole(t, gwID, map[string]any{"name": uniq})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/roles?name=%s",
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

func TestListRoles_SortByNameAsc(t *testing.T) {
	defer Track(t, "ListRole")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("role-sort-gw")})
	prefix := uniqueName("role-sort")
	_ = CreateRole(t, gwID, map[string]any{"name": prefix + "-c"})
	_ = CreateRole(t, gwID, map[string]any{"name": prefix + "-a"})
	_ = CreateRole(t, gwID, map[string]any{"name": prefix + "-b"})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/roles?search=%s&sort=name&order=asc",
			AdminURL, gwID, url.QueryEscape(prefix)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	items, _ := body["items"].([]any)
	require.Len(t, items, 3)
	names := make([]string, 0, 3)
	for _, raw := range items {
		obj, _ := raw.(map[string]any)
		names = append(names, obj["name"].(string))
	}
	assert.Equal(t, []string{prefix + "-a", prefix + "-b", prefix + "-c"}, names)
}

func TestListRoles_ScopedByGateway(t *testing.T) {
	defer Track(t, "ListRole")()
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("role-scope-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("role-scope-b")})
	idA := CreateRole(t, gwA, map[string]any{"name": uniqueName("role-a")})
	idB := CreateRole(t, gwB, map[string]any{"name": uniqueName("role-b")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/roles", AdminURL, gwA),
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
	assert.True(t, sawA)
	assert.False(t, sawB)
}

func TestListRoles_InvalidSort(t *testing.T) {
	defer Track(t, "ListRole")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("role-badsort-gw")})

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/roles?sort=not_a_field", AdminURL, gwID),
		nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_sort", body["error"])
}

func TestListRoles_UnknownGatewayReturnsEmpty(t *testing.T) {
	defer Track(t, "ListRole")()
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/roles", AdminURL, uuid.NewString()),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(0), body["total"])
}
