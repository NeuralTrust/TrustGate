//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListAuths_MasksSecrets(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-list")})
	prefix := uniqueName("listed")
	for i := 0; i < 3; i++ {
		_ = CreateAuth(t, gwID, validAuthPayload(fmt.Sprintf("%s-%d", prefix, i)))
	}

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?name=%s&page=1&size=10",
			AdminURL, gwID, url.QueryEscape(prefix)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)

	items, ok := body["items"].([]any)
	require.True(t, ok, "items missing: %v", body)
	assert.Equal(t, float64(3), body["total"])
	require.Len(t, items, 3)

	for _, raw := range items {
		obj, ok := raw.(map[string]any)
		require.True(t, ok)
		cfg, _ := obj["config"].(map[string]any)
		apiKey, ok := cfg["api_key"].(map[string]any)
		require.True(t, ok, "api_key config missing in list item: %v", obj)
		assert.Equal(t, "sk...key", apiKey["key"], "list must mask secrets")
		assert.NotEqual(t, "sk-supersecretclientkey", apiKey["key"])
	}
}

func TestListAuths_InvalidPagination(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"name": uniqueName("auth-list-bad")})
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?page=-1", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_pagination", body["error"])
}
