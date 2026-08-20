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

func TestListAuths_NeverReturnsSecrets(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-list")})
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
		_, hasTopLevelKey := obj["api_key"]
		assert.False(t, hasTopLevelKey, "list must never return plaintext keys: %v", obj)
		cfg, _ := obj["config"].(map[string]any)
		_, hasAPIKeyCfg := cfg["api_key"]
		assert.False(t, hasAPIKeyCfg, "api_key auth must not carry a config.api_key block: %v", obj)
	}
}

func TestListAuths_InvalidPagination(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-list-bad")})
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?page=-1", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_pagination", body["error"])
}

func TestListAuths_FilterByNameAndGateway(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwA := CreateGateway(t, map[string]any{"slug": uniqueName("auth-scope-a")})
	gwB := CreateGateway(t, map[string]any{"slug": uniqueName("auth-scope-b")})
	uniq := uniqueName("auth-needle")
	idA := CreateAuth(t, gwA, validAuthPayload(uniq))
	_ = CreateAuth(t, gwB, validAuthPayload(uniqueName("auth-other")))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?search=%s", AdminURL, gwA, url.QueryEscape(uniq)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(1), body["total"])
	items, _ := body["items"].([]any)
	require.Len(t, items, 1)
	obj, _ := items[0].(map[string]any)
	assert.Equal(t, idA, obj["id"])
}

func TestListAuths_FilterByTypeAndEnabled(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-type-gw")})
	prefix := uniqueName("auth-type")
	_ = CreateAuth(t, gwID, validAuthPayload(prefix+"-on"))

	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?search=%s&type=api_key&enabled=true",
			AdminURL, gwID, url.QueryEscape(prefix)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(1), body["total"])

	status, body = sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?search=%s&type=oauth2",
			AdminURL, gwID, url.QueryEscape(prefix)),
		nil, nil,
	)
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, float64(0), body["total"])
}

func TestListAuths_TypeFilterAcceptsTheLegacyOIDCAlias(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-oidc-filter")})
	name := uniqueName("oidc-filtered")
	authID := CreateAuth(t, gwID, map[string]any{
		"name": name,
		"type": "oidc",
		"config": map[string]any{
			"oidc": map[string]any{
				"issuer":    "https://issuer.example.com",
				"audiences": []string{"gateway"},
				"jwks_url":  "https://issuer.example.com/.well-known/jwks.json",
			},
		},
	})

	pageFor := func(t *testing.T, authType string) map[string]any {
		t.Helper()
		status, body := sendRequest(t, http.MethodGet,
			fmt.Sprintf("%s/v1/gateways/%s/auths?search=%s&type=%s",
				AdminURL, gwID, url.QueryEscape(name), authType),
			nil, nil,
		)
		require.Equal(t, http.StatusOK, status, "type=%s body=%v", authType, body)
		return body
	}

	aliased := pageFor(t, "oidc")
	canonical := pageFor(t, "oauth2")

	assert.Equal(t, float64(1), aliased["total"], "the alias must not yield an empty page: %v", aliased)
	assert.Equal(t, canonical["total"], aliased["total"])
	assert.Equal(t, canonical["items"], aliased["items"])

	items, ok := aliased["items"].([]any)
	require.True(t, ok, "items missing: %v", aliased)
	require.Len(t, items, 1)
	item, ok := items[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, authID, item["id"])
	assert.Equal(t, "oauth2", item["type"])
}

func TestListAuths_TypeFilterFindsRowsStoredAsOIDC(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-stored-oidc")})
	name := uniqueName("stored-oidc")
	authID := SeedStoredOIDCAuth(t, gwID, name, "https://stored.example.com", []string{"gateway"})

	for _, authType := range []string{"oidc", "oauth2"} {
		t.Run(authType, func(t *testing.T) {
			status, body := sendRequest(t, http.MethodGet,
				fmt.Sprintf("%s/v1/gateways/%s/auths?search=%s&type=%s",
					AdminURL, gwID, url.QueryEscape(name), authType),
				nil, nil,
			)
			require.Equal(t, http.StatusOK, status, "body=%v", body)

			items, ok := body["items"].([]any)
			require.True(t, ok, "items missing: %v", body)
			require.Len(t, items, 1, "a row stored as oidc must stay listable under ?type=%s", authType)
			assert.Equal(t, float64(len(items)), body["total"],
				"pagination total disagrees with the page")

			item, ok := items[0].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, authID, item["id"])
			assert.Equal(t, "oauth2", item["type"])
		})
	}
}

func TestListAuths_InvalidSort(t *testing.T) {
	defer Track(t, "ListAuth")()
	gwID := CreateGateway(t, map[string]any{"slug": uniqueName("auth-badsort")})
	status, body := sendRequest(t, http.MethodGet,
		fmt.Sprintf("%s/v1/gateways/%s/auths?sort=nope", AdminURL, gwID), nil, nil,
	)
	require.Equal(t, http.StatusUnprocessableEntity, status, "body=%v", body)
	assert.Equal(t, "invalid_sort", body["error"])
}
