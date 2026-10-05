//go:build functional

package functional_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createAndAttachExpiringAPIKey(t *testing.T, gatewayID, consumerID string, expiresAt time.Time) string {
	t.Helper()
	status, body := sendRequest(t, http.MethodPost,
		fmt.Sprintf("%s/v1/gateways/%s/auths", AdminURL, gatewayID), nil,
		map[string]any{
			"name":       uniqueName("proxy-key-expiring"),
			"type":       "api_key",
			"enabled":    true,
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		},
	)
	require.Equal(t, http.StatusCreated, status, "body=%v", body)
	authID, ok := body["id"].(string)
	require.True(t, ok, "create auth response missing id: %v", body)
	key, ok := body["api_key"].(string)
	require.True(t, ok, "create auth response missing generated api_key: %v", body)
	registerProxyKey(t, gatewayID, consumerID, authID, key)
	return key
}

func TestProxyAPIKeyExpiry_KeyStopsWorkingOnceItsExpiryPasses(t *testing.T) {
	defer Track(t, "ProxyAPIKeyExpiry")()

	up := newJSONUpstream(t, "expiry-ok")
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("expiry-gw")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("be"), up.URL()))
	consumerID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("cons")})
	AttachRegistry(t, gatewayID, consumerID, registryID)
	path := chatCompletionsPath(t, consumerID)

	expiresAt := time.Now().UTC().Add(6 * time.Second).Truncate(time.Second).Add(time.Second)
	key := createAndAttachExpiringAPIKey(t, gatewayID, consumerID, expiresAt)
	futureKey := createAndAttachExpiringAPIKey(t, gatewayID, consumerID, time.Now().Add(time.Hour))

	status, _, body := proxyPost(t, key, path, chatRequest(false))
	require.Equal(t, http.StatusOK, status, "a key before its expiry must be served, body: %s", body)
	assert.Contains(t, string(body), "expiry-ok")
	require.Equal(t, 1, up.Hits())

	time.Sleep(time.Until(expiresAt) + 500*time.Millisecond)

	status, _, body = proxyPost(t, key, path, chatRequest(false))
	assert.Equal(t, http.StatusUnauthorized, status, "body: %s", body)
	assert.Equal(t, 1, up.Hits(), "an expired key must never reach the upstream")

	status, _, body = proxyPost(t, futureKey, path, chatRequest(false))
	assert.Equal(t, http.StatusOK, status, "a key with a future expiry must be served, body: %s", body)
	assert.Equal(t, 2, up.Hits())
}
