//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const gatewaySlugHeader = "X-AG-Gateway-Slug"

func setupDiscoveryRoute(t *testing.T) (slug, apiKey, path string) {
	t.Helper()
	gatewayID := CreateGateway(t, map[string]any{"name": uniqueName("disc-gw")})
	host, ok := gatewayHosts.Load(gatewayID)
	require.True(t, ok, "gateway host missing for %s", gatewayID)
	slug = strings.TrimSuffix(host.(string), "."+functionalGatewayBaseDomain)
	require.NotEmpty(t, slug)

	up := newJSONUpstream(t, "discovery-upstream")
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("disc-be"), up.URL()))

	path = "/v1/" + uniqueName("disc-route")
	coID := CreateConsumer(t, gatewayID, map[string]any{"name": uniqueName("disc-co"), "path": path})
	AttachRegistry(t, gatewayID, coID, registryID)
	apiKey = createAndAttachAPIKey(t, gatewayID, coID)
	return slug, apiKey, path
}

func discoveryPost(t *testing.T, apiKey, path, host, headerSlug string) (int, []byte) {
	t.Helper()
	buf, err := json.Marshal(chatRequest(false))
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ProxyURL+path, bytes.NewReader(buf))
	require.NoError(t, err)
	if host != "" {
		req.Host = host
	}
	if headerSlug != "" {
		req.Header.Set(gatewaySlugHeader, headerSlug)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proxyAPIKeyHeader, apiKey)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func TestProxyE2E_GatewayDiscovery(t *testing.T) {
	defer Track(t, "GatewayDiscovery")()
	slug, apiKey, path := setupDiscoveryRoute(t)
	subdomainHost := fmt.Sprintf("%s.%s", slug, functionalGatewayBaseDomain)

	t.Run("matches by slug header without a gateway host", func(t *testing.T) {
		status, body := discoveryPost(t, apiKey, path, "", slug)
		require.Equal(t, http.StatusOK, status, "body=%s", body)
		assert.Contains(t, string(body), "discovery-upstream")
	})

	t.Run("falls back to the subdomain host when the header is absent", func(t *testing.T) {
		status, body := discoveryPost(t, apiKey, path, subdomainHost, "")
		require.Equal(t, http.StatusOK, status, "body=%s", body)
		assert.Contains(t, string(body), "discovery-upstream")
	})

	t.Run("header takes precedence over a valid subdomain host", func(t *testing.T) {
		status, body := discoveryPost(t, apiKey, path, subdomainHost, "ghost-"+slug)
		require.Equal(t, http.StatusBadRequest, status, "body=%s", body)
		assert.Contains(t, string(body), "invalid_auth_request")
	})

	t.Run("rejects an invalid slug in the header", func(t *testing.T) {
		status, body := discoveryPost(t, apiKey, path, "", "-bad-slug-")
		require.Equal(t, http.StatusBadRequest, status, "body=%s", body)
		assert.Contains(t, string(body), "invalid_auth_request")
	})

	t.Run("rejects when neither header nor host identify a gateway", func(t *testing.T) {
		status, body := discoveryPost(t, apiKey, path, "", "")
		require.Equal(t, http.StatusBadRequest, status, "body=%s", body)
		assert.Contains(t, string(body), "invalid_auth_request")
	})
}
