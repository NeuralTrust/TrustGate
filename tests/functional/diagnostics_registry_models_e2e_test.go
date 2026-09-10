//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getDiagnosticsRegistryModels(t *testing.T, gatewayID, registryID, token string) (int, []byte) {
	t.Helper()
	url := fmt.Sprintf("%s/__diagnostics/gateways/%s/registries/%s/models", ProxyURL, gatewayID, registryID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set(diagnosticsTokenHeader, token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

// TestDiagnosticsRegistryModelsE2E exercises the data-plane model listing: the
// same answer the admin catalog endpoint gives, but resolved by the proxy plane
// so a provider endpoint reachable only from the serving network still narrows
// the catalog.
//
// How much the listing narrows depends on the model catalog, which this suite
// does not seed (it is synced from models.dev at boot), so these cases assert
// the route's contract and authorization. The narrowing itself is covered by
// the handler and availability unit tests.
func TestDiagnosticsRegistryModelsE2E(t *testing.T) {
	defer Track(t, "DiagnosticsRegistryModels")()

	up := newModelsUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("diag-models-gw")})
	registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("diag-models-be"), up.URL))

	t.Run("lists the registry's models from the proxy plane", func(t *testing.T) {
		token := mintDiagnosticsToken(t, gatewayID, "diagnostics")

		status, raw := getDiagnosticsRegistryModels(t, gatewayID, registryID, token)

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		var out struct {
			Items []struct {
				Slug    string `json:"slug"`
				Enabled bool   `json:"enabled"`
			} `json:"items"`
		}
		require.NoError(t, json.Unmarshal(raw, &out), "body: %s", raw)
		for _, item := range out.Items {
			assert.NotEmpty(t, item.Slug, "every listed model carries a slug")
			assert.True(t, item.Enabled, "a withdrawn model is not a valid pick")
		}
	})

	t.Run("registry missing from this plane is not found", func(t *testing.T) {
		token := mintDiagnosticsToken(t, gatewayID, "diagnostics")

		status, _ := getDiagnosticsRegistryModels(t, gatewayID, ids.New[ids.RegistryKind]().String(), token)

		// Distinct from 401 on purpose: the caller falls back to the
		// unnarrowed catalog and retries once config-sync catches up.
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("missing token is rejected", func(t *testing.T) {
		status, _ := getDiagnosticsRegistryModels(t, gatewayID, registryID, "")
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("playground-purpose token is rejected", func(t *testing.T) {
		token := mintDiagnosticsToken(t, gatewayID, "playground")
		status, _ := getDiagnosticsRegistryModels(t, gatewayID, registryID, token)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("token bound to another gateway is rejected", func(t *testing.T) {
		otherGateway := CreateGateway(t, map[string]any{"slug": uniqueName("diag-models-other")})
		token := mintDiagnosticsToken(t, otherGateway, "diagnostics")
		status, _ := getDiagnosticsRegistryModels(t, gatewayID, registryID, token)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
