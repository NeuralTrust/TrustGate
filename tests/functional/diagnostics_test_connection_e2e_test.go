//go:build functional

package functional_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const diagnosticsTokenHeader = "X-AG-Diagnostics-Token"

// mintDiagnosticsToken signs a short-lived diagnostics JWT bound to gatewayID
// with the shared server secret, mirroring what the dashboard BFF mints (the
// HS256 fallback; production uses RS256 with the M2M issuer key).
func mintDiagnosticsToken(t *testing.T, gatewayID, purpose string) string {
	t.Helper()
	claims := &jwt.Claims{
		Purpose:   purpose,
		GatewayID: gatewayID,
		RegisteredClaims: golangjwt.RegisteredClaims{
			IssuedAt:  golangjwt.NewNumericDate(time.Now()),
			ExpiresAt: golangjwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Audience:  golangjwt.ClaimStrings{"trustgate-diagnostics"},
		},
	}
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims).
		SignedString([]byte(GlobalConfig.Server.SecretKey))
	require.NoError(t, err)
	return token
}

// newModelsUpstream serves the GET /models discovery endpoint the openai
// connection tester probes.
func newModelsUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func postDiagnosticsTestConnection(t *testing.T, gatewayID, token string, body map[string]any) (int, []byte) {
	t.Helper()
	buf, err := json.Marshal(body)
	require.NoError(t, err)
	url := fmt.Sprintf("%s/__diagnostics/gateways/%s/registries/test-connection", ProxyURL, gatewayID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
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

// TestDiagnosticsTestConnectionE2E exercises the data-plane connection probe:
// the same test the admin plane offers, but executed by the proxy plane so the
// result reflects the serving network's reachability.
func TestDiagnosticsTestConnectionE2E(t *testing.T) {
	defer Track(t, "DiagnosticsTestConnection")()

	up := newModelsUpstream(t)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("diag-gw")})
	inline := map[string]any{
		"provider":         "openai",
		"provider_options": map[string]any{"base_url": up.URL},
		"auth":             map[string]any{"type": "api_key", "api_key": map[string]any{"api_key": "sk-test"}},
	}

	t.Run("inline candidate probes from the proxy plane", func(t *testing.T) {
		token := mintDiagnosticsToken(t, gatewayID, "diagnostics")

		status, raw := postDiagnosticsTestConnection(t, gatewayID, token, inline)

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		var out struct {
			OK       bool   `json:"ok"`
			Provider string `json:"provider"`
		}
		require.NoError(t, json.Unmarshal(raw, &out))
		assert.True(t, out.OK, "body: %s", raw)
		assert.Equal(t, "openai", out.Provider)
	})

	t.Run("stored registry probes by id", func(t *testing.T) {
		registryID := CreateRegistry(t, gatewayID, openaiBackendPayload(uniqueName("diag-be"), up.URL))
		token := mintDiagnosticsToken(t, gatewayID, "diagnostics")

		status, raw := postDiagnosticsTestConnection(t, gatewayID, token, map[string]any{"registry_id": registryID})

		require.Equal(t, http.StatusOK, status, "body: %s", raw)
		var out struct {
			OK bool `json:"ok"`
		}
		require.NoError(t, json.Unmarshal(raw, &out))
		assert.True(t, out.OK, "body: %s", raw)
	})

	t.Run("missing token is rejected", func(t *testing.T) {
		status, _ := postDiagnosticsTestConnection(t, gatewayID, "", inline)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("playground-purpose token is rejected", func(t *testing.T) {
		token := mintDiagnosticsToken(t, gatewayID, "playground")
		status, _ := postDiagnosticsTestConnection(t, gatewayID, token, inline)
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("token bound to another gateway is rejected", func(t *testing.T) {
		otherGateway := CreateGateway(t, map[string]any{"slug": uniqueName("diag-other")})
		token := mintDiagnosticsToken(t, otherGateway, "diagnostics")
		status, _ := postDiagnosticsTestConnection(t, gatewayID, token, inline)
		assert.Equal(t, http.StatusUnauthorized, status)
	})
}
