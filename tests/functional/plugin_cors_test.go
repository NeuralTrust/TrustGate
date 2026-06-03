//go:build functional

package functional_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// corsSettings is the plugin configuration shared by the CORS e2e cases: a
// single explicit origin and a small method allow-list.
func corsSettings() map[string]any {
	return map[string]any{
		"allowed_origins":   []string{"https://allowed.com"},
		"allowed_methods":   []string{"GET", "POST"},
		"allow_credentials": false,
		"max_age":           "600s",
		"expose_headers":    []string{"X-Test"},
		"log_violations":    true,
	}
}

func TestPluginE2E_CORS(t *testing.T) {
	defer Track(t, "PluginCORS")()

	up := newJSONUpstream(t, "cors-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("cors", corsSettings()),
	)

	t.Run("allowed origin simple request passes through", func(t *testing.T) {
		status, _, body := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"Origin": "https://allowed.com"},
			mustJSON(t, chatRequest(false)),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", body)
		assert.Contains(t, string(body), "cors-upstream")
	})

	t.Run("disallowed origin is rejected", func(t *testing.T) {
		status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"Origin": "https://evil.com"},
			mustJSON(t, chatRequest(false)),
		)
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("missing origin is rejected", func(t *testing.T) {
		status, _, _ := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, chatRequest(false)),
		)
		assert.Equal(t, http.StatusForbidden, status)
	})

	t.Run("valid preflight short-circuits with negotiated headers", func(t *testing.T) {
		hitsBefore := up.Hits()
		status, headers, _ := proxyRequest(t, http.MethodOptions, apiKey, path,
			map[string]string{
				"Origin":                        "https://allowed.com",
				"Access-Control-Request-Method": "POST",
			}, nil,
		)
		assert.Equal(t, http.StatusNoContent, status)
		assert.Equal(t, "https://allowed.com", headers.Get("Access-Control-Allow-Origin"))
		assert.Contains(t, headers.Get("Access-Control-Allow-Methods"), "POST")
		assert.Equal(t, "600s", headers.Get("Access-Control-Max-Age"))
		assert.Equal(t, hitsBefore, up.Hits(), "a preflight must never reach the upstream")
	})

	t.Run("preflight with disallowed method is rejected", func(t *testing.T) {
		status, _, _ := proxyRequest(t, http.MethodOptions, apiKey, path,
			map[string]string{
				"Origin":                        "https://allowed.com",
				"Access-Control-Request-Method": "DELETE",
			}, nil,
		)
		assert.Equal(t, http.StatusMethodNotAllowed, status)
	})

	t.Run("preflight missing requested method is a bad request", func(t *testing.T) {
		status, _, _ := proxyRequest(t, http.MethodOptions, apiKey, path,
			map[string]string{"Origin": "https://allowed.com"}, nil,
		)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("preflight from disallowed origin is rejected", func(t *testing.T) {
		status, _, _ := proxyRequest(t, http.MethodOptions, apiKey, path,
			map[string]string{
				"Origin":                        "https://evil.com",
				"Access-Control-Request-Method": "POST",
			}, nil,
		)
		assert.Equal(t, http.StatusForbidden, status)
	})
}

func TestPluginE2E_CORS_Wildcard(t *testing.T) {
	defer Track(t, "PluginCORS")()

	up := newJSONUpstream(t, "cors-wild-upstream")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("cors", map[string]any{
			"allowed_origins":   []string{"*"},
			"allowed_methods":   []string{"GET", "POST", "OPTIONS"},
			"allow_credentials": false,
			"max_age":           "600s",
		}),
	)

	t.Run("wildcard allows an arbitrary origin", func(t *testing.T) {
		status, _, body := proxyRequest(t, http.MethodPost, apiKey, path,
			map[string]string{"Origin": "https://anything.example.com"},
			mustJSON(t, chatRequest(false)),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", body)
	})

	t.Run("wildcard preflight echoes the request origin", func(t *testing.T) {
		status, headers, _ := proxyRequest(t, http.MethodOptions, apiKey, path,
			map[string]string{
				"Origin":                        "https://any.origin",
				"Access-Control-Request-Method": "POST",
			}, nil,
		)
		assert.Equal(t, http.StatusNoContent, status)
		assert.Equal(t, "https://any.origin", headers.Get("Access-Control-Allow-Origin"))
	})
}
