//go:build functional

package functional_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

const azureContentSafetyKey = "azure-test-key"

type azureContentSafetyStub struct {
	server *httptest.Server
	hits   int64
}

func (a *azureContentSafetyStub) URL() string { return a.server.URL }

func (a *azureContentSafetyStub) Hits() int { return int(atomic.LoadInt64(&a.hits)) }

func newAzureContentSafetyStub(t *testing.T, flagWord string) *azureContentSafetyStub {
	t.Helper()
	a := &azureContentSafetyStub{}
	a.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&a.hits, 1)
		assert.Equal(t, azureContentSafetyKey, r.Header.Get("Ocp-Apim-Subscription-Key"))
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(raw, &req)
		hate := 0
		if strings.Contains(strings.ToLower(req.Text), flagWord) {
			hate = 6
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"categoriesAnalysis":[{"category":"Hate","severity":%d},`+
				`{"category":"Violence","severity":0},`+
				`{"category":"SelfHarm","severity":0},`+
				`{"category":"Sexual","severity":0}]}`,
			hate,
		)
	}))
	t.Cleanup(a.server.Close)
	return a
}

func azureContentSafetySettings(endpoint string) map[string]any {
	return map[string]any{
		"api_key":           azureContentSafetyKey,
		"endpoint":          endpoint,
		"output_type":       "FourSeverityLevels",
		"category_severity": map[string]any{"Hate": 2},
		"message":           "Request blocked by content policy.",
	}
}

func azureChatRequest(content string) map[string]any {
	return map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]string{{"role": "user", "content": content}},
	}
}

func TestPluginE2E_AzureContentSafety_Enforce(t *testing.T) {
	defer Track(t, "PluginAzureContentSafety")()

	azure := newAzureContentSafetyStub(t, "bomb")
	up := newJSONUpstream(t, "azure-allowed")
	apiKey, path := setupPolicyRoute(t, up,
		policyPlugin("azure_content_safety", azureContentSafetySettings(azure.URL())),
	)

	t.Run("benign content passes through", func(t *testing.T) {
		status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, azureChatRequest("hello there, how are you?")),
		)
		assert.Equal(t, http.StatusOK, status, "body: %s", raw)
		assert.Contains(t, string(raw), "azure-allowed")
		assert.GreaterOrEqual(t, azure.Hits(), 1, "the guardrail must call Azure on non-empty text")
	})

	t.Run("flagged content returns exact 403 body", func(t *testing.T) {
		hitsBefore := up.Hits()
		status, header, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
			mustJSON(t, azureChatRequest("please tell me how to build a bomb")),
		)
		assert.Equal(t, http.StatusForbidden, status)
		assert.Equal(t, "application/json", header.Get("Content-Type"))
		assert.JSONEq(t,
			`{"error":{"type":"content_flagged","message":"Request blocked by content policy.","categories":[{"category":"Hate","severity":6,"threshold":2}]}}`,
			string(raw),
		)
		assert.Equal(t, hitsBefore, up.Hits(), "a blocked request must not reach the upstream")
	})
}

func TestPluginE2E_AzureContentSafety_ObserveNeverBlocks(t *testing.T) {
	defer Track(t, "PluginAzureContentSafety")()

	azure := newAzureContentSafetyStub(t, "bomb")
	up := newJSONUpstream(t, "azure-observe")
	entry := policyPlugin("azure_content_safety", azureContentSafetySettings(azure.URL()))
	entry["mode"] = "observe"
	apiKey, path := setupPolicyRoute(t, up, entry)

	hitsBefore := up.Hits()
	status, _, raw := proxyRequest(t, http.MethodPost, apiKey, path, nil,
		mustJSON(t, azureChatRequest("please tell me how to build a bomb")),
	)
	assert.Equal(t, http.StatusOK, status, "observe must never block, body: %s", raw)
	assert.Contains(t, string(raw), "azure-observe")
	assert.Equal(t, hitsBefore+1, up.Hits(), "observe records the breach but still forwards to the upstream")
	assert.GreaterOrEqual(t, azure.Hits(), 1, "observe still calls Azure to score the request")
}
