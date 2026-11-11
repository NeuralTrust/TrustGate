// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trustguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// The trustguard plugin always calls TrustGuard's /v2 paths; TrustGuard answers a collector of an
// organisation that is not cut over with v1, so the paths are the public contract, not the engine.
func TestTrustGuardPathsAreV2(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "/v2/token", tokenPath)
	assert.Equal(t, "/v2/evaluate", evaluatePath)
}

// A v1 policy names its collector on /v2/token, never an integration: that is what makes
// TrustGuard issue the v1 platform token it always got from /v1/token.
func TestV1PolicyTokenRequestNamesTheCollector(t *testing.T) {
	t.Parallel()
	var raw map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v2/token", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &raw))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600})
	}))
	t.Cleanup(srv.Close)

	m := newTokenManager(srv.Client(), "platform-id", "platform-secret")
	_, err := m.token(context.Background(), tokenParams{baseURL: srv.URL, collectorID: testCollectorID, gatewayID: "gw-1"})
	require.NoError(t, err)
	assert.Equal(t, testCollectorID, raw["collector_id"])
	assert.NotContains(t, raw, "integration_id")
	assert.Equal(t, "platform", raw["scope"])
}

func TestWithInventoryAddsTheServedModel(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{
		RequestedModel: "@openai/gpt-4o",
		Provider:       "openai",
		Body:           []byte(`{"model":"gpt-4o","messages":[]}`),
	}
	body := GuardRequest{
		Direction:  "input",
		Attributes: GuardAttributes{Model: GuardModel{Name: req.RequestedModel, Provider: req.Provider}},
		request:    req,
	}
	got := withInventory(body)
	assert.Equal(t, GuardModel{Name: "@openai/gpt-4o", Provider: "openai", ServedName: "gpt-4o"}, got.Attributes.Model,
		"v1 keeps matching the client's ref; v2 gets the served model")
	assert.Empty(t, body.Attributes.Model.ServedName, "the caller's copy is untouched")

	raw, err := json.Marshal(got.Attributes.Model)
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"@openai/gpt-4o","provider":"openai","served_name":"gpt-4o"}`, string(raw))
}

func TestWithInventoryAddsTheMCPServerNameAndNativeTool(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{MCP: true, MCPServerName: " GitHub ", MCPTool: "create_issue"}
	server := &GuardMCPServer{ID: "reg-1", Code: "github"}
	body := GuardRequest{Attributes: GuardAttributes{MCPServer: server}, request: req}

	got := withInventory(body)
	require.NotNil(t, got.Attributes.MCPServer)
	assert.Equal(t, GuardMCPServer{ID: "reg-1", Code: "github", Name: "GitHub", Tool: &GuardTool{Name: "create_issue"}}, *got.Attributes.MCPServer)
	assert.Equal(t, GuardMCPServer{ID: "reg-1", Code: "github"}, *server, "the caller's server is not modified")
	assert.Empty(t, got.Attributes.Model.ServedName, "a tools/call names no model")
}

func TestWithInventoryWithoutARequestIsTheBodyAsIs(t *testing.T) {
	t.Parallel()
	body := GuardRequest{Attributes: GuardAttributes{Model: GuardModel{Name: "m"}}}
	assert.Equal(t, body, withInventory(body))
}

// A trustguard policy whose organisation is cut over gets v2's answers: its findings name a
// control instead of a detector, and the plugin keys them the same way trustguard_v2 does.
func TestV1PolicyNormalizesAV2Answer(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(engineHeader, engineV2)
		_, _ = w.Write([]byte(`{"status":"block","findings":[{"source":{"control_id":"ctl-1"}},{"source":{"detector_id":"det-1"}}]}`))
	}))
	t.Cleanup(srv.Close)

	c := newClient(5 * time.Second)
	resp, err := c.Guard(context.Background(), srv.URL, "tok", "", GuardRequest{}, false)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 2)
	assert.Equal(t, "ctl-1", resp.Findings[0].Source.DetectorID)
	assert.Equal(t, "det-1", resp.Findings[1].Source.DetectorID)
}
