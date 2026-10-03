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

package policy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	policyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/app/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const canary = "sk-live-CANARY-0123456789"

// credPlugin is a registered plugin that declares one credential path.
type credPlugin struct {
	appplugins.Plugin
}

func (credPlugin) CredentialPaths() []string { return []string{"api_key"} }

func credentialRegistry(t *testing.T) *pluginmocks.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().Get("cred").Return(credPlugin{Plugin: pluginmocks.NewPlugin(t)}, true).Maybe()
	reg.EXPECT().Get("gone").Return(nil, false).Maybe()
	return reg
}

// credentialPolicy is paused so the status evaluator never needs the plugin.
// Only api_key is a declared credential of "cred"; "nested.token" is not, so it
// is exercised only under "gone", where nothing is declared at all.
func credentialPolicy(gatewayID ids.GatewayID, slug string) *domain.Policy {
	settings := map[string]any{"api_key": canary, "model": "m"}
	if slug == "gone" {
		settings["nested"] = map[string]any{"token": canary}
	}
	return &domain.Policy{
		ID:        ids.New[ids.PolicyKind](),
		GatewayID: gatewayID,
		Slug:      slug,
		Settings:  settings,
	}
}

func doJSON(t *testing.T, app *fiber.App, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(raw)
}

func settingsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &body))
	s, _ := body["settings"].(map[string]any)
	return s
}

// Every route that serialises a policy must mask its settings. Each case drives
// one handler and fails if the canary credential reaches the response body.
func TestPolicyHandlers_NeverReturnCredentials(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	base := "/v1/gateways/" + gatewayID.String() + "/policies"
	const route = "/v1/gateways/:gateway_id/policies"

	build := func(t *testing.T, p *domain.Policy) *fiber.App {
		t.Helper()
		reg := credentialRegistry(t)
		status := apppolicy.NewStatusEvaluator(reg)
		app := fiber.New()

		finder := policymocks.NewFinder(t)
		finder.EXPECT().FindByID(mock.Anything, gatewayID, p.ID).Return(p, nil).Maybe()
		finder.EXPECT().List(mock.Anything, mock.Anything).Return([]*domain.Policy{p}, 1, nil).Maybe()
		app.Get(route+"/:id", policyhttp.NewGetPolicyHandler(finder, status, reg).Handle)
		app.Get(route, policyhttp.NewListPolicyHandler(finder, status, reg).Handle)

		warner := policymocks.NewWarner(t)
		warner.EXPECT().Overlaps(mock.Anything, p).Return(nil, nil).Maybe()

		creator := policymocks.NewCreator(t)
		creator.EXPECT().Create(mock.Anything, mock.Anything).Return(p, nil).Maybe()
		app.Post(route, policyhttp.NewCreatePolicyHandler(creator, warner, reg).Handle)

		updater := policymocks.NewUpdater(t)
		updater.EXPECT().Update(mock.Anything, mock.Anything).Return(p, nil).Maybe()
		app.Put(route+"/:id", policyhttp.NewUpdatePolicyHandler(updater, warner, reg).Handle)

		dup := policymocks.NewDuplicator(t)
		dup.EXPECT().Duplicate(mock.Anything, gatewayID, p.ID).Return(p, nil).Maybe()
		app.Post(route+"/:id/duplicate", policyhttp.NewDuplicatePolicyHandler(dup, status, reg).Handle)

		scoper := policymocks.NewScoper(t)
		scoper.EXPECT().SetGlobal(mock.Anything, gatewayID, p.ID).Return(p, nil).Maybe()
		scoper.EXPECT().UnsetGlobal(mock.Anything, gatewayID, p.ID).Return(p, nil).Maybe()
		scoper.EXPECT().SetMCPWide(mock.Anything, gatewayID, p.ID).Return(p, nil).Maybe()
		scoper.EXPECT().UnsetMCPWide(mock.Anything, gatewayID, p.ID).Return(p, nil).Maybe()
		global := policyhttp.NewGlobalPolicyHandler(scoper, warner, status, reg)
		app.Post(route+"/:id/global", global.SetGlobal)
		app.Delete(route+"/:id/global", global.UnsetGlobal)
		mcpWide := policyhttp.NewMCPWidePolicyHandler(scoper, warner, status, reg)
		app.Post(route+"/:id/mcp-wide", mcpWide.SetMCPWide)
		app.Delete(route+"/:id/mcp-wide", mcpWide.UnsetMCPWide)
		return app
	}

	createBody := `{"name":"n","slug":"cred","settings":{"api_key":"x"}}`
	routes := []struct {
		name, method, path, body string
	}{
		{"get", http.MethodGet, "/{id}", ""},
		{"list", http.MethodGet, "", ""},
		{"create", http.MethodPost, "", createBody},
		{"update", http.MethodPut, "/{id}", `{"name":"n"}`},
		{"duplicate", http.MethodPost, "/{id}/duplicate", ""},
		{"set global", http.MethodPost, "/{id}/global", ""},
		{"unset global", http.MethodDelete, "/{id}/global", ""},
		{"set mcp-wide", http.MethodPost, "/{id}/mcp-wide", ""},
		{"unset mcp-wide", http.MethodDelete, "/{id}/mcp-wide", ""},
	}
	for _, slug := range []string{"cred", "gone"} {
		for _, rt := range routes {
			t.Run(slug+"/"+rt.name, func(t *testing.T) {
				t.Parallel()
				p := credentialPolicy(gatewayID, slug)
				app := build(t, p)
				code, raw := doJSON(t, app, rt.method, base+strings.ReplaceAll(rt.path, "{id}", p.ID.String()), rt.body)

				require.Less(t, code, 300, raw)
				assert.NotContains(t, raw, "CANARY", "credential reached the client")
				if slug == "cred" {
					var s map[string]any
					if rt.name == "list" {
						var l struct {
							Items []struct {
								Settings map[string]any `json:"settings"`
							} `json:"items"`
						}
						require.NoError(t, json.Unmarshal([]byte(raw), &l))
						s = l.Items[0].Settings
					} else {
						s = settingsOf(t, raw)
					}
					assert.Equal(t, "***6789", s["api_key"])
					assert.Equal(t, "m", s["model"], "non-credential settings stay readable")
				}
				// The stored policy still holds the real value: plugin execution reads it.
				assert.Equal(t, canary, p.Settings["api_key"])
			})
		}
	}
}

func TestPolicyHandlers_NilRegistryWithholdsEverything(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	p := credentialPolicy(gatewayID, "cred")
	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gatewayID, p.ID).Return(p, nil).Once()
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/policies/:id", policyhttp.NewGetPolicyHandler(finder, apppolicy.NewStatusEvaluator(credentialRegistry(t)), nil).Handle)

	code, raw := doJSON(t, app, http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/policies/"+p.ID.String(), "")
	require.Equal(t, http.StatusOK, code)
	assert.NotContains(t, raw, "CANARY")
	s := settingsOf(t, raw)
	assert.Equal(t, "***", s["api_key"])
	assert.Equal(t, "***", s["model"], "with no registry nothing says which value is a secret")
}
