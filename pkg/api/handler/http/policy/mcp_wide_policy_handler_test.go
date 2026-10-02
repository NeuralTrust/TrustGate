// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"testing"

	policyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/app/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMCPWidePolicyHandler_ReportsLoadStatus(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	stages := []domain.Stage{domain.StagePreRequest}
	tests := []struct {
		name        string
		method      string
		policy      *domain.Policy
		wantStatus  string
		wantMessage string
	}{
		{"promote unloadable", http.MethodPost, &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "gone", Enabled: true, MCPWide: true}, "error", "unknown plugin"},
		{"promote active", http.MethodPost, &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "good", Enabled: true, MCPWide: true, Stages: stages}, "active", ""},
		{"demote unloadable", http.MethodDelete, &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "broken", Enabled: true, Stages: stages}, "error", "limit must be positive"},
		{"demote paused", http.MethodDelete, &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "gone", Enabled: false}, "paused", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			scoper := policymocks.NewScoper(t)
			warner := policymocks.NewWarner(t)
			if tt.method == http.MethodPost {
				scoper.EXPECT().SetMCPWide(mock.Anything, gatewayID, tt.policy.ID).Return(tt.policy, nil).Once()
				warner.EXPECT().Overlaps(mock.Anything, tt.policy).Return(nil, nil).Once()
			} else {
				scoper.EXPECT().UnsetMCPWide(mock.Anything, gatewayID, tt.policy.ID).Return(tt.policy, nil).Once()
			}

			reg := statusRegistry(t)
			handler := policyhttp.NewMCPWidePolicyHandler(scoper, warner, apppolicy.NewStatusEvaluator(reg), reg)
			app := fiber.New()
			app.Post("/v1/gateways/:gateway_id/policies/:id/mcp-wide", handler.SetMCPWide)
			app.Delete("/v1/gateways/:gateway_id/policies/:id/mcp-wide", handler.UnsetMCPWide)

			resp, err := app.Test(httptest.NewRequest(tt.method, "/v1/gateways/"+gatewayID.String()+"/policies/"+tt.policy.ID.String()+"/mcp-wide", nil))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))

			assert.Equal(t, tt.wantStatus, body["status"])
			if tt.wantMessage == "" {
				assert.NotContains(t, body, "status_message")
			} else {
				assert.Contains(t, body["status_message"], tt.wantMessage)
			}
		})
	}
}
