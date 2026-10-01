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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	policyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy"
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

func TestListPolicyHandler_ReportsLoadStatus(t *testing.T) {
	t.Parallel()

	gatewayID := ids.New[ids.GatewayKind]()
	good := &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "good", Enabled: true}
	paused := &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "gone", Enabled: false}
	broken := &domain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gatewayID, Slug: "broken", Enabled: true}

	finder := policymocks.NewFinder(t)
	finder.EXPECT().List(mock.Anything, mock.Anything).
		Return([]*domain.Policy{good, paused, broken}, 3, nil).Once()

	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages("good", mock.Anything).Return(nil)
	reg.EXPECT().ValidateMode("good", mock.Anything).Return(nil)
	reg.EXPECT().Validate("good", mock.Anything).Return(nil)
	reg.EXPECT().ValidateStages("broken", mock.Anything).Return(nil)
	reg.EXPECT().ValidateMode("broken", mock.Anything).Return(nil)
	reg.EXPECT().Validate("broken", mock.Anything).Return(errors.New("limit must be positive"))

	handler := policyhttp.NewListPolicyHandler(finder, apppolicy.NewStatusEvaluator(reg))
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/policies", handler.Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gatewayID.String()+"/policies", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var body struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Len(t, body.Items, 3)

	assert.Equal(t, "active", body.Items[0]["status"])
	assert.NotContains(t, body.Items[0], "status_message")
	assert.Equal(t, "paused", body.Items[1]["status"])
	assert.NotContains(t, body.Items[1], "status_message")
	assert.Equal(t, "error", body.Items[2]["status"])
	assert.Contains(t, body.Items[2]["status_message"], "limit must be positive")
}
