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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

const handlerKey = "HANDLER-KEY-MARKER-0123456789"

func postPolicyTest(t *testing.T, tester apppolicy.ConnectionTester, gatewayID, body string) (int, []byte) {
	t.Helper()
	app := fiber.New()
	app.Post("/v1/gateways/:gateway_id/policies/test-connection", policyhttp.NewTestConnectionHandler(tester).Handle)
	req := httptest.NewRequest(fiber.MethodPost, "/v1/gateways/"+gatewayID+"/policies/test-connection", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func testBody(policyID string) string {
	body := `{"slug":"google_model_armor","settings":{"project":"acme","location":"us","template":"t",` +
		`"credentials":{"service_account_json":"` + handlerKey + `"}}`
	if policyID != "" {
		body += `,"policy_id":"` + policyID + `"`
	}
	return body + `}`
}

func TestTestConnectionHandlerAnswersTheProbeOutcome(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	policyID := ids.New[ids.PolicyKind]()
	tester := policymocks.NewConnectionTester(t)
	tester.EXPECT().Test(mock.Anything, mock.MatchedBy(func(in apppolicy.TestConnectionInput) bool {
		return in.GatewayID == gw && in.Slug == "google_model_armor" && !in.OnDataPlane &&
			in.PolicyID != nil && *in.PolicyID == policyID && in.Settings["template"] == "t"
	})).Return(apppolicy.TestConnectionResult{Code: "permission_denied", Message: "grant it", Latency: 1500 * time.Millisecond}, nil).Once()

	status, raw := postPolicyTest(t, tester, gw.String(), testBody(policyID.String()))

	require.Equal(t, fiber.StatusOK, status)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, map[string]any{"ok": false, "code": "permission_denied", "message": "grant it", "latency_ms": float64(1500)}, got)
	assert.NotContains(t, string(raw), handlerKey)
}

func TestTestConnectionHandlerRejectsBadRequests(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]().String()
	for name, body := range map[string]string{
		"not json":         `{`,
		"missing slug":     `{"settings":{}}`,
		"missing settings": `{"slug":"google_model_armor"}`,
		"null settings":    `{"slug":"google_model_armor","settings":null}`,
		"bad policy id":    `{"slug":"google_model_armor","settings":{},"policy_id":"nope"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			status, _ := postPolicyTest(t, policymocks.NewConnectionTester(t), gw, body)
			assert.Equal(t, fiber.StatusUnprocessableEntity, status)
		})
	}
}

func TestTestConnectionHandlerMapsTesterErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		err    error
		status int
		code   string
	}{
		"hybrid gateway": {domain.ErrTestRunsOnDataPlane, fiber.StatusConflict, "test_runs_on_data_plane"},
		"unknown policy": {domain.ErrNotFound, fiber.StatusNotFound, ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tester := policymocks.NewConnectionTester(t)
			tester.EXPECT().Test(mock.Anything, mock.Anything).Return(apppolicy.TestConnectionResult{}, tc.err).Once()

			status, raw := postPolicyTest(t, tester, ids.New[ids.GatewayKind]().String(), testBody(""))

			assert.Equal(t, tc.status, status)
			if tc.code != "" {
				assert.Contains(t, string(raw), tc.code)
			}
			assert.NotContains(t, string(raw), handlerKey)
		})
	}
}
