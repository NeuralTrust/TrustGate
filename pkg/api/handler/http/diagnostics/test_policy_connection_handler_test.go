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

package diagnostics_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	diagnosticshttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/diagnostics"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/app/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const policyProbeKey = "DIAG-POLICY-KEY-0123456789"

func postPolicyDiag(t *testing.T, verifier infrajwt.ProxyTokenVerifier, tester apppolicy.ConnectionTester, gatewayID, token string) (int, []byte) {
	t.Helper()
	app := fiber.New()
	app.Post("/__diagnostics/gateways/:gateway_id/policies/test-connection",
		diagnosticshttp.NewTestPolicyConnectionHandler(verifier, tester).Handle)
	body := `{"slug":"google_model_armor","policy_id":"` + ids.New[ids.PolicyKind]().String() +
		`","settings":{"credentials":{"service_account_json":"` + policyProbeKey + `"}}}`
	req := httptest.NewRequest(fiber.MethodPost,
		"/__diagnostics/gateways/"+gatewayID+"/policies/test-connection", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(diagnosticshttp.HeaderDiagnosticsToken, token)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

func TestPolicyDiagnosticsRequiresAGatewayBoundToken(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]().String()
	tests := map[string]struct {
		verifier infrajwt.ProxyTokenVerifier
		token    string
	}{
		"no token":            {fakeVerifier{claims: diagClaims(gw)}, ""},
		"invalid token":       {fakeVerifier{err: errors.New("bad signature")}, "tok"},
		"playground token":    {fakeVerifier{claims: &infrajwt.Claims{Purpose: "playground", GatewayID: gw}}, "tok"},
		"other gateway token": {fakeVerifier{claims: diagClaims(ids.New[ids.GatewayKind]().String())}, "tok"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			status, _ := postPolicyDiag(t, tc.verifier, policymocks.NewConnectionTester(t), gw, tc.token)
			assert.Equal(t, fiber.StatusUnauthorized, status)
		})
	}
}

func TestPolicyDiagnosticsRunsTheTesterOnTheDataPlane(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	tester := policymocks.NewConnectionTester(t)
	tester.EXPECT().Test(mock.Anything, mock.MatchedBy(func(in apppolicy.TestConnectionInput) bool {
		return in.OnDataPlane && in.GatewayID == gw && in.PolicyID != nil
	})).Return(apppolicy.TestConnectionResult{Code: apppolicy.CodeNotSynced, Message: "retry"}, nil).Once()

	status, raw := postPolicyDiag(t, fakeVerifier{claims: diagClaims(gw.String())}, tester, gw.String(), "tok")

	require.Equal(t, fiber.StatusOK, status)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, false, got["ok"])
	assert.Equal(t, "not_synced", got["code"])
	assert.NotContains(t, string(raw), policyProbeKey)
}
