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
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	diagnosticshttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/diagnostics"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/app/secretstore/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
)

func postSecretTest(t *testing.T, verifier infrajwt.ProxyTokenVerifier, tester appsecretstore.Tester, gatewayID, token, body string) (int, string) {
	t.Helper()
	app := fiber.New()
	app.Post("/__diagnostics/gateways/:gateway_id/secret-stores/:name/test", diagnosticshttp.NewTestSecretHandler(verifier, tester).Handle)
	req := httptest.NewRequest(fiber.MethodPost, "/__diagnostics/gateways/"+gatewayID+"/secret-stores/aws/test", strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(diagnosticshttp.HeaderDiagnosticsToken, token)
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestDiagnosticsSecretTest_ReportsTheOutcome(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	tester := mocks.NewTester(t)
	tester.EXPECT().Test(mock.Anything, appsecretstore.TestInput{GatewayID: gw, Store: "aws", Path: "prod/llm/openai", Field: "key"}).
		Return(appsecretstore.TestResult{Auth: "ok", Read: "ok", Version: "v7"}, nil)
	code, body := postSecretTest(t, fakeVerifier{claims: diagClaims(gw.String())}, tester, gw.String(), "tok", `{"path":"prod/llm/openai","field":"key"}`)
	assert.Equal(t, fiber.StatusOK, code)
	assert.JSONEq(t, `{"auth":"ok","read":"ok","version":"v7","latency_ms":0}`, body)
}

func TestDiagnosticsSecretTest_RequiresATokenForThisGateway(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	code, _ := postSecretTest(t, fakeVerifier{claims: diagClaims(gw.String())}, mocks.NewTester(t), gw.String(), "", "")
	assert.Equal(t, fiber.StatusUnauthorized, code)
	code, _ = postSecretTest(t, fakeVerifier{claims: diagClaims(ids.New[ids.GatewayKind]().String())}, mocks.NewTester(t), gw.String(), "tok", "")
	assert.Equal(t, fiber.StatusUnauthorized, code)
}

func TestDiagnosticsSecretTest_PathOutsideTheAllowlistIsRefused(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	tester := mocks.NewTester(t)
	tester.EXPECT().Test(mock.Anything, mock.Anything).Return(appsecretstore.TestResult{}, refdomain.ErrPathNotAllowed)
	code, body := postSecretTest(t, fakeVerifier{claims: diagClaims(gw.String())}, tester, gw.String(), "tok", `{"path":"prod/db"}`)
	assert.Equal(t, fiber.StatusUnprocessableEntity, code)
	assert.Contains(t, body, "secret_path_not_allowed")
}
