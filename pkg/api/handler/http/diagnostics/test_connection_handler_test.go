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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	diagnosticshttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/diagnostics"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infrajwt "github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeVerifier struct {
	claims *infrajwt.Claims
	err    error
}

func (f fakeVerifier) Verify(string) (*infrajwt.Claims, error) { return f.claims, f.err }

type fakeTester struct {
	in     appregistry.TestConnectionInput
	result appregistry.TestConnectionResult
	err    error
}

func (f *fakeTester) Test(_ context.Context, in appregistry.TestConnectionInput) (appregistry.TestConnectionResult, error) {
	f.in = in
	return f.result, f.err
}

func newDiagApp(verifier infrajwt.ProxyTokenVerifier, tester appregistry.ConnectionTester) *fiber.App {
	app := fiber.New()
	h := diagnosticshttp.NewTestConnectionHandler(verifier, tester)
	app.Post("/__diagnostics/gateways/:gateway_id/registries/test-connection", h.Handle)
	return app
}

func postDiag(t *testing.T, app *fiber.App, gatewayID, token, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost,
		"/__diagnostics/gateways/"+gatewayID+"/registries/test-connection", strings.NewReader(body))
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

func diagClaims(gatewayID string) *infrajwt.Claims {
	return &infrajwt.Claims{Purpose: infrajwt.PurposeDiagnostics, GatewayID: gatewayID}
}

const inlineBody = `{"provider":"openai","provider_options":{"base_url":"http://upstream.local"},"auth":{"type":"api_key","api_key":{"api_key":"sk-test"}}}`

func TestDiagnosticsTestConnection_InlineHappyPath(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	tester := &fakeTester{result: appregistry.TestConnectionResult{OK: true, Stage: "provider", Provider: "openai", StatusCode: 200}}
	app := newDiagApp(fakeVerifier{claims: diagClaims(gatewayID.String())}, tester)

	status, raw := postDiag(t, app, gatewayID.String(), "a.diag.token", inlineBody)

	require.Equal(t, fiber.StatusOK, status, "body: %s", raw)
	var out struct {
		OK    bool   `json:"ok"`
		Stage string `json:"stage"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.OK)
	assert.Equal(t, gatewayID, tester.in.GatewayID)
	assert.Equal(t, "openai", tester.in.Provider)
	assert.Nil(t, tester.in.RegistryID)
}

func TestDiagnosticsTestConnection_MissingTokenRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	app := newDiagApp(fakeVerifier{claims: diagClaims(gatewayID.String())}, &fakeTester{})

	status, _ := postDiag(t, app, gatewayID.String(), "", inlineBody)
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsTestConnection_InvalidTokenRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	app := newDiagApp(fakeVerifier{err: errors.New("bad signature")}, &fakeTester{})

	status, _ := postDiag(t, app, gatewayID.String(), "bad.token", inlineBody)
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsTestConnection_WrongPurposeRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	claims := &infrajwt.Claims{Purpose: infrajwt.PurposePlayground, GatewayID: gatewayID.String()}
	app := newDiagApp(fakeVerifier{claims: claims}, &fakeTester{})

	status, _ := postDiag(t, app, gatewayID.String(), "playground.token", inlineBody)
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsTestConnection_GatewayMismatchRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	other := ids.New[ids.GatewayKind]()
	app := newDiagApp(fakeVerifier{claims: diagClaims(other.String())}, &fakeTester{})

	status, _ := postDiag(t, app, gatewayID.String(), "a.diag.token", inlineBody)
	assert.Equal(t, fiber.StatusUnauthorized, status)
}

func TestDiagnosticsTestConnection_ByIDNotSyncedYet(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()
	tester := &fakeTester{err: registrydomain.ErrNotFound}
	app := newDiagApp(fakeVerifier{claims: diagClaims(gatewayID.String())}, tester)

	status, raw := postDiag(t, app, gatewayID.String(), "a.diag.token", `{"registry_id":"`+registryID.String()+`"}`)

	require.Equal(t, fiber.StatusOK, status, "body: %s", raw)
	var out struct {
		OK    bool   `json:"ok"`
		Stage string `json:"stage"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.False(t, out.OK)
	assert.Equal(t, diagnosticshttp.StageNotSynced, out.Stage)
}

func TestDiagnosticsTestConnection_InvalidBodyRejected(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	app := newDiagApp(fakeVerifier{claims: diagClaims(gatewayID.String())}, &fakeTester{})

	status, _ := postDiag(t, app, gatewayID.String(), "a.diag.token", `{"registry_id":"r1","provider":"openai"}`)
	assert.Equal(t, fiber.StatusUnprocessableEntity, status)
}
