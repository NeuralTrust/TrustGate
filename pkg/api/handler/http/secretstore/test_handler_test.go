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
package secretstore_test

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	secretstorehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/app/secretstore/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type gatewayStub struct{}

func (gatewayStub) FindByID(_ context.Context, id ids.GatewayID) (*gateway.Gateway, error) {
	return &gateway.Gateway{ID: id}, nil
}

type sourceStub struct{ src appsecretstore.Source }

func (s sourceStub) Source(context.Context, *gateway.Gateway) (appsecretstore.Source, error) {
	return s.src, nil
}

func postTest(t *testing.T, src appsecretstore.Source, tester appsecretstore.Tester, body string) (int, string) {
	t.Helper()
	app := fiber.New()
	h := secretstorehttp.NewTestHandler(gatewayStub{}, sourceStub{src}, tester)
	app.Post("/v1/gateways/:gateway_id/secret-stores/:name/test", h.Handle)
	req := httptest.NewRequest(fiber.MethodPost, "/v1/gateways/"+ids.New[ids.GatewayKind]().String()+"/secret-stores/Corp-Vault/test", strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	resp, err := app.Test(req)
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestTestHandler_RunsOnTheAdminCatalog(t *testing.T) {
	tester := mocks.NewTester(t)
	tester.EXPECT().Test(mock.Anything, mock.MatchedBy(func(in appsecretstore.TestInput) bool {
		return in.Store == "corp-vault" && in.Path == "ai-gateway/openai" && in.Field == "api_key"
	})).Return(appsecretstore.TestResult{Auth: "ok", Read: "ok", Version: "3", Latency: 42 * time.Millisecond}, nil)

	code, body := postTest(t, appsecretstore.Source{Supported: true, Kind: appsecretstore.KindControlPlane}, tester, `{"path":"ai-gateway/openai","field":"api_key"}`)
	assert.Equal(t, fiber.StatusOK, code)
	assert.JSONEq(t, `{"auth":"ok","read":"ok","version":"3","latency_ms":42}`, body)
}

func TestTestHandler_DataPlaneSourceAnswers409(t *testing.T) {
	code, body := postTest(t, appsecretstore.Source{Supported: true, Kind: appsecretstore.KindDataPlane}, mocks.NewTester(t), "")
	assert.Equal(t, fiber.StatusConflict, code)
	assert.Contains(t, body, "test_runs_on_data_plane")
}

func TestTestHandler_UnsupportedGatewayAnswers422(t *testing.T) {
	code, body := postTest(t, appsecretstore.Source{}, mocks.NewTester(t), "")
	assert.Equal(t, fiber.StatusUnprocessableEntity, code)
	assert.Contains(t, body, "secret_references_not_supported")
}
