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

package diagnostics

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore/response"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
)

// TestSecretHandler tests a secret against this data plane's own stores.
type TestSecretHandler struct {
	verifier jwt.ProxyTokenVerifier
	tester   appsecretstore.Tester
}

// NewTestSecretHandler returns a TestSecretHandler.
func NewTestSecretHandler(verifier jwt.ProxyTokenVerifier, tester appsecretstore.Tester) *TestSecretHandler {
	return &TestSecretHandler{verifier: verifier, tester: tester}
}

// Handle godoc
// @Summary      Test a secret store from the data plane
// @Description  Authenticates to one of this data plane's secret stores and, when a path is given, reads it, enforcing the store's gateway allowlist and allowed paths. Same contract as the admin test. Authorized by a control-plane-minted diagnostics token bound to the gateway. Never returns the value.
// @Tags         diagnostics
// @Accept       json
// @Produce      json
// @Param        X-AG-Diagnostics-Token  header    string                     true   "Control-plane-minted diagnostics JWT"
// @Param        gateway_id              path      string                     true   "Gateway id"  format(uuid)
// @Param        name                    path      string                     true   "Store name"
// @Param        body                    body      request.TestSecretRequest  false  "What to read"
// @Success      200                     {object}  response.TestSecretResponse
// @Failure      400                     {object}  httpio.ErrorBody
// @Failure      401                     {object}  httpio.ErrorBody
// @Failure      422                     {object}  httpio.ErrorBody
// @Router       /__diagnostics/gateways/{gateway_id}/secret-stores/{name}/test [post]
func (h *TestSecretHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if !authorizeGateway(c, h.verifier, gatewayID) {
		return unauthorized(c)
	}
	in, err := request.Bind(c, gatewayID, c.Params("name"))
	if err != nil {
		return httpio.WriteError(c, err)
	}
	result, err := h.tester.Test(c.UserContext(), in)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromTestResult(result))
}
