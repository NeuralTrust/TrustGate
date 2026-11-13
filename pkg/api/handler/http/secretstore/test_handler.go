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

package secretstore

import (
	"github.com/gofiber/fiber/v2"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/secretstore/response"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// TestHandler tests a secret against the admin's own stores.
type TestHandler struct {
	gateways GatewayFinder
	sources  appsecretstore.SourceResolver
	tester   appsecretstore.Tester
}

// NewTestHandler returns a TestHandler.
func NewTestHandler(gateways GatewayFinder, sources appsecretstore.SourceResolver, tester appsecretstore.Tester) *TestHandler {
	return &TestHandler{gateways: gateways, sources: sources, tester: tester}
}

// Handle godoc
// @Summary      Test a secret store
// @Description  Authenticates to the store and, when a path is given, reads it, from the admin itself. Only for a gateway whose stores the admin loads (source control_plane); a gateway served by its own data planes answers 409 test_runs_on_data_plane and is tested through the data plane's diagnostics route. Requires secret_stores:read. Never returns the value.
// @Tags         secret-stores
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                             true   "Gateway id"  format(uuid)
// @Param        name        path      string                             true   "Store name"
// @Param        body        body      request.TestSecretRequest          false  "What to read"
// @Success      200         {object}  response.TestSecretResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/secret-stores/{name}/test [post]
func (h *TestHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	ctx := c.UserContext()
	gw, err := h.gateways.FindByID(ctx, gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	src, err := h.sources.Source(ctx, gw)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if !src.Supported {
		return httpio.WriteError(c, refdomain.ErrReferencesNotSupported)
	}
	if src.Kind != appsecretstore.KindControlPlane {
		return httpio.WriteError(c, refdomain.ErrTestRunsOnDataPlane)
	}
	in, err := request.Bind(c, gatewayID, c.Params("name"))
	if err != nil {
		return httpio.WriteError(c, err)
	}
	result, err := h.tester.Test(ctx, in)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromTestResult(result))
}
