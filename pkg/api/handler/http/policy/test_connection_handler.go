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

package policy

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type TestConnectionHandler struct {
	tester apppolicy.ConnectionTester
}

func NewTestConnectionHandler(tester apppolicy.ConnectionTester) *TestConnectionHandler {
	return &TestConnectionHandler{tester: tester}
}

// Handle godoc
// @Summary      Test a policy's connection to its upstream service
// @Description  Checks, with the settings as the form holds them, that the gateway can use the service the policy calls (today google_model_armor). In edit mode pass policy_id: a masked credential then stands for the stored one, as long as the fields it is bound to (location, project) are unchanged. Every probe outcome answers 200; read "ok" and "code" (ok, invalid_credentials, permission_denied, api_disabled, template_not_found, throttled, timeout, unreachable, invalid_config, reenter_credentials). A gateway served by a hybrid data plane answers 409: run the test on its data plane.
// @Tags         policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                          true  "Gateway id"  format(uuid)
// @Param        body        body      request.TestConnectionRequest   true  "Policy settings to test"
// @Success      200         {object}  response.TestConnectionResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      403         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies/test-connection [post]
func (h *TestConnectionHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.TestConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	in, err := req.ToInput(gatewayID, false)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	result, err := h.tester.Test(c.UserContext(), in)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromTestConnectionResult(result))
}
