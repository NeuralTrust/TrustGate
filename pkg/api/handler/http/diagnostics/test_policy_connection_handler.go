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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	policyrequest "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/request"
	policyresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
)

type TestPolicyConnectionHandler struct {
	verifier jwt.ProxyTokenVerifier
	tester   apppolicy.ConnectionTester
}

func NewTestPolicyConnectionHandler(verifier jwt.ProxyTokenVerifier, tester apppolicy.ConnectionTester) *TestPolicyConnectionHandler {
	return &TestPolicyConnectionHandler{verifier: verifier, tester: tester}
}

// Handle godoc
// @Summary      Test a policy's connection from the data plane
// @Description  Runs the policy connection test from this data plane's own network, so the result reflects what serving traffic will reach. Authorized by a control-plane-minted diagnostics token bound to the gateway. Same body and outcomes as the admin policy test-connection endpoint, plus code "not_synced" when this plane's config snapshot does not carry the policy (or its latest key) yet: retry shortly.
// @Tags         diagnostics
// @Accept       json
// @Produce      json
// @Param        X-AG-Diagnostics-Token  header    string                                true  "Control-plane-minted diagnostics JWT"
// @Param        gateway_id              path      string                                true  "Gateway id"  format(uuid)
// @Param        body                    body      policyrequest.TestConnectionRequest   true  "Policy settings to test"
// @Success      200                     {object}  policyresponse.TestConnectionResponse
// @Failure      400                     {object}  httpio.ErrorBody
// @Failure      401                     {object}  httpio.ErrorBody
// @Failure      422                     {object}  httpio.ErrorBody
// @Router       /__diagnostics/gateways/{gateway_id}/policies/test-connection [post]
func (h *TestPolicyConnectionHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if !authorizeGateway(c, h.verifier, gatewayID) {
		return unauthorized(c)
	}
	var req policyrequest.TestConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	in, err := req.ToInput(gatewayID, true)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	result, err := h.tester.Test(c.UserContext(), in)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, policyresponse.FromTestConnectionResult(result))
}
