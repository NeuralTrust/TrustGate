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

package registry

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type TestConnectionHandler struct {
	tester appregistry.ConnectionTester
}

func NewTestConnectionHandler(tester appregistry.ConnectionTester) *TestConnectionHandler {
	return &TestConnectionHandler{tester: tester}
}

// Handle godoc
// @Summary      Test a backend connection
// @Description  Validates connectivity and credentials against the provider's API with a lightweight, auth-only request. Test either a stored registry (registry_id) or an inline candidate configuration (provider + auth). Always returns 200; inspect "ok" and "stage" for the outcome.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                          true  "Gateway id"  format(uuid)
// @Param        body        body      request.TestConnectionRequest   true  "Connection to test"
// @Success      200         {object}  response.TestConnectionResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      422         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/test-connection [post]
func (h *TestConnectionHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.TestConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	in := appregistry.TestConnectionInput{GatewayID: gatewayID}
	if req.IsByID() {
		registryID, err := ids.Parse[ids.RegistryKind](req.RegistryID)
		if err != nil {
			return helpers.WriteError(c, fmt.Errorf("invalid registry_id: %w", commonerrors.ErrValidation))
		}
		in.RegistryID = &registryID
	} else {
		in.Provider = req.Provider
		in.ProviderOptions = req.ProviderOptions
		in.Auth = req.ToAuth()
	}

	result, err := h.tester.Test(c.UserContext(), in)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromTestConnectionResult(result))
}
