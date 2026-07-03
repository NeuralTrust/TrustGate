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

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateRegistryHandler struct {
	updater appregistry.Updater
}

func NewUpdateRegistryHandler(updater appregistry.Updater) *UpdateRegistryHandler {
	return &UpdateRegistryHandler{updater: updater}
}

// Handle godoc
// @Summary      Update a backend
// @Description  Updates an existing registry.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                        true  "Gateway id"  format(uuid)
// @Param        id          path      string                        true  "Registry id"  format(uuid)
// @Param        body        body      request.UpdateRegistryRequest  true  "Registry fields to update"
// @Success      200         {object}  response.RegistryResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id} [put]
func (h *UpdateRegistryHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	var req request.UpdateRegistryRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	b, err := h.updater.Update(c.UserContext(), appregistry.UpdateInput{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            req.Name,
		Enabled:         req.Enabled,
		Provider:        req.Provider,
		ProviderOptions: req.ProviderOptions,
		Description:     req.Description,
		Auth:            req.ToAuth(),
		HealthChecks:    req.ToHealthChecks(),
		MCPTarget:       req.ToMCPTarget(),
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromRegistry(b))
}
