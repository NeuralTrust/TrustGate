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
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type ListRegistryToolsHandler struct {
	introspector appmcp.Introspector
}

func NewListRegistryToolsHandler(introspector appmcp.Introspector) *ListRegistryToolsHandler {
	return &ListRegistryToolsHandler{introspector: introspector}
}

type ListRegistryToolsResponse struct {
	Tools []appmcp.Tool `json:"tools"`
}

func (h *ListRegistryToolsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	tools, err := h.introspector.ListRegistryTools(c.UserContext(), gatewayID, id)
	if err != nil {
		if errors.Is(err, appmcp.ErrUpstreamUnavailable) {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
		}
		return helpers.WriteError(c, err)
	}
	if tools == nil {
		tools = []appmcp.Tool{}
	}
	return helpers.WriteOK(c, ListRegistryToolsResponse{Tools: tools})
}
