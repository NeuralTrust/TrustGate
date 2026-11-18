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

package store

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	storerequest "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/request"
	storeresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/response"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/gofiber/fiber/v2"
)

type AgentAccessHandler struct {
	access appstore.AgentAccessService
}

func NewAgentAccessHandler(access appstore.AgentAccessService) *AgentAccessHandler {
	return &AgentAccessHandler{access: access}
}

// List godoc
// @Summary      List the Employee portal's agent access
// @Description  Returns every agent access row of the gateway: for everyone (principal_type all), a group or a user, the mode (all | selected | none) and the A2A registries picked when selected.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  storeresponse.AgentAccessList
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/agent-access [get]
func (h *AgentAccessHandler) List(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	rows, err := h.access.ListAgentAccessByGateway(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := storeresponse.AgentAccessList{Rows: make([]storeresponse.AgentAccess, 0, len(rows))}
	for _, row := range rows {
		if row != nil {
			out.Rows = append(out.Rows, toAgentAccessResponse(row))
		}
	}
	return httpio.WriteOK(c, out)
}

// Set godoc
// @Summary      Set one principal's agent access
// @Description  Sets which A2A agents everyone (principal_type all, empty principal_id), a group or a user may call from the Employee portal: mode all, selected (the agents in registry_ids) or none. An empty mode deletes the row.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                       true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.SetAgentAccess  true  "The row"
// @Success      200         {object}  storeresponse.AgentAccess
// @Success      204         "Row deleted"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/agent-access [put]
func (h *AgentAccessHandler) Set(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.SetAgentAccess
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, httpio.ErrInvalidBody)
	}
	registryIDs := make([]ids.RegistryID, 0, len(req.RegistryIDs))
	for _, raw := range req.RegistryIDs {
		id, err := ids.Parse[ids.RegistryKind](strings.TrimSpace(raw))
		if err != nil {
			return httpio.WriteError(c, fmt.Errorf("%w: registry_ids holds %q, which is not a registry id", httpio.ErrInvalidBody, raw))
		}
		registryIDs = append(registryIDs, id)
	}
	row, err := h.access.Set(c.UserContext(), appstore.SetAgentAccessRequest{
		GatewayID:     gatewayID,
		PrincipalType: storeaccessdomain.PrincipalType(strings.ToLower(strings.TrimSpace(req.PrincipalType))),
		PrincipalID:   req.PrincipalID,
		Mode:          req.Mode,
		RegistryIDs:   registryIDs,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if row == nil {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return httpio.WriteOK(c, toAgentAccessResponse(row))
}

func toAgentAccessResponse(row *storeaccessdomain.AgentAccess) storeresponse.AgentAccess {
	out := storeresponse.AgentAccess{
		PrincipalType: string(row.PrincipalType),
		PrincipalID:   row.PrincipalID,
		Mode:          row.Mode,
		RegistryIDs:   make([]string, 0, len(row.RegistryIDs)),
	}
	for _, id := range row.RegistryIDs {
		out.RegistryIDs = append(out.RegistryIDs, id.String())
	}
	return out
}
