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
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/gofiber/fiber/v2"
)

type EveryoneHandler struct {
	everyone appstore.EveryoneService
}

func NewEveryoneHandler(everyone appstore.EveryoneService) *EveryoneHandler {
	return &EveryoneHandler{everyone: everyone}
}

// Get godoc
// @Summary      Get the MCP Store Everyone access
// @Description  Returns the Store level and servers every group passes on to its members, and the excluded groups. An empty mode means the gateway has none.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  storeresponse.Everyone
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/everyone [get]
func (h *EveryoneHandler) Get(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	everyone, err := h.everyone.GetEveryone(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, toEveryoneResponse(everyone))
}

// Set godoc
// @Summary      Set the MCP Store Everyone access
// @Description  Replaces the gateway's Everyone access: mode open or curated (curated needs at least one grant), the servers it grants, and the excluded group keys. Mode is required; an empty mode removes it.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                    true  "Gateway id"  format(uuid)
// @Param        body        body      storerequest.SetEveryone  true  "The Everyone access"
// @Success      200         {object}  storeresponse.Everyone
// @Success      204         "Everyone access removed"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/everyone [put]
func (h *EveryoneHandler) Set(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req storerequest.SetEveryone
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if req.Mode == nil {
		return httpio.WriteError(c, fmt.Errorf("mode is required; an empty mode removes Everyone: %w", commonerrors.ErrValidation))
	}
	grants := make([]storeaccessdomain.EveryoneGrant, 0, len(req.Grants))
	for _, g := range req.Grants {
		grant := storeaccessdomain.EveryoneGrant{CatalogCode: g.CatalogCode}
		if raw := strings.TrimSpace(g.RegistryID); raw != "" {
			parsed, err := ids.Parse[ids.RegistryKind](raw)
			if err != nil {
				return httpio.WriteError(c, fmt.Errorf("invalid registry_id: %w", commonerrors.ErrValidation))
			}
			grant.RegistryID = parsed
		}
		grants = append(grants, grant)
	}
	everyone, err := h.everyone.Set(c.UserContext(), appstore.SetEveryoneRequest{
		GatewayID:      gatewayID,
		Mode:           *req.Mode,
		Grants:         grants,
		ExcludedGroups: req.ExcludedGroups,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if everyone == nil {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return httpio.WriteOK(c, toEveryoneResponse(everyone))
}

func toEveryoneResponse(e *storeaccessdomain.Everyone) storeresponse.Everyone {
	out := storeresponse.Everyone{Grants: []storeresponse.EveryoneGrant{}, ExcludedGroups: []string{}}
	if e == nil {
		return out
	}
	out.Mode = e.Mode
	out.ExcludedGroups = nonNil(e.ExcludedGroups)
	for _, g := range e.Grants {
		grant := storeresponse.EveryoneGrant{CatalogCode: g.CatalogCode}
		if g.IsInstance() {
			grant.RegistryID = g.RegistryID.String()
		}
		out.Grants = append(out.Grants, grant)
	}
	return out
}
