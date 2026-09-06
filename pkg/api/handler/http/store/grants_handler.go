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
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storegrantdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storegrant"
	"github.com/gofiber/fiber/v2"
)

// GrantsHandler serves the MCP Store access grants: who may use which catalog
// server (or which configured instance of it) on a gateway. It is the Access
// page's read/write surface.
type GrantsHandler struct {
	grants appstore.GrantService
}

func NewGrantsHandler(grants appstore.GrantService) *GrantsHandler {
	return &GrantsHandler{grants: grants}
}

// grantResponse is one grant. registry_id is absent for a code-level grant.
type grantResponse struct {
	CatalogCode string   `json:"catalog_code"`
	RegistryID  string   `json:"registry_id,omitempty"`
	Groups      []string `json:"groups"`
	Users       []string `json:"users"`
}

type listGrantsResponse struct {
	Items []grantResponse `json:"items"`
	Total int             `json:"total"`
}

// setGrantRequest replaces one grant. Omit registry_id for a code-level grant;
// empty groups and users clear the grant.
type setGrantRequest struct {
	CatalogCode string   `json:"catalog_code"`
	RegistryID  string   `json:"registry_id"`
	Groups      []string `json:"groups"`
	Users       []string `json:"users"`
}

// List godoc
// @Summary      List MCP Store access grants
// @Description  Returns every access grant on the gateway: per catalog code, optionally narrowed to one configured instance (registry).
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  listGrantsResponse
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/grants [get]
func (h *GrantsHandler) List(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	grants, err := h.grants.ListByGateway(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := listGrantsResponse{Items: make([]grantResponse, 0, len(grants))}
	for _, g := range grants {
		if g == nil {
			continue
		}
		out.Items = append(out.Items, toGrantResponse(g))
	}
	out.Total = len(out.Items)
	return httpio.WriteOK(c, out)
}

// Set godoc
// @Summary      Set an MCP Store access grant
// @Description  Replaces the grant for a catalog code (or one configured instance of it) with the given groups and users; empty members clear it.
// @Tags         store
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string           true  "Gateway id"  format(uuid)
// @Param        body        body      setGrantRequest  true  "The grant"
// @Success      200         {object}  grantResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/grants [put]
func (h *GrantsHandler) Set(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req setGrantRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if strings.TrimSpace(req.CatalogCode) == "" {
		return httpio.WriteError(c, fmt.Errorf("catalog_code is required: %w", commonerrors.ErrValidation))
	}
	var registryID ids.RegistryID
	if raw := strings.TrimSpace(req.RegistryID); raw != "" {
		parsed, err := ids.Parse[ids.RegistryKind](raw)
		if err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid registry_id: %w", commonerrors.ErrValidation))
		}
		registryID = parsed
	}
	grant, err := h.grants.Set(c.UserContext(), appstore.SetGrantRequest{
		GatewayID:   gatewayID,
		CatalogCode: req.CatalogCode,
		RegistryID:  registryID,
		Groups:      req.Groups,
		Users:       req.Users,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, toGrantResponse(grant))
}

func toGrantResponse(g *storegrantdomain.Grant) grantResponse {
	out := grantResponse{
		CatalogCode: g.CatalogCode,
		Groups:      nonNil(g.Groups),
		Users:       nonNil(g.Users),
	}
	if g.IsInstance() {
		out.RegistryID = g.RegistryID.String()
	}
	return out
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
