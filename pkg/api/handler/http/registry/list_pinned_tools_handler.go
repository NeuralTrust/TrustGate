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
	"strconv"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type ListPinnedToolsHandler struct {
	tools appregistry.PinnedToolService
}

func NewListPinnedToolsHandler(tools appregistry.PinnedToolService) *ListPinnedToolsHandler {
	return &ListPinnedToolsHandler{tools: tools}
}

// Handle godoc
// @Summary      List the tool definitions of a pinned MCP registry
// @Description  Returns the tool definitions the registry has recorded, each with its decision. A definition is identified by (name, fingerprint): when an upstream changes a tool, the new definition appears as a pending item beside the approved one, and carries approved_version (the exposed definition) so it can be diffed. Filter with status=pending|approved|rejected. Paginated with limit (default 100, max 500) and offset over a stable first_seen_at, name, fingerprint order; total is the number of matching definitions across all pages.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true   "Gateway id"   format(uuid)
// @Param        id          path      string  true   "Registry id"  format(uuid)
// @Param        status      query     string  false  "Only definitions in this status"  Enums(pending, approved, rejected)
// @Param        limit       query     int     false  "Page size (default 100, max 500)"  minimum(1)  maximum(500)
// @Param        offset      query     int     false  "Rows to skip, in first_seen_at, name, fingerprint order"  minimum(0)
// @Success      200         {object}  response.PinnedToolsResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/pinned-tools [get]
func (h *ListPinnedToolsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var status *domain.ToolStatus
	if raw := c.Query("status"); raw != "" {
		s := domain.ToolStatus(raw)
		if !s.IsValid() {
			return httpio.WriteError(c, fmt.Errorf("%w: status must be one of pending, approved, rejected", httpio.ErrInvalidQuery))
		}
		status = &s
	}
	page := appregistry.PinnedToolPage{Limit: appregistry.DefaultPinnedToolsPage}
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > appregistry.MaxPinnedToolsPage {
			return httpio.WriteError(c, fmt.Errorf("%w: limit must be between 1 and %d", httpio.ErrInvalidQuery, appregistry.MaxPinnedToolsPage))
		}
		page.Limit = n
	}
	if raw := c.Query("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return httpio.WriteError(c, fmt.Errorf("%w: offset must be zero or positive", httpio.ErrInvalidQuery))
		}
		page.Offset = n
	}
	list, err := h.tools.List(c.UserContext(), gatewayID, id, status, page)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromPinnedToolList(list, page))
}
