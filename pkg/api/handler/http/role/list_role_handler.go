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

package role

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/role/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/role/response"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/gofiber/fiber/v2"
)

type ListRoleHandler struct {
	finder approle.Finder
}

func NewListRoleHandler(finder approle.Finder) *ListRoleHandler {
	return &ListRoleHandler{finder: finder}
}

// Handle godoc
// @Summary      List roles
// @Description  Returns a paginated list of roles in a gateway.
// @Tags         roles
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true   "Gateway id"  format(uuid)
// @Param        name        query     string  false  "Filter by name (substring match)"
// @Param        page        query     int     false  "Page number (1-based)"
// @Param        size        query     int     false  "Page size"
// @Success      200         {object}  response.ListRoleResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/roles [get]
func (h *ListRoleHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	page, err := httpio.ParsePage(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	size, err := httpio.ParseSize(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	req := request.ListRoleRequest{
		Name: c.Query("name"),
		Page: page,
		Size: size,
	}
	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID:    gatewayID,
		NameContains: req.Name,
		Page:         req.Page,
		Size:         req.Size,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := response.ListRoleResponse{
		Items: make([]response.RoleResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, role := range items {
		out.Items = append(out.Items, response.FromRole(role))
	}
	return httpio.WriteOK(c, out)
}
