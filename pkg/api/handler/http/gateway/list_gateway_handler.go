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

package gateway

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type ListGatewayHandler struct {
	finder        appgateway.Finder
	baseDomain    string
	mcpBaseDomain string
}

func NewListGatewayHandler(finder appgateway.Finder, baseDomain, mcpBaseDomain string) *ListGatewayHandler {
	return &ListGatewayHandler{finder: finder, baseDomain: baseDomain, mcpBaseDomain: mcpBaseDomain}
}

// Handle godoc
// @Summary      List gateways
// @Description  Returns a paginated list of gateways.
// @Tags         gateways
// @Produce      json
// @Security     BearerAuth
// @Param        slug  query     string  false  "Filter by slug (substring match)"
// @Param        page  query     int     false  "Page number (1-based)"
// @Param        size  query     int     false  "Page size"
// @Success      200   {object}  response.ListGatewayResponse
// @Failure      400   {object}  httpio.ErrorBody
// @Failure      401   {object}  httpio.ErrorBody
// @Router       /v1/gateways [get]
func (h *ListGatewayHandler) Handle(c *fiber.Ctx) error {
	page, err := httpio.ParsePage(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	size, err := httpio.ParseSize(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	req := request.ListGatewayRequest{
		Slug: c.Query("slug"),
		Page: page,
		Size: size,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		SlugContains: req.Slug,
		Page:         req.Page,
		Size:         req.Size,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}

	out := response.ListGatewayResponse{
		Items: make([]response.GatewayResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, g := range items {
		out.Items = append(out.Items, response.FromDomain(g, h.baseDomain, h.mcpBaseDomain))
	}
	return httpio.WriteOK(c, out)
}
