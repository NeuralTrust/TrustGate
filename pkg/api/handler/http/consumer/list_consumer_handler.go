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

package consumer

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type ListConsumerHandler struct {
	finder appconsumer.Finder
}

func NewListConsumerHandler(finder appconsumer.Finder) *ListConsumerHandler {
	return &ListConsumerHandler{finder: finder}
}

// Handle godoc
// @Summary      List consumers
// @Description  Returns a paginated list of consumers in a gateway.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true   "Gateway id"  format(uuid)
// @Param        search      query     string  false  "Substring match on name or slug (alias: name)"
// @Param        name        query     string  false  "Alias of search"
// @Param        type        query     string  false  "Filter by consumer type (LLM, MCP, A2A)"
// @Param        active      query     bool    false  "Filter by active flag"
// @Param        auth_id     query     string  false  "Filter consumers linked to this auth id"  format(uuid)
// @Param        sort        query     string  false  "Sort field (name, created_at, updated_at, type)"
// @Param        order       query     string  false  "Sort order (asc, desc)"
// @Param        page        query     int     false  "Page number (1-based)"
// @Param        size        query     int     false  "Page size"
// @Success      200         {object}  response.ListConsumerResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers [get]
func (h *ListConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	page, err := httpio.ParseListingPage(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	sort, err := httpio.ParseSort(c, domain.SortableFields)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	active, err := httpio.ParseOptionalBool(c, "active")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var consumerType domain.Type
	if raw := c.Query("type"); raw != "" {
		consumerType = domain.Type(raw)
		if !domain.IsValidType(consumerType) {
			return httpio.WriteError(c, httpio.ErrInvalidFilter)
		}
	}
	var authID ids.AuthID
	if raw := c.Query("auth_id"); raw != "" {
		authID, err = ids.Parse[ids.AuthKind](raw)
		if err != nil {
			return httpio.WriteError(c, httpio.ErrInvalidFilter)
		}
	}
	req := request.ListConsumerRequest{
		Search: httpio.ParseSearch(c),
		Type:   consumerType,
		Active: active,
		AuthID: authID,
		Page:   page,
		Sort:   sort,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID: gatewayID,
		Search:    req.Search,
		Type:      req.Type,
		Active:    req.Active,
		AuthID:    req.AuthID,
		Page:      req.Page,
		Sort:      req.Sort,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}

	out := response.ListConsumerResponse{
		Items: make([]response.ConsumerResponse, 0, len(items)),
		Page:  req.Page.Number,
		Size:  req.Page.Size,
		Total: total,
	}
	for _, cons := range items {
		out.Items = append(out.Items, response.FromConsumer(cons))
	}
	return httpio.WriteOK(c, out)
}
