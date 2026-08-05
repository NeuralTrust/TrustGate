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

package policy

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy/response"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
)

type ListPolicyHandler struct {
	finder apppolicy.Finder
}

func NewListPolicyHandler(finder apppolicy.Finder) *ListPolicyHandler {
	return &ListPolicyHandler{finder: finder}
}

// Handle godoc
// @Summary      List policies
// @Description  Returns a paginated list of policies in a gateway.
// @Tags         policies
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true   "Gateway id"  format(uuid)
// @Param        search      query     string  false  "Substring match on name or slug (alias: name)"
// @Param        name        query     string  false  "Alias of search"
// @Param        enabled     query     bool    false  "Filter by enabled flag"
// @Param        global      query     bool    false  "Filter by global flag"
// @Param        mode        query     string  false  "Filter by mode (enforce, throttle, observe)"
// @Param        category    query     string  false  "Catalog category (group type); comma-separated multi"
// @Param        type        query     string  false  "Plugin slug (FE type filter); comma-separated multi"
// @Param        sort        query     string  false  "Sort field (name, created_at, updated_at, priority)"
// @Param        order       query     string  false  "Sort order (asc, desc)"
// @Param        page        query     int     false  "Page number (1-based)"
// @Param        size        query     int     false  "Page size"
// @Success      200         {object}  response.ListPolicyResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/policies [get]
func (h *ListPolicyHandler) Handle(c *fiber.Ctx) error {
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
	enabled, err := httpio.ParseOptionalBool(c, "enabled")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	global, err := httpio.ParseOptionalBool(c, "global")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var mode domain.Mode
	if raw := c.Query("mode"); raw != "" {
		mode = domain.Mode(raw)
		if !mode.IsValid() {
			return httpio.WriteError(c, httpio.ErrInvalidFilter)
		}
	}
	req := request.ListPolicyRequest{
		Search:     httpio.ParseSearch(c),
		Enabled:    enabled,
		Global:     global,
		Mode:       mode,
		Categories: httpio.ParseCSVQuery(c, "category"),
		Types:      httpio.ParseCSVQuery(c, "type"),
		Page:       page,
		Sort:       sort,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID:  gatewayID,
		Search:     req.Search,
		Enabled:    req.Enabled,
		Global:     req.Global,
		Mode:       req.Mode,
		Categories: req.Categories,
		Types:      req.Types,
		Page:       req.Page,
		Sort:       req.Sort,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}

	out := response.ListPolicyResponse{
		Items: make([]response.PolicyResponse, 0, len(items)),
		Page:  req.Page.Number,
		Size:  req.Page.Size,
		Total: total,
	}
	for _, p := range items {
		out.Items = append(out.Items, response.FromPolicy(p))
	}
	return httpio.WriteOK(c, out)
}
