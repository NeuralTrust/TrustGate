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

package auth

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/gofiber/fiber/v2"
)

type ListAuthHandler struct {
	finder appauth.Finder
}

func NewListAuthHandler(finder appauth.Finder) *ListAuthHandler {
	return &ListAuthHandler{finder: finder}
}

// Handle godoc
// @Summary      List auths
// @Description  Returns a paginated list of auths in a gateway.
// @Tags         auths
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true   "Gateway id"  format(uuid)
// @Param        search      query     string  false  "Substring match on name (alias: name)"
// @Param        name        query     string  false  "Alias of search"
// @Param        type        query     string  false  "Filter by auth type (api_key, oauth2, mtls; oidc is a deprecated alias of oauth2)"
// @Param        enabled     query     bool    false  "Filter by enabled flag"
// @Param        sort        query     string  false  "Sort field (name, created_at, updated_at, type)"
// @Param        order       query     string  false  "Sort order (asc, desc)"
// @Param        page        query     int     false  "Page number (1-based)"
// @Param        size        query     int     false  "Page size"
// @Success      200         {object}  response.ListAuthResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths [get]
func (h *ListAuthHandler) Handle(c *fiber.Ctx) error {
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
	var authType domain.Type
	if raw := c.Query("type"); raw != "" {
		authType = domain.NormalizeType(domain.Type(raw))
		if !domain.IsValidType(authType) {
			return httpio.WriteError(c, httpio.ErrInvalidFilter)
		}
	}
	req := request.ListAuthRequest{
		Search:  httpio.ParseSearch(c),
		Type:    authType,
		Enabled: enabled,
		Page:    page,
		Sort:    sort,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID: gatewayID,
		Search:    req.Search,
		Type:      req.Type,
		Enabled:   req.Enabled,
		Page:      req.Page,
		Sort:      req.Sort,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}

	out := response.ListAuthResponse{
		Items: make([]response.AuthResponse, 0, len(items)),
		Page:  req.Page.Number,
		Size:  req.Page.Size,
		Total: total,
	}
	for _, a := range items {
		out.Items = append(out.Items, response.FromAuth(a))
	}
	return httpio.WriteOK(c, out)
}
