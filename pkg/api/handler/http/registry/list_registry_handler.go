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

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type ListRegistryHandler struct {
	finder        appregistry.Finder
	groupedFinder appregistry.GroupedFinder
}

func NewListRegistryHandler(finder appregistry.Finder, groupedFinder appregistry.GroupedFinder) *ListRegistryHandler {
	return &ListRegistryHandler{
		finder:        finder,
		groupedFinder: groupedFinder,
	}
}

// Handle godoc
// @Summary      List registries
// @Description  Returns one of two mutually exclusive variants: flat (items/page/size/total) when view and type are omitted, or grouped (view/groups/total_groups/total_instances) with view=grouped&type=LLM. Grouped requests require at most 200 total registries and must omit name, page, and size.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true   "Gateway id"  format(uuid)
// @Param        name        query     string  false  "Flat view only: filter by name (substring match)"
// @Param        page        query     int     false  "Flat view only: page number (1-based)"
// @Param        size        query     int     false  "Flat view only: page size (maximum 200)"
// @Param        view        query     string  false  "Response view"  Enums(grouped)
// @Param        type        query     string  false  "Grouped view only: required registry type; omit for flat view"  Enums(LLM)
// @Success      200         {object}  response.ListRegistryViewResponse  "Mutually exclusive variants: flat (items/page/size/total) or grouped (view/groups/total_groups/total_instances)"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries [get]
func (h *ListRegistryHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	queryArgs := c.Context().QueryArgs()
	req := request.ListRegistryRequest{
		Name:        c.Query("name"),
		View:        c.Query("view"),
		Type:        c.Query("type"),
		TypePresent: queryArgs.Has("type"),
		NamePresent: queryArgs.Has("name"),
		PagePresent: queryArgs.Has("page"),
		SizePresent: queryArgs.Has("size"),
	}
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, fmt.Errorf("%w: %v", httpio.ErrInvalidQuery, err))
	}
	if req.View == request.GroupedView {
		result, err := h.groupedFinder.Find(c.UserContext(), gatewayID)
		if err != nil {
			return httpio.WriteError(c, err)
		}
		return httpio.WriteOK(c, response.FromGroupedRegistries(result))
	}

	page, err := httpio.ParsePage(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	size, err := httpio.ParseSize(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	req.Page = page
	req.Size = size

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID:    gatewayID,
		NameContains: req.Name,
		Page:         req.Page,
		Size:         req.Size,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}

	out := response.ListRegistryResponse{
		Items: make([]response.RegistryResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, b := range items {
		out.Items = append(out.Items, response.FromRegistry(b))
	}
	return httpio.WriteOK(c, out)
}
