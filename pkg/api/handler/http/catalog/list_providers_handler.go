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

package catalog

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/gofiber/fiber/v2"
)

type ListProvidersHandler struct {
	service appcatalog.Service
}

func NewListProvidersHandler(service appcatalog.Service) *ListProvidersHandler {
	return &ListProvidersHandler{service: service}
}

// Handle godoc
// @Summary      List provider catalog
// @Description  Returns the catalog of supported LLM providers.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string][]response.ProviderResponse
// @Failure      401  {object}  httpio.ErrorBody
// @Router       /v1/providers-catalog [get]
func (h *ListProvidersHandler) Handle(c *fiber.Ctx) error {
	providers, err := h.service.ListProviders(c.UserContext())
	if err != nil {
		return httpio.WriteError(c, err)
	}
	out := make([]response.ProviderResponse, 0, len(providers))
	for _, p := range providers {
		out = append(out, response.FromProvider(p))
	}
	return httpio.WriteOK(c, fiber.Map{"items": out})
}
