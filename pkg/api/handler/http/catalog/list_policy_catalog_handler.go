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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/helpers"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/gofiber/fiber/v2"
)

type ListPolicyCatalogHandler struct {
	service appplugins.CatalogService
}

func NewListPolicyCatalogHandler(service appplugins.CatalogService) *ListPolicyCatalogHandler {
	return &ListPolicyCatalogHandler{service: service}
}

// Handle godoc
// @Summary      List policy catalog
// @Description  Returns the catalog of available policies grouped by type. Each entry includes the settings schema needed to render its configuration form dynamically.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  appplugins.Catalog
// @Failure      401  {object}  helpers.ErrorBody
// @Router       /v1/policies-catalog [get]
func (h *ListPolicyCatalogHandler) Handle(c *fiber.Ctx) error {
	return helpers.WriteOK(c, h.service.Catalog())
}
