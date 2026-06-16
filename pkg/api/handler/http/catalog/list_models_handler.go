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
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/catalog/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appcatalog "github.com/NeuralTrust/AgentGateway/pkg/app/catalog"
	"github.com/gofiber/fiber/v2"
)

type ListModelsHandler struct {
	service appcatalog.Service
}

func NewListModelsHandler(service appcatalog.Service) *ListModelsHandler {
	return &ListModelsHandler{service: service}
}

// Handle godoc
// @Summary      List model catalog
// @Description  Returns the catalog of supported models, optionally filtered by provider.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Param        provider  query     string  false  "Filter by provider id"
// @Success      200       {object}  map[string][]response.ModelResponse
// @Failure      401       {object}  helpers.ErrorBody
// @Router       /v1/models-catalog [get]
func (h *ListModelsHandler) Handle(c *fiber.Ctx) error {
	models, err := h.service.ListModels(c.UserContext(), c.Query("provider"))
	if err != nil {
		return helpers.WriteError(c, err)
	}
	out := make([]response.ModelResponse, 0, len(models))
	for _, m := range models {
		out = append(out, response.FromModel(m))
	}
	return helpers.WriteOK(c, fiber.Map{"items": out})
}
