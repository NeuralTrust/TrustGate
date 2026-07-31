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
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type ListModelsHandler struct {
	service    appcatalog.Service
	serverless appcatalog.ServerlessFilter
}

func NewListModelsHandler(
	service appcatalog.Service,
	serverless appcatalog.ServerlessFilter,
) *ListModelsHandler {
	return &ListModelsHandler{service: service, serverless: serverless}
}

// Handle godoc
// @Summary      List model catalog
// @Description  Returns the catalog of supported models, optionally filtered by provider. When gateway_id and registry_id are supplied for an AWS Bedrock registry, the list is narrowed to the models those credentials can invoke serverless (on-demand base models and system-defined inference profiles), excluding Bedrock Marketplace, Provisioned Throughput and custom models. Malformed ids and unreachable AWS endpoints are ignored and yield the full catalog.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Param        provider     query     string  false  "Filter by provider id"
// @Param        gateway_id   query     string  false  "Gateway of the registry to scope availability to"  format(uuid)
// @Param        registry_id  query     string  false  "Registry whose credentials decide model availability"  format(uuid)
// @Success      200          {object}  map[string][]response.ModelResponse
// @Failure      401          {object}  httpio.ErrorBody
// @Router       /v1/models-catalog [get]
func (h *ListModelsHandler) Handle(c *fiber.Ctx) error {
	providerCode := c.Query("provider")
	models, err := h.service.ListModels(c.UserContext(), providerCode)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	// Availability is per credential set, so it can only be narrowed when the
	// caller names the registry to scope it to. Unparseable ids fall through to
	// the unfiltered catalog rather than failing a read-only listing.
	gatewayID, gatewayErr := ids.Parse[ids.GatewayKind](c.Query("gateway_id"))
	registryID, registryErr := ids.Parse[ids.RegistryKind](c.Query("registry_id"))
	if gatewayErr == nil && registryErr == nil {
		models = h.serverless.Filter(c.UserContext(), appcatalog.ServerlessFilterInput{
			ProviderCode: providerCode,
			GatewayID:    gatewayID,
			RegistryID:   registryID,
			Models:       models,
		})
	}

	out := make([]response.ModelResponse, 0, len(models))
	for _, m := range models {
		out = append(out, response.FromModel(m))
	}
	return httpio.WriteOK(c, fiber.Map{"items": out})
}
