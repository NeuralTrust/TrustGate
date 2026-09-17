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

package store

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

// MaterializeHandler serves the admin's "put this built-in on the shelf"
// request: POST /v1/gateways/{id}/registries/from-catalog.
type MaterializeHandler struct {
	materializer appstore.CatalogMaterializer
}

func NewMaterializeHandler(materializer appstore.CatalogMaterializer) *MaterializeHandler {
	return &MaterializeHandler{materializer: materializer}
}

type materializeRequest struct {
	Code string `json:"code"`
}

// Handle godoc
// @Summary      Materialise a catalog MCP server
// @Description  Creates the shared registry for a self-service catalog server (idempotent: an existing registry for the code is returned). Servers that need admin credentials answer 409; connect them from the registry panel instead.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Param        body        body      materializeRequest  true  "Catalog code"
// @Success      200         {object}  response.RegistryResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/from-catalog [post]
func (h *MaterializeHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req materializeRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	reg, err := h.materializer.Materialize(c.UserContext(), gatewayID, req.Code)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromRegistry(reg))
}
