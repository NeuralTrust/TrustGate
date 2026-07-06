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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/gofiber/fiber/v2"
)

type ListMCPServersHandler struct {
	catalog appcatalog.MCPServerCatalog
}

func NewListMCPServersHandler(catalog appcatalog.MCPServerCatalog) *ListMCPServersHandler {
	return &ListMCPServersHandler{catalog: catalog}
}

type ListMCPServersResponse struct {
	MCPServers []domain.MCPServer `json:"mcp_servers"`
}

// Handle godoc
// @Summary      List the MCP servers catalog
// @Description  Returns the curated catalog of well-known remote MCP servers, used to prefill MCP registry creation.
// @Tags         catalog
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  ListMCPServersResponse
// @Failure      401  {object}  httpio.ErrorBody
// @Router       /v1/mcp-servers-catalog [get]
func (h *ListMCPServersHandler) Handle(c *fiber.Ctx) error {
	return httpio.WriteOK(c, ListMCPServersResponse{MCPServers: h.catalog.ListMCPServers()})
}
