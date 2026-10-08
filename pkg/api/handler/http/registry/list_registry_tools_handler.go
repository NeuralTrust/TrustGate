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
	"encoding/json"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type ListRegistryToolsHandler struct {
	introspector appmcp.Introspector
}

func NewListRegistryToolsHandler(introspector appmcp.Introspector) *ListRegistryToolsHandler {
	return &ListRegistryToolsHandler{introspector: introspector}
}

type ListRegistryToolsResponse struct {
	Tools []RegistryTool `json:"tools"`
}

// RegistryTool is a tool exactly as the upstream listed it (its raw payload is
// passed through unmodified) plus what pinning needs. Fingerprint is the
// identity the data plane screens by, computed by appmcp.ToolCandidate from the
// same Tool value; Pinnable is false, with no fingerprint, for a tool whose
// definition cannot be stored (for example a NUL character).
type RegistryTool struct {
	Tool        appmcp.Tool
	Fingerprint string
	Pinnable    bool
}

func (t RegistryTool) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(t.Tool)
	if err != nil {
		return nil, err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	pinnable, _ := json.Marshal(t.Pinnable)
	payload["pinnable"] = pinnable
	if t.Fingerprint != "" {
		fp, _ := json.Marshal(t.Fingerprint)
		payload["fingerprint"] = fp
	} else {
		delete(payload, "fingerprint")
	}
	return json.Marshal(payload)
}

// Handle godoc
// @Summary      List an MCP backend's tools
// @Description  Introspects the MCP server behind the registry and returns its advertised tools under their native upstream names. Each tool is passed through as the server declared it (name plus whatever else it exposes, e.g. description and inputSchema), with two additive fields: fingerprint, the identity a pinned registry screens tools by (the value to send to PUT tool-pinning), and pinnable, false (with no fingerprint) for a tool whose definition cannot be stored. Returns 409 when the registry cannot be introspected from the admin plane (per-principal auth or URL variables), and 502 when the upstream MCP server is unreachable or its tools/list call fails.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  ListRegistryToolsResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Failure      502         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/tools [get]
func (h *ListRegistryToolsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	tools, err := h.introspector.ListRegistryTools(c.UserContext(), gatewayID, id)
	if err != nil {
		if errors.Is(err, appmcp.ErrUpstreamUnavailable) {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": appmcp.ErrUpstreamUnavailable.Error()})
		}
		return httpio.WriteError(c, err)
	}
	out := make([]RegistryTool, 0, len(tools))
	for _, tool := range tools {
		item := RegistryTool{Tool: tool}
		if cand, err := appmcp.ToolCandidate(tool); err == nil {
			item.Fingerprint, item.Pinnable = cand.Fingerprint, true
		}
		out = append(out, item)
	}
	return httpio.WriteOK(c, ListRegistryToolsResponse{Tools: out})
}
