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
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type EnableToolPinningHandler struct {
	tools        appregistry.PinnedToolService
	introspector appmcp.Introspector
}

func NewEnableToolPinningHandler(tools appregistry.PinnedToolService, introspector appmcp.Introspector) *EnableToolPinningHandler {
	return &EnableToolPinningHandler{tools: tools, introspector: introspector}
}

// Handle godoc
// @Summary      Enable tool pinning with a confirmed list
// @Description  Makes the listed tools exactly the approved set and sets the registry's tool_policy to pinned, in one transaction, then publishes a new config snapshot. Tools are identified by the (name, fingerprint) returned by GET .../tools; the server re-reads the live tool list and approves the definitions it finds there. If a listed tool is no longer in the live list with that fingerprint (the upstream changed since it was reviewed) the call is 422 naming the stale tools and nothing is applied; an unreachable upstream is 502. A registry whose tools depend on the caller (per-principal auth or URL variables) cannot be introspected, so only an empty list is accepted for it. Any other approved definition goes back to pending and unlisted rejections stay rejected. An empty list is allowed. Every live tool that is not on the list is recorded as pending in the same transaction (a stored row, rejected included, is never overwritten, and the pending caps apply), so it appears for review immediately. Only MCP registries can be pinned; an LLM registry is 422. Disabling pinning is a plain registry update with tool_policy=auto.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                            true  "Gateway id"   format(uuid)
// @Param        id          path      string                            true  "Registry id"  format(uuid)
// @Param        body        body      request.EnableToolPinningRequest  true  "The confirmed tools, by name and fingerprint"
// @Success      200         {object}  response.RegistryResponse
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Failure      502         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/tool-pinning [put]
func (h *EnableToolPinningHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	actor, ok := requireActor(c)
	if !ok {
		return unauthenticated(c)
	}
	var req request.EnableToolPinningRequest
	if err := c.BodyParser(&req); err != nil {
		return badRequest(c, "invalid request body")
	}
	refs, err := req.Refs()
	if err != nil {
		if errors.Is(err, request.ErrBadToolPinning) {
			return badRequest(c, err.Error())
		}
		return httpio.WriteError(c, err)
	}
	candidates, unchecked, err := h.liveCandidates(c, gatewayID, id, refs)
	if err != nil {
		if errors.Is(err, appmcp.ErrUpstreamUnavailable) {
			return c.Status(fiber.StatusBadGateway).JSON(httpio.ErrorBody{Error: "upstream_unavailable", Message: "the MCP server could not be reached; nothing was changed"})
		}
		return httpio.WriteError(c, err)
	}
	reg, err := h.tools.Pin(c.UserContext(), appregistry.PinToolsInput{
		GatewayID:  gatewayID,
		RegistryID: id,
		Tools:      candidates,
		Unchecked:  unchecked,
		DecidedBy:  actor,
	})
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromRegistry(reg))
}

// liveCandidates splits the live upstream list by the confirmed refs, through
// the same appmcp.ToolCandidate the discovery filter uses: the approved
// definitions, and the unchecked ones (live but not confirmed), which are
// recorded as pending. Refs the live list does not contain are stale: none of
// the list is applied. A server that cannot be introspected has no live list, so
// only an empty list is accepted and nothing is recorded.
func (h *EnableToolPinningHandler) liveCandidates(c *fiber.Ctx, gatewayID ids.GatewayID, id ids.RegistryID, refs []domain.ToolRef) (approved, unchecked []domain.ToolCandidate, err error) {
	live, err := h.introspector.ListRegistryTools(c.UserContext(), gatewayID, id)
	if errors.Is(err, appmcp.ErrRegistryNotIntrospectable) {
		if len(refs) == 0 {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("%w: this server's tools depend on the caller (per-principal auth or URL variables), so they cannot be listed for review; pin it with an empty list", domain.ErrInvalidToolPolicy)
	}
	if err != nil {
		return nil, nil, err
	}
	byRef := make(map[domain.ToolRef]domain.ToolCandidate, len(live))
	for _, t := range live {
		if cand, err := appmcp.ToolCandidate(t); err == nil {
			byRef[cand.ToolRef] = cand
		}
	}
	var stale []string
	chosen := make(map[domain.ToolRef]struct{}, len(refs))
	for _, ref := range refs {
		if _, dup := chosen[ref]; dup {
			continue
		}
		chosen[ref] = struct{}{}
		cand, ok := byRef[ref]
		if !ok {
			stale = append(stale, ref.Name)
			continue
		}
		approved = append(approved, cand)
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		const maxNamed = 10
		listed := stale
		if len(listed) > maxNamed {
			listed = listed[:maxNamed]
		}
		return nil, nil, fmt.Errorf("%w: %d tool(s) changed or disappeared upstream since they were reviewed (%s); reload the list and confirm again", domain.ErrUnknownToolRefs, len(stale), strings.Join(listed, ", "))
	}
	for ref, cand := range byRef {
		if _, ok := chosen[ref]; !ok {
			unchecked = append(unchecked, cand)
		}
	}
	return approved, unchecked, nil
}
