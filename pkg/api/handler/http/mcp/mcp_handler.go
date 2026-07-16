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

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const (
	serverName            = "trustgate"
	serverVersion         = "1.0"
	latestProtocolVersion = "2025-06-18"
)

var supportedProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

const (
	codeConsentRequired  = -32003
	codeResourceNotFound = -32002
)

type Handler struct {
	gateway    *RPCGateway
	roleScoper appmcp.RoleScoper
}

func NewHandler(gateway *RPCGateway, roleScoper appmcp.RoleScoper) *Handler {
	return &Handler{gateway: gateway, roleScoper: roleScoper}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (h *Handler) MethodNotAllowed(c *fiber.Ctx) error {
	c.Set(fiber.HeaderAllow, fiber.MethodPost)
	return c.SendStatus(fiber.StatusMethodNotAllowed)
}

func (h *Handler) Handle(c *fiber.Ctx) error {
	rc, err := resolveMCPConsumer(c)
	if err != nil {
		skipMetrics(c)
		return err
	}
	rc, err = h.scopeByRoles(c, rc)
	if err != nil {
		skipMetrics(c)
		return err
	}

	if rt := trace.FromContext(c.UserContext()); rt != nil {
		rt.SetConsumer(rc.Consumer.ID.String(), rc.Consumer.Name)
	}

	var req rpcRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		skipMetrics(c)
		return writeRPCError(c, nil, codeParseError, "parse error")
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		skipMetrics(c)
		return writeRPCError(c, req.ID, codeInvalidRequest, "invalid request")
	}

	if isNotification(req) {
		skipMetrics(c)
		return c.SendStatus(fiber.StatusAccepted)
	}

	switch req.Method {
	case "initialize":
		h.recordInitialize(c)
		return h.handleInitialize(c, req)
	case "ping":
		skipMetrics(c)
		return writeRPCResult(c, req.ID, struct{}{})
	}

	result, err := h.gateway.Dispatch(c.UserContext(), rc, req.Method, req.Params)
	if err != nil {
		return writeAppError(c, req.ID, err)
	}
	if raw, ok := result.(json.RawMessage); ok {
		return writeRawRPCResult(c, req.ID, raw)
	}
	return writeRPCResult(c, req.ID, result)
}

// skipMetrics tells the MCP metrics middleware not to publish an event for the
// current request (ping, notifications, or pre-dispatch failures).
func skipMetrics(c *fiber.Ctx) {
	c.Locals(string(infracontext.MCPSkipMetricsKey), true)
}

func (h *Handler) recordInitialize(c *fiber.Ctx) {
	rt := trace.FromContext(c.UserContext())
	if rt == nil {
		return
	}
	span := rt.StartSpan(trace.SpanMCP, "initialize")
	span.SetMCPRequest("initialize", "initialize", "", "", "")
	span.SetMCPStatus("ok", 0)
	span.End()
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

func (h *Handler) handleInitialize(c *fiber.Ctx, req rpcRequest) error {
	var params initializeParams
	_ = json.Unmarshal(req.Params, &params)
	version := latestProtocolVersion
	if supportedProtocolVersions[params.ProtocolVersion] {
		version = params.ProtocolVersion
	}
	return writeRPCResult(c, req.ID, fiber.Map{
		"protocolVersion": version,
		"capabilities": fiber.Map{
			"tools":     fiber.Map{"listChanged": false},
			"resources": fiber.Map{"subscribe": false, "listChanged": false},
			"prompts":   fiber.Map{"listChanged": false},
		},
		"serverInfo": fiber.Map{
			"name":    serverName,
			"version": serverVersion,
		},
	})
}

func writeAppError(c *fiber.Ctx, id json.RawMessage, err error) error {
	var (
		rpcErr        *appmcp.RPCError
		consentErr    *appmcp.ConsentRequiredError
		invalidParams *InvalidParamsError
	)
	switch {
	case errors.As(err, &rpcErr):
		applyRPCErrorHeaders(c, rpcErr)
		return writeJSON(c, rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error:   &rpcError{Code: int(rpcErr.Code), Message: rpcErr.Message, Data: rpcErr.Data},
		})
	case errors.As(err, &consentErr):
		connectURL := fmt.Sprintf("%s%s/connect?ticket=%s", c.BaseURL(), consentErr.Path, consentErr.Ticket)
		data, _ := json.Marshal(fiber.Map{
			"provider":    consentErr.Provider,
			"connect_url": connectURL,
		})
		return writeJSON(c, rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error: &rpcError{
				Code:    codeConsentRequired,
				Message: fmt.Sprintf("user consent required: open %s to connect %s", connectURL, consentErr.Provider),
				Data:    data,
			},
		})
	case errors.As(err, &invalidParams):
		return writeRPCError(c, id, codeInvalidParams, invalidParams.Reason)
	case errors.Is(err, ErrMethodNotFound):
		return writeRPCError(c, id, codeMethodNotFound, err.Error())
	case errors.Is(err, sts.ErrInteractionRequired):
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	case errors.Is(err, appmcp.ErrNoPrincipal), errors.Is(err, appmcp.ErrAudienceMismatch),
		errors.Is(err, sts.ErrNoUserIdentity):
		return writeRPCError(c, id, codeInvalidRequest, err.Error())
	case errors.Is(err, appmcp.ErrToolNotFound), errors.Is(err, appmcp.ErrPromptNotFound):
		return writeRPCError(c, id, codeInvalidParams, err.Error())
	case errors.Is(err, appmcp.ErrResourceNotFound):
		return writeRPCError(c, id, codeResourceNotFound, err.Error())
	case errors.Is(err, appmcp.ErrNoMCPRegistries):
		return writeRPCError(c, id, codeInvalidRequest, err.Error())
	default:
		return writeRPCError(c, id, codeInternalError, err.Error())
	}
}

func isNotification(req rpcRequest) bool {
	return len(req.ID) == 0 || string(req.ID) == "null"
}

func writeRPCResult(c *fiber.Ctx, id json.RawMessage, result any) error {
	return writeJSON(c, rpcResponse{JSONRPC: "2.0", ID: normalizeID(id), Result: result})
}

func writeRawRPCResult(c *fiber.Ctx, id json.RawMessage, result json.RawMessage) error {
	return writeJSON(c, struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{JSONRPC: "2.0", ID: normalizeID(id), Result: result})
}

func writeRPCError(c *fiber.Ctx, id json.RawMessage, code int, message string) error {
	return writeJSON(c, rpcResponse{
		JSONRPC: "2.0",
		ID:      normalizeID(id),
		Error:   &rpcError{Code: code, Message: message},
	})
}

func writeJSON(c *fiber.Ctx, body any) error {
	return c.Status(fiber.StatusOK).JSON(body)
}

func applyRPCErrorHeaders(c *fiber.Ctx, err *appmcp.RPCError) {
	if err == nil {
		return
	}
	for name, values := range err.HTTPHeaders {
		for _, value := range values {
			c.Response().Header.Add(name, value)
		}
	}
}

func normalizeID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func (h *Handler) scopeByRoles(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) (*appconsumer.RoutableConsumer, error) {
	if rc.Consumer.RoutingMode != consumerdomain.RoutingModeRoleBased {
		return rc, nil
	}
	data, ok := appconsumer.DataFromContext(c.UserContext())
	if !ok || data == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	scoped, err := h.roleScoper.Scope(c.UserContext(), rc, data)
	if err != nil {
		if errors.Is(err, appmcp.ErrNoRoleAccess) {
			return nil, fiber.NewError(fiber.StatusForbidden, err.Error())
		}
		return nil, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return scoped, nil
}

func resolveMCPConsumer(c *fiber.Ctx) (*appconsumer.RoutableConsumer, error) {
	authID, ok := appconsumer.AuthIDFromContext(c.UserContext())
	if !ok {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	data, ok := appconsumer.DataFromContext(c.UserContext())
	if !ok || data == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	rc, ok := data.MatchPath(c.Path())
	if !ok {
		return nil, fiber.NewError(fiber.StatusNotFound, "no virtual MCP configured for this path")
	}
	if rc.Consumer.Type != consumerdomain.TypeMCP {
		return nil, fiber.NewError(fiber.StatusNotFound, "consumer is not an MCP consumer")
	}
	if !hasAuth(rc, authID) {
		return nil, fiber.NewError(fiber.StatusForbidden, "credential not allowed for this consumer")
	}
	return rc, nil
}

func hasAuth(rc *appconsumer.RoutableConsumer, authID ids.AuthID) bool {
	for _, id := range rc.Consumer.AuthIDs {
		if id == authID {
			return true
		}
	}
	return false
}
