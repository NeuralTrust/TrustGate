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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const (
	serverName    = "trustgate"
	serverVersion = "1.0"
)

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
	codePolicyBlocked    = -32001
)

type Handler struct {
	gateway    *RPCGateway
	roleScoper appmcp.RoleScoper
	protocol   ProtocolValidationRecorder
}

func NewHandler(gateway *RPCGateway, roleScoper appmcp.RoleScoper, rec ...ProtocolValidationRecorder) *Handler {
	h := &Handler{gateway: gateway, roleScoper: roleScoper}
	if len(rec) > 0 {
		h.protocol = rec[0]
	}
	return h
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
	if err := ensureMCPAuthenticated(c); err != nil {
		skipMetrics(c)
		return err
	}

	protocolHeader := c.Get("MCP-Protocol-Version")
	body := c.Body()
	invalidTopLevel := json.Valid(body) && !isJSONObject(body)
	var req rpcRequest
	parseErr := json.Unmarshal(body, &req)
	era := protocolEraLegacy
	if parseErr != nil || invalidTopLevel {
		if protocolHeader != "" && !isSupportedProtocolVersion(protocolHeader) {
			h.recordProtocolValidation(c, codeUnsupportedProtocolVersion, protocolEraModern)
			skipMetrics(c)
			return writeProtocolError(c, nil, unsupportedProtocolVersion(protocolHeader))
		}
		if parseErrorEra(protocolHeader) == protocolEraModern {
			if invalidTopLevel {
				h.recordProtocolValidation(c, codeInvalidRequest, protocolEraModern)
				skipMetrics(c)
				return writeBoundaryRPCError(c, nil, protocolEraModern, codeInvalidRequest, "invalid request")
			}
			h.recordProtocolValidation(c, codeParseError, protocolEraModern)
			skipMetrics(c)
			return writeBoundaryRPCError(c, nil, protocolEraModern, codeParseError, "parse error")
		}
	} else {
		var protocolErr *protocolError
		era, protocolErr = classifyEra(req, protocolHeader)
		if protocolErr != nil {
			h.recordProtocolValidation(c, protocolErr.code, era)
			skipMetrics(c)
			return writeProtocolError(c, req.ID, protocolErr)
		}
		if era == protocolEraModern {
			if protocolErr := validateModernRequest(req, modernHeaders(c)); protocolErr != nil {
				h.recordProtocolValidation(c, protocolErr.code, era)
				skipMetrics(c)
				return writeProtocolError(c, req.ID, protocolErr)
			}
			if isNotification(req, era) {
				skipMetrics(c)
				return c.Status(fiber.StatusAccepted).Send(nil)
			}
			if !isSupportedModernMethod(req.Method) {
				skipMetrics(c)
				return writeRPCErrorStatus(c, req.ID, fiber.StatusNotFound, codeMethodNotFound, "method not found", nil)
			}
		}
		c.SetUserContext(withMCPProtocol(c.UserContext(), era, resolvedProtocolVersion(req, protocolHeader)))
	}

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

	if parseErr != nil {
		skipMetrics(c)
		return writeBoundaryRPCError(c, nil, protocolEraLegacy, codeParseError, "parse error")
	}
	if era == protocolEraLegacy && (req.JSONRPC != "2.0" || req.Method == "") {
		skipMetrics(c)
		return writeBoundaryRPCError(c, req.ID, era, codeInvalidRequest, "invalid request")
	}

	if isNotification(req, era) {
		skipMetrics(c)
		return c.Status(fiber.StatusAccepted).Send(nil)
	}

	if era == protocolEraModern && req.Method == "server/discover" {
		normalized, err := normalizeModernResult(req.Method, serverDiscoveryResult(rc), rc)
		if err != nil {
			return writeRPCErrorStatus(c, req.ID, fiber.StatusInternalServerError, codeInternalError, "internal error", nil)
		}
		recordServerDiscovery(c)
		return writeRPCResult(c, req.ID, normalized)
	}

	switch req.Method {
	case "initialize":
		h.recordInitialize(c)
		return h.handleInitialize(c, req, rc)
	case "ping":
		skipMetrics(c)
		return writeRPCResult(c, req.ID, struct{}{})
	}

	result, err := h.gateway.Dispatch(c.UserContext(), rc, req.Method, req.Params)
	if err != nil {
		return writeAppError(c, req.ID, err, era, req.Method)
	}
	if era == protocolEraModern {
		normalized, err := normalizeModernResult(req.Method, result, rc)
		if err != nil {
			return writeRPCErrorStatus(c, req.ID, fiber.StatusInternalServerError, codeInternalError, "internal error", nil)
		}
		return writeRPCResult(c, req.ID, normalized)
	}
	if raw, ok := result.(json.RawMessage); ok {
		return writeRawRPCResult(c, req.ID, raw)
	}
	return writeRPCResult(c, req.ID, result)
}

func skipMetrics(c *fiber.Ctx) {
	c.Locals(string(infracontext.MCPSkipMetricsKey), true)
}

func (h *Handler) recordProtocolValidation(c *fiber.Ctx, code int, era protocolEra) {
	if h.protocol == nil {
		return
	}
	class, ok := validationClassForCode(code)
	if !ok {
		return
	}
	h.protocol.Record(c.UserContext(), class, eraLabel(era))
}

func ensureMCPAuthenticated(c *fiber.Ctx) error {
	if _, ok := appconsumer.AuthIDFromContext(c.UserContext()); !ok {
		return fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	if data, ok := appconsumer.DataFromContext(c.UserContext()); !ok || data == nil {
		return fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	return nil
}

func parseErrorEra(protocolHeader string) protocolEra {
	if protocolHeader != "" && !isLegacyProtocolVersion(protocolHeader) {
		return protocolEraModern
	}
	return protocolEraLegacy
}

func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func (h *Handler) recordInitialize(c *fiber.Ctx) {
	rt := trace.FromContext(c.UserContext())
	if rt == nil {
		return
	}
	span := rt.StartSpan(trace.SpanMCP, "initialize")
	span.SetMCPRequest("initialize", "initialize", "", "", "")
	stampMCPProtocol(span, c.UserContext())
	span.SetMCPStatus(fiber.StatusOK, 0)
	span.End()
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

func (h *Handler) handleInitialize(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	var params initializeParams
	_ = json.Unmarshal(req.Params, &params)
	version := latestLegacyProtocolVersion
	if isLegacyProtocolVersion(params.ProtocolVersion) {
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
			"version": serverVersion + "+" + surfaceFingerprint(rc),
		},
	})
}

func surfaceFingerprint(rc *appconsumer.RoutableConsumer) string {
	if rc == nil || rc.Consumer == nil {
		return "0"
	}
	parts := make([]string, 0, len(rc.Registries))
	for _, reg := range rc.Registries {
		if reg == nil || !reg.IsMCP() {
			continue
		}
		parts = append(parts, reg.ID.String()+"@"+reg.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	toolkit := rc.Consumer.Toolkit()
	entries := make([]string, 0, len(toolkit)+1)
	if toolkit == nil {
		entries = append(entries, "tk-state:nil")
	} else {
		entries = append(entries, "tk-state:configured")
	}
	for _, e := range toolkit {
		entries = append(entries, "tk:"+e.RegistryID.String()+"/"+e.Tool+"/"+e.Prompt+"/"+e.Resource+"/"+e.ExposeAs)
	}
	sort.Strings(parts)
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(append(parts, entries...), "|")))
	return hex.EncodeToString(sum[:6])
}

func writeAppError(c *fiber.Ctx, id json.RawMessage, err error, era protocolEra, method string) error {
	var (
		rpcErr        *appmcp.RPCError
		consentErr    *appmcp.ConsentRequiredError
		notPermitted  *appmcp.ToolNotPermittedError
		invalidParams *InvalidParamsError
	)
	if era == protocolEraModern && method == "resources/read" {
		if errors.As(err, &rpcErr) && int(rpcErr.Code) == codeResourceNotFound {
			applyRPCErrorHeaders(c, rpcErr, era)
			return writeRPCErrorStatus(c, id, fiber.StatusBadRequest, codeInvalidParams, rpcErr.Message, rpcErr.Data)
		}
		if errors.Is(err, appmcp.ErrResourceNotFound) {
			return writeRPCErrorStatus(c, id, fiber.StatusBadRequest, codeInvalidParams, err.Error(), nil)
		}
	}
	switch {
	case errors.As(err, &rpcErr):
		switch {
		case appmcp.IsPolicyBlockedCode(rpcErr.Code):
			middleware.SetOpsOutcome(c, o11y.OutcomeDeniedPolicy)
		case rpcErr.Code == appmcp.CodeRateLimited:
			middleware.SetOpsOutcome(c, o11y.OutcomeDeniedThrottled)
		default:
			middleware.SetOpsOutcome(c, o11y.OutcomeServerError)
		}
		applyRPCErrorHeaders(c, rpcErr, era)
		return writeJSONStatus(c, httpStatusForRPCError(rpcErr), rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error:   &rpcError{Code: int(rpcErr.Code), Message: rpcErr.Message, Data: rpcErr.Data},
		})
	case errors.As(err, &consentErr):
		middleware.SetOpsOutcome(c, o11y.OutcomeClientError)
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
	case errors.As(err, &notPermitted):
		middleware.SetOpsOutcome(c, o11y.OutcomeDeniedPolicy)
		return writeJSON(c, rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error:   &rpcError{Code: codePolicyBlocked, Message: notPermitted.Error()},
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
	case errors.Is(err, ratelimitapp.ErrUnavailable):
		middleware.SetOpsOutcome(c, o11y.OutcomeServerError)
		return writeJSONStatus(c, fiber.StatusServiceUnavailable, rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error:   &rpcError{Code: int(appmcp.CodeUnavailable), Message: err.Error()},
		})
	default:
		return writeRPCError(c, id, codeInternalError, err.Error())
	}
}

func isNotification(req rpcRequest, era protocolEra) bool {
	if len(req.ID) == 0 {
		return true
	}
	return era == protocolEraLegacy && bytes.Equal(bytes.TrimSpace(req.ID), []byte("null"))
}

func isSupportedModernMethod(method string) bool {
	switch method {
	case "server/discover",
		"tools/list",
		"tools/call",
		"resources/list",
		"resources/templates/list",
		"resources/read",
		"prompts/list",
		"prompts/get":
		return true
	default:
		return false
	}
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
	return writeRPCErrorStatus(c, id, fiber.StatusOK, code, message, nil)
}

func writeBoundaryRPCError(c *fiber.Ctx, id json.RawMessage, era protocolEra, code int, message string) error {
	status := fiber.StatusOK
	if era == protocolEraModern {
		status = fiber.StatusBadRequest
	}
	return writeRPCErrorStatus(c, id, status, code, message, nil)
}

func writeProtocolError(c *fiber.Ctx, id json.RawMessage, protocolErr *protocolError) error {
	if !validModernRequestID(id) {
		id = nil
	}
	var data json.RawMessage
	if protocolErr.data != nil {
		encoded, err := json.Marshal(protocolErr.data)
		if err != nil {
			return writeRPCErrorStatus(c, id, fiber.StatusInternalServerError, codeInternalError, "internal error", nil)
		}
		data = encoded
	}
	return writeRPCErrorStatus(
		c,
		id,
		protocolErr.status,
		protocolErr.code,
		protocolErr.message,
		data,
	)
}

func writeRPCErrorStatus(c *fiber.Ctx, id json.RawMessage, status, code int, message string, data json.RawMessage) error {
	outcome := o11y.OutcomeClientError
	if code == codeInternalError {
		outcome = o11y.OutcomeServerError
	}
	middleware.SetOpsOutcome(c, outcome)
	return writeJSONStatus(c, status, rpcResponse{
		JSONRPC: "2.0",
		ID:      normalizeID(id),
		Error:   &rpcError{Code: code, Message: message, Data: data},
	})
}

func writeJSON(c *fiber.Ctx, body any) error {
	return writeJSONStatus(c, fiber.StatusOK, body)
}

func writeJSONStatus(c *fiber.Ctx, status int, body any) error {
	return c.Status(status).JSON(body)
}

func httpStatusForRPCError(_ *appmcp.RPCError) int {
	return fiber.StatusOK
}

func applyRPCErrorHeaders(c *fiber.Ctx, err *appmcp.RPCError, era protocolEra) {
	if err == nil {
		return
	}
	for name, values := range err.HTTPHeaders {
		if era == protocolEraModern && strings.EqualFold(name, "Mcp-Session-Id") {
			continue
		}
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
	if !hasAuth(rc, authID) && authID != appauth.DefaultIdPAuthID() {
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
