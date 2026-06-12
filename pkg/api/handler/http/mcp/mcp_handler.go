// Package mcp exposes consumer-scoped virtual MCP servers over Streamable
// HTTP (JSON-RPC 2.0). One POST endpoint serves initialize, ping, tools/*,
// resources/*, and prompts/*; the surface is composed from the consumer's MCP
// registries and toolkit.
//
// Elicitation and sampling are not relayed: the gateway answers each POST
// with a single JSON-RPC response and does not advertise those capabilities
// upstream, so spec-compliant servers degrade gracefully.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

const (
	serverName    = "agentgateway"
	serverVersion = "1.0"
	// latestProtocolVersion is what the gateway answers when the client
	// requests a revision it does not know.
	latestProtocolVersion = "2025-06-18"
)

// supportedProtocolVersions are the MCP revisions the server plane speaks;
// initialize echoes the client's requested version when it is one of these.
var supportedProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// codeConsentRequired is an implementation-defined JSON-RPC error: the user
// must link a third-party account at data.connect_url before the call can
// succeed (forwarded downstream auth, Phase 4).
const codeConsentRequired = -32003

// codeResourceNotFound is the spec-defined error for resources/read on an
// unknown URI.
const codeResourceNotFound = -32002

type Handler struct {
	gateway *appmcp.RPCGateway
}

func NewHandler(gateway *appmcp.RPCGateway) *Handler {
	return &Handler{gateway: gateway}
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

// MethodNotAllowed answers the optional Streamable HTTP legs we do not
// support: GET (server-initiated SSE stream) and DELETE (client-initiated
// session termination). The spec mandates 405 here; anything else (401/404)
// sends clients like Cursor into an endless re-authentication loop.
func (h *Handler) MethodNotAllowed(c *fiber.Ctx) error {
	c.Set(fiber.HeaderAllow, fiber.MethodPost)
	return c.SendStatus(fiber.StatusMethodNotAllowed)
}

// Handle serves a single JSON-RPC message on the consumer's virtual MCP path.
func (h *Handler) Handle(c *fiber.Ctx) error {
	rc, err := resolveMCPConsumer(c)
	if err != nil {
		return err
	}

	var req rpcRequest
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return writeRPCError(c, nil, codeParseError, "parse error")
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return writeRPCError(c, req.ID, codeInvalidRequest, "invalid request")
	}

	if isNotification(req) {
		// notifications/initialized and friends: accept and ignore.
		return c.SendStatus(fiber.StatusAccepted)
	}

	// Protocol negotiation stays in the transport layer.
	switch req.Method {
	case "initialize":
		return h.handleInitialize(c, req)
	case "ping":
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

// writeAppError maps app-layer errors onto the JSON-RPC error surface.
func writeAppError(c *fiber.Ctx, id json.RawMessage, err error) error {
	var (
		rpcErr        *appmcp.RPCError
		consentErr    *appmcp.ConsentRequiredError
		invalidParams *appmcp.InvalidParamsError
	)
	switch {
	case errors.As(err, &rpcErr):
		// Pass upstream JSON-RPC errors through unchanged.
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
	case errors.Is(err, appmcp.ErrMethodNotFound):
		return writeRPCError(c, id, codeMethodNotFound, err.Error())
	case errors.Is(err, sts.ErrInteractionRequired):
		// IdP claims challenge: surface as 401 so the OAuth challenge
		// middleware adds WWW-Authenticate (never swallowed as a 500).
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
	// JSON-RPC errors ride on HTTP 200; transport-level failures use HTTP codes.
	return c.Status(fiber.StatusOK).JSON(body)
}

func normalizeID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
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
