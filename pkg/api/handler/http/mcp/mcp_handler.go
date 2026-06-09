// Package mcp exposes consumer-scoped virtual MCP servers over Streamable
// HTTP (JSON-RPC 2.0). One POST endpoint serves initialize, ping, tools/list,
// and tools/call; the tool surface is composed from the consumer's MCP
// registries and toolkit.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
	"github.com/gofiber/fiber/v2"
)

const (
	serverName      = "agentgateway"
	serverVersion   = "1.0"
	protocolVersion = mcpclient.ProtocolVersion
)

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

type Handler struct {
	composer appmcp.Composer
}

func NewHandler(composer appmcp.Composer) *Handler {
	return &Handler{composer: composer}
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

	switch req.Method {
	case "initialize":
		return h.handleInitialize(c, req)
	case "ping":
		return writeRPCResult(c, req.ID, struct{}{})
	case "tools/list":
		return h.handleToolsList(c, req, rc)
	case "tools/call":
		return h.handleToolsCall(c, req, rc)
	// Resources and prompts are not federated in v1; answer with empty
	// collections so spec-compliant clients degrade gracefully.
	case "resources/list":
		return writeRPCResult(c, req.ID, fiber.Map{"resources": []any{}})
	case "resources/templates/list":
		return writeRPCResult(c, req.ID, fiber.Map{"resourceTemplates": []any{}})
	case "prompts/list":
		return writeRPCResult(c, req.ID, fiber.Map{"prompts": []any{}})
	default:
		return writeRPCError(c, req.ID, codeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
	}
}

func (h *Handler) handleInitialize(c *fiber.Ctx, req rpcRequest) error {
	return writeRPCResult(c, req.ID, fiber.Map{
		"protocolVersion": protocolVersion,
		"capabilities": fiber.Map{
			"tools": fiber.Map{"listChanged": false},
		},
		"serverInfo": fiber.Map{
			"name":    serverName,
			"version": serverVersion,
		},
	})
}

func (h *Handler) handleToolsList(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	tools, err := h.composer.ListTools(c.UserContext(), rc)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	if tools == nil {
		tools = []mcpclient.Tool{}
	}
	return writeRPCResult(c, req.ID, fiber.Map{"tools": tools})
}

type callToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (h *Handler) handleToolsCall(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	var params callToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
		return writeRPCError(c, req.ID, codeInvalidParams, "tools/call requires params.name")
	}
	result, err := h.composer.CallTool(c.UserContext(), rc, params.Name, params.Arguments)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	return writeRawRPCResult(c, req.ID, result)
}

func writeComposerError(c *fiber.Ctx, id json.RawMessage, err error) error {
	var rpcErr *mcpclient.RPCError
	switch {
	case errors.As(err, &rpcErr):
		// Pass upstream JSON-RPC errors through unchanged.
		return writeJSON(c, rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error:   &rpcError{Code: rpcErr.Code, Message: rpcErr.Message, Data: rpcErr.Data},
		})
	case errors.Is(err, appmcp.ErrToolNotFound):
		return writeRPCError(c, id, codeInvalidParams, err.Error())
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
