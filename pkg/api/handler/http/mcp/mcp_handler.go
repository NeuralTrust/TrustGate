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

	switch req.Method {
	case "initialize":
		return h.handleInitialize(c, req)
	case "ping":
		return writeRPCResult(c, req.ID, struct{}{})
	case "tools/list":
		return h.handleToolsList(c, req, rc)
	case "tools/call":
		return h.handleToolsCall(c, req, rc)
	case "resources/list":
		return h.handleResourcesList(c, req, rc)
	case "resources/templates/list":
		return h.handleResourceTemplatesList(c, req, rc)
	case "resources/read":
		return h.handleResourcesRead(c, req, rc)
	case "prompts/list":
		return h.handlePromptsList(c, req, rc)
	case "prompts/get":
		return h.handlePromptsGet(c, req, rc)
	default:
		return writeRPCError(c, req.ID, codeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
	}
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

func (h *Handler) handleToolsList(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	tools, err := h.composer.ListTools(c.UserContext(), rc)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	if tools == nil {
		tools = []appmcp.Tool{}
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

func (h *Handler) handleResourcesList(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	resources, err := h.composer.ListResources(c.UserContext(), rc)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	if resources == nil {
		resources = []appmcp.Resource{}
	}
	return writeRPCResult(c, req.ID, fiber.Map{"resources": resources})
}

func (h *Handler) handleResourceTemplatesList(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	templates, err := h.composer.ListResourceTemplates(c.UserContext(), rc)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	if templates == nil {
		templates = []appmcp.ResourceTemplate{}
	}
	return writeRPCResult(c, req.ID, fiber.Map{"resourceTemplates": templates})
}

type readResourceParams struct {
	URI string `json:"uri"`
}

func (h *Handler) handleResourcesRead(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	var params readResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.URI == "" {
		return writeRPCError(c, req.ID, codeInvalidParams, "resources/read requires params.uri")
	}
	result, err := h.composer.ReadResource(c.UserContext(), rc, params.URI)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	return writeRawRPCResult(c, req.ID, result)
}

func (h *Handler) handlePromptsList(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	prompts, err := h.composer.ListPrompts(c.UserContext(), rc)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	if prompts == nil {
		prompts = []appmcp.Prompt{}
	}
	return writeRPCResult(c, req.ID, fiber.Map{"prompts": prompts})
}

type getPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

func (h *Handler) handlePromptsGet(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	var params getPromptParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
		return writeRPCError(c, req.ID, codeInvalidParams, "prompts/get requires params.name")
	}
	result, err := h.composer.GetPrompt(c.UserContext(), rc, params.Name, params.Arguments)
	if err != nil {
		return writeComposerError(c, req.ID, err)
	}
	return writeRawRPCResult(c, req.ID, result)
}

// codeConsentRequired is an implementation-defined JSON-RPC error: the user
// must link a third-party account at data.connect_url before the call can
// succeed (forwarded downstream auth, Phase 4).
const codeConsentRequired = -32003

// codeResourceNotFound is the spec-defined error for resources/read on an
// unknown URI.
const codeResourceNotFound = -32002

func writeComposerError(c *fiber.Ctx, id json.RawMessage, err error) error {
	var (
		rpcErr     *appmcp.RPCError
		consentErr *appmcp.ConsentRequiredError
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
