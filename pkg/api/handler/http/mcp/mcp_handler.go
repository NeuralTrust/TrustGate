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
	"context"
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
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const (
	serverName              = "trustgate"
	serverVersion           = "1.0"
	latestProtocolVersion   = "2025-06-18"
	modernProtocolVersion   = "2026-07-28"
	discoverCacheTTLMs      = 0
	modernServerInfoMetaKey = "io.modelcontextprotocol/serverInfo"
)

var supportedProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// advertisedProtocolVersions is the ordered list returned by server/discover.
// Modern Claude clients probe with 2026-07-28 first; the gateway is already
// stateless per request, so that revision is safe to advertise alongside the
// legacy initialize handshake versions.
var advertisedProtocolVersions = []string{
	modernProtocolVersion,
	latestProtocolVersion,
	"2025-03-26",
	"2024-11-05",
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
	// codePolicyBlocked mirrors the app-layer policy-denial code, so a toolkit
	// denial is classified alongside plugin blocks.
	codePolicyBlocked = -32001
)

type Handler struct {
	gateway    *RPCGateway
	roleScoper appmcp.RoleScoper
	vault      vaultdomain.Repository
	timings    streamTimings
}

func NewHandler(gateway *RPCGateway, roleScoper appmcp.RoleScoper, vault vaultdomain.Repository) *Handler {
	return &Handler{
		gateway:    gateway,
		roleScoper: roleScoper,
		vault:      vault,
		timings:    defaultStreamTimings,
	}
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
		stampRequestIdentity(c, rt, rc, nil)
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

	if req.Method != "ping" {
		if rt := trace.FromContext(c.UserContext()); rt != nil {
			stampRequestIdentity(c, rt, rc, h.vault)
		}
	}

	switch req.Method {
	case "initialize":
		h.recordInitialize(c)
		return h.handleInitialize(c, req, rc)
	case "server/discover":
		recordServerDiscovery(c)
		return writeRPCResult(c, req.ID, serverDiscoveryResult(rc, h.connectedProviders(c, rc)))
	case "ping":
		skipMetrics(c)
		return writeRPCResult(c, req.ID, struct{}{})
	}

	result, err := h.gateway.DispatchWithBaseURL(c.UserContext(), rc, c.BaseURL(), req.Method, req.Params)
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

func stampRequestIdentity(c *fiber.Ctx, rt *trace.RequestTrace, rc *appconsumer.RoutableConsumer, vault vaultdomain.Repository) {
	if rt == nil {
		return
	}
	p := identity.PrincipalFromContext(c.UserContext())
	if p == nil {
		return
	}
	email := p.Email()
	if email == "" && vault != nil && rc != nil && rc.Consumer != nil {
		email = appmcp.ConnectedAccountEmail(c.UserContext(), vault, rc.Consumer.GatewayID, p.Subject)
	}
	rt.SetPrincipalIdentity(p.Subject, string(p.Method), email)
}

func (h *Handler) recordInitialize(c *fiber.Ctx) {
	rt := trace.FromContext(c.UserContext())
	if rt == nil {
		return
	}
	span := rt.StartSpan(trace.SpanMCP, "initialize")
	span.SetMCPRequest("initialize", "initialize", "", "", "")
	span.SetMCPStatus(fiber.StatusOK, 0)
	span.End()
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

func (h *Handler) handleInitialize(c *fiber.Ctx, req rpcRequest, rc *appconsumer.RoutableConsumer) error {
	var params initializeParams
	_ = json.Unmarshal(req.Params, &params)
	version := latestProtocolVersion
	if supportedProtocolVersions[params.ProtocolVersion] {
		version = params.ProtocolVersion
	}
	return writeRPCResult(c, req.ID, fiber.Map{
		"protocolVersion": version,
		// tools.listChanged has to be advertised for clients to act on the
		// notification at all — Claude drops notifications/tools/list_changed
		// from a server that did not declare the capability. The gateway backs
		// it with the SSE stream served on GET.
		"capabilities": fiber.Map{
			"tools":     fiber.Map{"listChanged": true},
			"resources": fiber.Map{"subscribe": false, "listChanged": false},
			"prompts":   fiber.Map{"listChanged": false},
		},
		"serverInfo": fiber.Map{
			"name":    serverName,
			"version": serverVersion + "+" + surfaceFingerprint(rc, h.connectedProviders(c, rc)),
		},
	})
}

// connectedProviders describes, for the calling principal, which of this
// consumer's forwarded-auth providers currently hold a credential and when it
// last changed. Federation skips upstreams pending consent, so connecting an
// account on the connect page changes the tool surface without touching any
// registry or toolkit — the configuration-only fingerprint stayed identical and
// a version-keyed client kept serving its stale tool list. Providers this
// consumer does not federate are left out so an unrelated connection elsewhere
// on the gateway does not invalidate this surface.
func (h *Handler) connectedProviders(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) []string {
	ctx := c.UserContext()
	return h.connectionSnapshot(ctx, rc, identity.PrincipalFromContext(ctx))
}

// connectionSnapshot takes its context and principal as arguments because the
// notification stream keeps polling it long after the request context that
// opened the stream is gone.
func (h *Handler) connectionSnapshot(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	principal *identity.Principal,
) []string {
	if h.vault == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	if principal == nil || strings.TrimSpace(principal.Subject) == "" {
		return nil
	}
	federated := forwardedProviders(rc)
	if len(federated) == 0 {
		return nil
	}
	creds, err := h.vault.ListByPrincipal(ctx, rc.Consumer.GatewayID, principal.Subject)
	if err != nil {
		return nil
	}
	parts := make([]string, 0, len(creds))
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		if _, ok := federated[cred.Provider]; !ok {
			continue
		}
		parts = append(parts, "cx:"+cred.Provider+"@"+cred.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	return parts
}

func forwardedProviders(rc *appconsumer.RoutableConsumer) map[string]struct{} {
	providers := make(map[string]struct{})
	for _, reg := range rc.Registries {
		if reg == nil || !reg.IsMCP() || reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
			continue
		}
		if reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
			continue
		}
		providers[reg.MCPTarget.Auth.Provider] = struct{}{}
	}
	return providers
}

// surfaceFingerprint summarises everything that decides which tools a virtual
// MCP exposes: the bound MCP registries, when each was last changed, the
// toolkit that filters them, and the caller's connected accounts. It rides in
// serverInfo.version as semver build metadata, so a client that caches a
// server's tool list keyed on its reported version re-lists after the consumer
// is reconfigured or the user connects an account. Without it every virtual MCP
// reports a constant "1.0" forever and a newly attached registry stays
// invisible until the client is reinstalled.
func surfaceFingerprint(rc *appconsumer.RoutableConsumer, connections []string) string {
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
	entries := make([]string, 0, len(rc.Consumer.Toolkit()))
	for _, e := range rc.Consumer.Toolkit() {
		entries = append(entries, "tk:"+e.RegistryID.String()+"/"+e.Tool+"/"+e.Prompt+"/"+e.Resource+"/"+e.ExposeAs)
	}
	// None of these lists has a guaranteed order across replicas or reloads —
	// the role-derived toolkit is a union, the vault answers in its own order —
	// so sort them all: the same configuration must always fingerprint the same.
	sort.Strings(parts)
	sort.Strings(entries)
	linked := append([]string(nil), connections...)
	sort.Strings(linked)
	material := append(append(parts, entries...), linked...)
	sum := sha256.Sum256([]byte(strings.Join(material, "|")))
	return hex.EncodeToString(sum[:6])
}

func writeAppError(c *fiber.Ctx, id json.RawMessage, err error) error {
	var (
		rpcErr        *appmcp.RPCError
		consentErr    *appmcp.ConsentRequiredError
		notPermitted  *appmcp.ToolNotPermittedError
		invalidParams *InvalidParamsError
	)
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
		applyRPCErrorHeaders(c, rpcErr)
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
		// HTTP 200 carrying a JSON-RPC error, not a 4xx. MCP streamable-HTTP
		// clients treat any non-2xx on this endpoint as a transport failure: they
		// drop the connection and restart authentication instead of reading the
		// body, so the connect URL never reaches the user. The refusal is
		// reported to the agent through the JSON-RPC error, and the semantic
		// status (403) is recorded on the span for metrics and traces.
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
		// A denial the agent should read and act on, so it rides on HTTP 200 for
		// the same transport reason as the consent case above; the span records
		// it as forbidden. Written inline rather than through writeRPCError,
		// which would reclassify the outcome as a generic client error.
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
	outcome := o11y.OutcomeClientError
	if code == codeInternalError {
		outcome = o11y.OutcomeServerError
	}
	middleware.SetOpsOutcome(c, outcome)
	return writeJSON(c, rpcResponse{
		JSONRPC: "2.0",
		ID:      normalizeID(id),
		Error:   &rpcError{Code: code, Message: message},
	})
}

func writeJSON(c *fiber.Ctx, body any) error {
	return writeJSONStatus(c, fiber.StatusOK, body)
}

func writeJSONStatus(c *fiber.Ctx, status int, body any) error {
	return c.Status(status).JSON(body)
}

// httpStatusForRPCError maps gateway denials onto the wire HTTP status so
// agents and telemetry see the real outcome. Upstream JSON-RPC errors stay on 200.
// httpStatusForRPCError is always 200: on the MCP wire a JSON-RPC error is a
// successful exchange carrying a failed call. Clients treat a 4xx/5xx here as a
// transport failure — they drop the connection and restart authentication
// without reading the body — so a policy denial answered with 403 killed the
// session instead of telling the agent it was blocked. The status the refusal
// means (403, 429, 503) is recorded on the span, and rate-limit headers still
// ride along on the response.
func httpStatusForRPCError(_ *appmcp.RPCError) int {
	return fiber.StatusOK
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
	// The built-in NeuralTrust default identity provider is not attached to the
	// consumer's AuthIDs (the consumer has no identity provider of its own). The
	// auth chain only resolves a default-IdP session on a path that has no
	// oauth2 provider, so accepting it here is consistent with that scoping.
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
