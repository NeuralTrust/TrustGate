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
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

const (
	serverName              = "trustgate"
	serverVersion           = "1.0"
	latestProtocolVersion   = "2025-06-18"
	discoverCacheTTLMs      = 0
	modernServerInfoMetaKey = "io.modelcontextprotocol/serverInfo"
)

var advertisedProtocolVersions = []string{
	latestProtocolVersion,
	"2025-03-26",
	"2024-11-05",
}

var supportedProtocolVersions = negotiableVersions(advertisedProtocolVersions)

func negotiableVersions(advertised []string) map[string]bool {
	versions := make(map[string]bool, len(advertised))
	for _, version := range advertised {
		versions[version] = true
	}
	return versions
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
	resolveClientIP func(string, string) string
	gateway         *RPCGateway
	surface         appmcp.SurfaceWatcher
	consumers       appconsumer.DataFinder
	timings         streamTimings
	memory          *surfaceMemory
}

type HandlerOption func(*Handler)

func WithClientIPResolver(resolve func(string, string) string) HandlerOption {
	return func(h *Handler) {
		if resolve != nil {
			h.resolveClientIP = resolve
		}
	}
}

// WithConsumerFinder lets the notification stream re-read the consumer on
// each poll so an admin attach or detach is visible. Without it the stream
// keeps the RoutableConsumer resolved when the GET opened.
func WithConsumerFinder(finder appconsumer.DataFinder) HandlerOption {
	return func(h *Handler) {
		if finder != nil {
			h.consumers = finder
		}
	}
}

func NewHandler(gateway *RPCGateway, surface appmcp.SurfaceWatcher, opts ...HandlerOption) *Handler {
	h := &Handler{
		resolveClientIP: requestmeta.NewIPResolver("peer", nil),
		gateway:         gateway,
		surface:         surface,
		timings:         defaultStreamTimings,
		memory:          newSurfaceMemory(),
	}
	for _, opt := range opts {
		opt(h)
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
	c.SetUserContext(requestmeta.NewContext(c.UserContext(), h.resolveClientIP(c.Context().RemoteAddr().String(), c.Get(fiber.HeaderXForwardedFor)), c.GetReqHeaders()))
	rc, err := resolveMCPConsumer(c)
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
			stampRequestIdentity(c, rt, rc, h.surface)
		}
	}

	switch req.Method {
	case "initialize":
		h.recordInitialize(c)
		return h.handleInitialize(c, req, rc)
	case "server/discover":
		recordServerDiscovery(c)
		return writeRPCResult(c, req.ID, serverDiscoveryResult(rc, h.surfaceVersion(c, rc)))
	case "ping":
		skipMetrics(c)
		return writeRPCResult(c, req.ID, struct{}{})
	}

	result, err := h.gateway.DispatchWithBaseURL(c.UserContext(), rc, c.BaseURL(), req.Method, req.Params)
	if err != nil {
		return writeAppError(c, req.ID, err)
	}
	// An install or a connect made since this caller's last request leaves their
	// client serving the tool list it cached at handshake. tools/list_changed is
	// what fixes that, and the GET stream is not always there to carry it, so a
	// response the client is already waiting for carries it instead. tools/list
	// is the one method to leave alone: it is the answer to the notification,
	// and announcing a change on it asks for another list of what was just sent.
	listChanged := req.Method != "tools/list" && h.surfaceMoved(c, rc)
	if raw, ok := result.(json.RawMessage); ok {
		return writeRPCBody(c, rawRPCResponse(req.ID, raw), listChanged)
	}
	return writeRPCBody(c, rpcResponse{JSONRPC: "2.0", ID: normalizeID(req.ID), Result: result}, listChanged)
}

func skipMetrics(c *fiber.Ctx) {
	c.Locals(string(infracontext.MCPSkipMetricsKey), true)
}

func stampRequestIdentity(c *fiber.Ctx, rt *trace.RequestTrace, rc *appconsumer.RoutableConsumer, surface appmcp.SurfaceWatcher) {
	if rt == nil {
		return
	}
	p := identity.PrincipalFromContext(c.UserContext())
	if p == nil {
		return
	}
	email := p.Email()
	subject := p.Subject
	if credential, ok := p.Claims[identity.ClaimCredentialSubject].(string); ok && credential != "" {
		subject = credential
	}
	if email == "" && surface != nil && rc != nil && rc.Consumer != nil {
		email = surface.ConnectedEmail(c.UserContext(), rc.Consumer.GatewayID, p.Subject)
	}
	rt.SetPrincipalIdentity(subject, string(p.Method), email)
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
		"capabilities": fiber.Map{
			"tools":     fiber.Map{"listChanged": true},
			"resources": fiber.Map{"subscribe": false, "listChanged": false},
			"prompts":   fiber.Map{"listChanged": false},
		},
		"serverInfo": fiber.Map{
			"name":    serverName,
			"version": serverVersion + "+" + h.surfaceVersion(c, rc),
		},
		"instructions": serverInstructions(rc),
	})
}

const baseServerInstructions = "This server is the NeuralTrust TrustGate gateway — the organization's single governed entry point for MCP tools, which it proxies with policy, auditing and per-user credentials handled centrally. Use the tools this gateway exposes to do the work. Never advise the user to add an MCP server directly in their client (for example their IDE's MCP settings) or to connect to an upstream MCP URL out of band: that bypasses the gateway and its governance. If a capability is not currently available, obtain it through this gateway rather than around it."

const storeServerInstructions = " This gateway includes an MCP Store. When the user needs a tool from a server that is not installed yet, search the catalog with trustgate_store_search and install it yourself with trustgate_store_install — do not ask the user to install it manually or to add it in their client. If an install returns a configure or connect link, present that link to the user to authorize; do not offer any path that skips the gateway."

func serverInstructions(rc *appconsumer.RoutableConsumer) string {
	if rc != nil && consumerdomain.IsStoreConsumer(rc.Consumer) {
		return baseServerInstructions + storeServerInstructions
	}
	return baseServerInstructions
}

func writeAppError(c *fiber.Ctx, id json.RawMessage, err error) error {
	var (
		rpcErr        *appmcp.RPCError
		consentErr    *appmcp.ConsentRequiredError
		notPermitted  *appmcp.ToolNotPermittedError
		appNotLinked  *appmcp.ApplicationNotConnectedError
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
			"cause":       consentErr.Cause,
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
	case errors.As(err, &appNotLinked):
		middleware.SetOpsOutcome(c, o11y.OutcomeDeniedPolicy)
		return writeJSON(c, rpcResponse{
			JSONRPC: "2.0",
			ID:      normalizeID(id),
			Error:   &rpcError{Code: codeConsentRequired, Message: appNotLinked.Error()},
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
	case errors.Is(err, appmcp.ErrNoPrincipal), errors.Is(err, appmcp.ErrUpstreamNeedsCallerToken),
		errors.Is(err, appmcp.ErrAudienceMismatch),
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
	case errors.Is(err, appmcp.ErrUnreachable), errors.Is(err, appmcp.ErrUpstreamUnavailable):
		slog.Default().Warn("mcp handler: upstream MCP server unreachable",
			"method", c.Method(), "path", c.Path(), "error", err)
		return writeRPCError(c, id, codeInternalError, "upstream MCP server unreachable")
	case errors.Is(err, registrydomain.ErrURLTemplate):
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
	return writeJSON(c, rawRPCResponse(id, result))
}

// rawRPCResponse wraps an already-encoded result, which rpcResponse cannot: its
// Result is `any` with omitempty, and a json.RawMessage there would be re-encoded.
func rawRPCResponse(id json.RawMessage, result json.RawMessage) any {
	return struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{JSONRPC: "2.0", ID: normalizeID(id), Result: result}
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

func resolveMCPConsumer(c *fiber.Ctx) (*appconsumer.RoutableConsumer, error) {
	authID, ok := appconsumer.AuthIDFromContext(c.UserContext())
	if !ok {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	data, ok := appconsumer.DataFromContext(c.UserContext())
	if !ok || data == nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
	}
	if consumerdomain.IsStoreSlug(appconsumer.SlugFromMCPPath(c.Path())) {
		if data.StoreConsumer != nil {
			return data.StoreConsumer, nil
		}
		gatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext())
		if !ok {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "not authenticated")
		}
		return &appconsumer.RoutableConsumer{
			Consumer: consumerdomain.BuildStoreConsumer(gatewayID),
		}, nil
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
	if !consumerAdmitsPrincipal(rc.Consumer, identity.PrincipalFromContext(c.UserContext())) {
		return nil, fiber.NewError(fiber.StatusForbidden, "caller not allowed for this consumer")
	}
	switch {
	case rc.Consumer.Identity.AppUsers():
		if !machineCredential(identity.PrincipalFromContext(c.UserContext())) {
			return nil, fiber.NewError(fiber.StatusForbidden,
				"this application identifies its own users; call it with its API key or client certificate, not a user login")
		}
		endUser := c.Get(consumerdomain.EndUserHeader)
		if err := consumerdomain.ValidateEndUser(endUser); err != nil {
			return nil, fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		ctx := identity.WithPrincipal(c.UserContext(), endUserPrincipal(rc.Consumer, identity.PrincipalFromContext(c.UserContext()), endUser))
		c.SetUserContext(ctx)
		if rt := trace.FromContext(ctx); rt != nil {
			rt.SetEndUser(strings.TrimSpace(endUser))
		}
	case !rc.Consumer.ActsForUsers() && machineCredential(identity.PrincipalFromContext(c.UserContext())):
		ctx := identity.WithPrincipal(c.UserContext(), appPrincipal(rc.Consumer, identity.PrincipalFromContext(c.UserContext())))
		c.SetUserContext(ctx)
	}
	return rc, nil
}

func machineCredential(p *identity.Principal) bool {
	return p != nil && (p.Method == identity.MethodAPIKey || p.Method == identity.MethodMTLS)
}

func endUserPrincipal(cons *consumerdomain.Consumer, app *identity.Principal, endUser string) *identity.Principal {
	endUser = strings.TrimSpace(endUser)
	p := &identity.Principal{
		Subject: consumerdomain.EndUserSubject(cons.ID, endUser),
		Method:  identity.MethodAPIKey,
		Claims: map[string]any{
			"end_user":    endUser,
			"consumer_id": cons.ID.String(),
		},
	}
	if app != nil {
		if app.Method != "" {
			p.Method = app.Method
		}
		if app.Subject != "" {
			p.Claims["app_subject"] = app.Subject
		}
	}
	return p
}

// appPrincipal is the principal a request runs as on a consumer that acts as
// the application itself and was entered with a credential the application
// holds: the consumer-namespaced subject its upstream accounts hang off. The
// credential's own subject stays in the claims, so an audit trail still names
// the api key or the certificate that was used.
//
// The swap happens here, after the auth binding has been applied to the real
// caller, because only the request path knows which consumer is being entered:
// an api key is a many-to-many row, so the credential alone cannot say whose
// application this is.
//
// It is deliberately limited to an api key or a client certificate — a shared
// credential, where callers already share whatever it opens. A bearer token
// keeps its own subject: on a consumer that admits tokens from an external IdP
// the token may well be one person's, and collapsing those onto one subject
// would hand every holder the account the first of them linked. A
// client-credentials token needs nothing from this either, since its subject is
// the application's client id already.
func appPrincipal(cons *consumerdomain.Consumer, caller *identity.Principal) *identity.Principal {
	p := &identity.Principal{Subject: consumerdomain.AppSubject(cons.ID), Method: identity.MethodAPIKey}
	if caller != nil {
		// Everything but the subject is carried over: an upstream that forwards
		// or exchanges the caller's own token still needs it, and the claims are
		// what an audit trail reads.
		copied := *caller
		p = &copied
		p.Subject = consumerdomain.AppSubject(cons.ID)
	}
	claims := make(map[string]any, len(p.Claims)+2)
	for k, v := range p.Claims {
		claims[k] = v
	}
	claims["consumer_id"] = cons.ID.String()
	if caller != nil && caller.Subject != "" {
		claims[identity.ClaimCredentialSubject] = caller.Subject
	}
	p.Claims = claims
	return p
}

// consumerAdmitsPrincipal applies the consumer's auth binding to the verified
// caller: a bearer token from a shared IdP must have been issued to an allowed
// client, and a client certificate must carry an allowed subject. API keys are
// bound to one consumer already, and a missing principal has nothing to bind.
func consumerAdmitsPrincipal(cons *consumerdomain.Consumer, principal *identity.Principal) bool {
	if cons == nil {
		return false
	}
	if principal == nil {
		return true
	}
	switch {
	case principal.Method.IsBearerToken():
		return cons.AuthBinding.AllowsClient(principal.Claims)
	case principal.Method == identity.MethodMTLS:
		return cons.AuthBinding.AllowsCertificateClaims(principal.Claims)
	default:
		return true
	}
}

func hasAuth(rc *appconsumer.RoutableConsumer, authID ids.AuthID) bool {
	for _, id := range rc.Consumer.AuthIDs {
		if id == authID {
			return true
		}
	}
	return false
}
