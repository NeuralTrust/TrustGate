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

package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"net/textproto"
	"net/url"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
)

var newline = []byte("\n")

var streamErrorEvent = []byte(`data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}`)

var errNotAuthenticated = errors.New("request is not authenticated")
var errPathNotFound = errors.New("no consumer matches the request path")
var errForbidden = errors.New("credential is not authorized for the matched consumer")

const (
	errCodePluginRejected     = "plugin_rejected"
	errCodeUnauthenticated    = "unauthenticated"
	errCodeForbidden          = "forbidden"
	errCodeNotFound           = "not_found"
	errCodeNoBackendAvailable = "no_backend_available"
	errCodeInvalidRequest     = "invalid_request"
	errCodeInvalidModel       = "invalid_model"
	errCodeModelNotAllowed    = "model_not_allowed"
	errCodeProviderCredential = "provider_credential_error"
	errCodeBackendError       = "backend_error"
)

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Content-Length":      {},
}

type ForwardedHandler struct {
	forwarder appproxy.Forwarder
}

func NewForwardedHandler(forwarder appproxy.Forwarder) *ForwardedHandler {
	return &ForwardedHandler{forwarder: forwarder}
}

// Handle godoc
// @Summary      Proxy chat completion
// @Description  Forwards an OpenAI Chat Completions request to the selected provider. Proxy plane route: /{consumer_slug}/v1/chat/completions. Other fixed routes include /v1/messages (Anthropic) and /v1/responses (OpenAI Responses).
// @Tags         proxy
// @Accept       json
// @Produce      json
// @Param        consumer_slug      path   string  true   "Consumer slug"
// @Param        X-AG-API-Key       header string  false  "API key for inline consumers"
// @Param        Authorization      header string  false  "Bearer token for OAuth2 or OIDC consumers"
// @Param        X-AG-Gateway-Slug  header string  false  "Gateway slug when using header-based gateway discovery"
// @Param        body               body   object  true   "OpenAI Chat Completions request body"
// @Success      200                {object}  map[string]interface{}
// @Failure      400                {object}  httpio.ErrorBody
// @Failure      401                {object}  httpio.ErrorBody
// @Failure      403                {object}  httpio.ErrorBody
// @Failure      404                {object}  httpio.ErrorBody
// @Failure      502                {object}  httpio.ErrorBody
// @Router       /{consumer_slug}/v1/chat/completions [post]
func (h *ForwardedHandler) Handle(c *fiber.Ctx) error {
	route, err := proxyRoute(c)
	if err != nil {
		return writeProxyError(c, err)
	}
	gatewayID, consumer, authCtx, err := resolveConsumer(c, route)
	if err != nil {
		return writeProxyError(c, err)
	}

	stampConsumerTrace(c, consumer)

	data, _ := appconsumer.DataFromContext(c.UserContext())
	reqCtx := buildRequestContext(c, gatewayID, route)
	result, err := h.forwarder.Forward(c.UserContext(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  consumer,
		Data:      data,
		RoleIDs:   authCtx.RoleIDs,
		Request:   reqCtx,
	})
	if err != nil {
		return writeProxyError(c, err)
	}

	relayHeaders(c, result.Headers)

	if result.Stream != nil {
		return writeStream(c, result, reqCtx)
	}
	return c.Status(result.StatusCode).Send(result.Body)
}

func relayHeaders(c *fiber.Ctx, headers map[string][]string) {
	for name, values := range headers {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		if _, skip := hopByHopHeaders[canonical]; skip {
			continue
		}
		if _, skip := middleware.StrippedProxyResponseHeaders[canonical]; skip {
			continue
		}
		for _, v := range values {
			c.Response().Header.Add(name, v)
		}
	}
}

func writeStream(c *fiber.Ctx, result *appproxy.ForwardResult, req *infracontext.RequestContext) error {
	finalizer, _ := c.Locals(infracontext.StreamMetricsFinalizerKey).(infracontext.StreamMetricsFinalizer)
	statusCode := result.StatusCode
	headers := result.Headers

	// Claim metrics ownership synchronously so the middleware skips its own
	// deferred emission (the finalizer runs later, during body serialization).
	if finalizer != nil {
		c.Locals(infracontext.StreamMetricsOwnedKey, true)
	}

	c.Status(statusCode)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		var captured bytes.Buffer
		if finalizer != nil {
			defer func() {
				req.Body = append([]byte(nil), req.Body...)
				finalizer(req, captured.Bytes(), statusCode, headers)
			}()
		}
		for line, err := range result.Stream {
			if err != nil {
				// The response is already a 200 SSE stream, so a mid-stream
				// failure cannot change the status code. Emit an explicit error
				// event (instead of a silent truncation that looks like a clean
				// finish) so clients can distinguish an aborted stream.
				if finalizer != nil {
					captured.Write(streamErrorEvent)
					captured.Write(newline)
				}
				_, _ = w.Write(streamErrorEvent)
				_, _ = w.Write(newline)
				_, _ = w.Write(newline)
				_ = w.Flush()
				return
			}
			if finalizer != nil {
				captured.Write(line)
				captured.Write(newline)
			}
			if _, werr := w.Write(line); werr != nil {
				return
			}
			if _, werr := w.Write(newline); werr != nil {
				return
			}
			if flushErr := w.Flush(); flushErr != nil {
				return
			}
		}
	})
	return nil
}

func proxyRoute(c *fiber.Ctx) (apiresolver.ProxyRoute, error) {
	if route, ok := c.Locals(apiresolver.ProxyRouteLocalsKey).(apiresolver.ProxyRoute); ok {
		return route, nil
	}
	route, err := apiresolver.ResolveProxyPath(c.Path())
	if err != nil {
		return apiresolver.ProxyRoute{}, errPathNotFound
	}
	return route, nil
}

func resolveConsumer(
	c *fiber.Ctx,
	route apiresolver.ProxyRoute,
) (ids.GatewayID, *appconsumer.RoutableConsumer, *appauth.AuthContext, error) {
	gatewayID, ok := appconsumer.GatewayIDFromContext(c.UserContext())
	if !ok {
		return ids.GatewayID{}, nil, nil, errNotAuthenticated
	}
	authCtx, ok := appauth.AuthContextFromContext(c.UserContext())
	if !ok {
		return ids.GatewayID{}, nil, nil, errNotAuthenticated
	}
	data, ok := appconsumer.DataFromContext(c.UserContext())
	if !ok || data == nil {
		return ids.GatewayID{}, nil, nil, errNotAuthenticated
	}
	rc, ok := appconsumer.ConsumerFromContext(c.UserContext())
	if !ok {
		rc, ok = data.MatchSlug(route.ConsumerSlug)
		if !ok {
			return ids.GatewayID{}, nil, nil, errPathNotFound
		}
	}
	if rc.Consumer == nil || (rc.Consumer.Type != domainconsumer.TypeLLM && rc.Consumer.Type != "") {
		return ids.GatewayID{}, nil, nil, errPathNotFound
	}
	if !isAuthorizedForConsumer(rc, authCtx) {
		return ids.GatewayID{}, nil, nil, errForbidden
	}
	return gatewayID, rc, authCtx, nil
}

func stampConsumerTrace(c *fiber.Ctx, rc *appconsumer.RoutableConsumer) {
	if rc == nil || rc.Consumer == nil {
		return
	}
	rt := trace.FromContext(c.UserContext())
	if rt == nil {
		return
	}
	rt.SetConsumer(rc.Consumer.ID.String(), rc.Consumer.Name)
}

func isAuthorizedForConsumer(rc *appconsumer.RoutableConsumer, authCtx *appauth.AuthContext) bool {
	if rc == nil || rc.Consumer == nil || authCtx == nil {
		return false
	}
	// Playground tokens are validated upstream (signature, purpose, and
	// consumer-slug binding in the playground identity resolver), so they are
	// authorized for the matched consumer regardless of routing mode.
	if authCtx.Method == appauth.MethodPlayground {
		return true
	}
	switch rc.Consumer.RoutingMode {
	case "", domainconsumer.RoutingModeInline:
		return isInlineAuthMethod(authCtx.Method) && consumerHasAuth(rc, authCtx.AuthID)
	case domainconsumer.RoutingModeRoleBased:
		return authCtx.Method == appauth.MethodOIDC && consumerHasRole(rc, authCtx.RoleIDs)
	default:
		return false
	}
}

func isInlineAuthMethod(method appauth.Method) bool {
	switch method {
	case appauth.MethodAPIKey, appauth.MethodOAuth2:
		return true
	default:
		return false
	}
}

func consumerHasAuth(rc *appconsumer.RoutableConsumer, authID ids.AuthID) bool {
	if rc == nil || rc.Consumer == nil {
		return false
	}
	for _, id := range rc.Consumer.AuthIDs {
		if id == authID {
			return true
		}
	}
	return false
}

func consumerHasRole(rc *appconsumer.RoutableConsumer, roleIDs []ids.RoleID) bool {
	if rc == nil || rc.Consumer == nil {
		return false
	}
	effective := make(map[ids.RoleID]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		effective[id] = struct{}{}
	}
	for _, id := range rc.Consumer.RoleIDs {
		if _, ok := effective[id]; ok {
			return true
		}
	}
	return false
}

func buildRequestContext(c *fiber.Ctx, gatewayID ids.GatewayID, route apiresolver.ProxyRoute) *infracontext.RequestContext {
	headers := make(map[string][]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		name := string(key)
		headers[name] = append(headers[name], string(value))
	})

	query := url.Values{}
	c.Context().QueryArgs().VisitAll(func(key, value []byte) {
		query.Add(string(key), string(value))
	})

	incomingBody := c.Body()
	return &infracontext.RequestContext{
		GatewayID:       gatewayID.String(),
		Headers:         headers,
		Method:          c.Method(),
		Path:            c.Path(),
		Query:           query,
		Body:            bytes.Clone(incomingBody),
		OriginalBody:    bytes.Clone(incomingBody),
		IP:              c.IP(),
		SessionID:       sessionIDFromContext(c),
		SourceFormat:    string(route.SourceFormat),
		ProxyCapability: string(route.Capability),
	}
}

func sessionIDFromContext(c *fiber.Ctx) string {
	if v, ok := c.UserContext().Value(infracontext.SessionContextKey).(string); ok && v != "" {
		return v
	}
	if v, ok := c.Locals(string(infracontext.SessionContextKey)).(string); ok {
		return v
	}
	return ""
}

func writeProxyError(c *fiber.Ctx, err error) error {
	status, body := mapProxyError(err)
	if rt := trace.FromContext(c.UserContext()); rt != nil {
		rt.SetStatusReason(body.Error)
	}
	return c.Status(status).JSON(body)
}

func mapProxyError(err error) (int, httpio.ErrorBody) {
	if pe, ok := appplugins.AsPluginError(err); ok {
		return pe.StatusCode, httpio.ErrorBody{Error: errCodePluginRejected, Message: pe.Message}
	}
	switch {
	case errors.Is(err, errNotAuthenticated):
		return fiber.StatusUnauthorized, httpio.ErrorBody{Error: errCodeUnauthenticated, Message: err.Error()}
	case errors.Is(err, errForbidden):
		return fiber.StatusForbidden, httpio.ErrorBody{Error: errCodeForbidden, Message: err.Error()}
	case errors.Is(err, errPathNotFound),
		errors.Is(err, commonerrors.ErrNotFound):
		return fiber.StatusNotFound, httpio.ErrorBody{Error: errCodeNotFound}
	case errors.Is(err, appproxy.ErrNoBackendAvailable),
		errors.Is(err, appproxy.ErrNoBackendsInPool):
		return fiber.StatusServiceUnavailable, httpio.ErrorBody{Error: errCodeNoBackendAvailable, Message: err.Error()}
	case errors.Is(err, appproxy.ErrInvalidRequestPayload):
		return fiber.StatusBadRequest, httpio.ErrorBody{Error: errCodeInvalidRequest, Message: err.Error()}
	case errors.Is(err, routingdomain.ErrInvalidModelRef),
		errors.Is(err, routingdomain.ErrUnknownPoolAlias),
		errors.Is(err, routingdomain.ErrAmbiguousModel):
		return fiber.StatusBadRequest, httpio.ErrorBody{Error: errCodeInvalidModel, Message: err.Error()}
	case errors.Is(err, routingdomain.ErrModelDenied),
		errors.Is(err, appproxy.ErrModelNotAllowed):
		return fiber.StatusForbidden, httpio.ErrorBody{Error: errCodeModelNotAllowed, Message: err.Error()}
	case errors.Is(err, registrydomain.ErrCredentialAcquisition):
		return fiber.StatusBadGateway, httpio.ErrorBody{
			Error:   errCodeProviderCredential,
			Message: registrydomain.ErrCredentialAcquisition.Error(),
		}
	default:
		return fiber.StatusBadGateway, httpio.ErrorBody{Error: errCodeBackendError}
	}
}
