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

package middleware

import (
	"cmp"
	"errors"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type AuthMiddleware struct {
	resolver        resolver.IdentityResolver
	dataFinder      appconsumer.DataFinder
	gatewayResolver resolver.GatewayResolver
	storeKeys       appconsumer.StoreKeyResolver
	logger          *slog.Logger
	now             func() time.Time
}

func NewAuthMiddleware(
	identityResolver resolver.IdentityResolver,
	dataFinder appconsumer.DataFinder,
	gatewayResolver resolver.GatewayResolver,
	storeKeys appconsumer.StoreKeyResolver,
	logger *slog.Logger,
	now func() time.Time,
) *AuthMiddleware {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if storeKeys == nil {
		cmp.Or(logger, slog.Default()).Warn("no store key resolver is wired, so /store/v1 answers 404")
	}
	return &AuthMiddleware{
		resolver:        identityResolver,
		dataFinder:      dataFinder,
		gatewayResolver: gatewayResolver,
		storeKeys:       storeKeys,
		logger:          logger,
		now:             now,
	}
}

func (m *AuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gw, err := m.gatewayResolver.Resolve(c)
		if err != nil {
			if isAuthMappableError(err) {
				return writeAuthError(c, err)
			}
			return internalError(c, "failed to resolve gateway")
		}
		route, err := resolver.ResolveProxyPath(c.Path())
		if err != nil {
			if errors.Is(err, resolver.ErrInvalidBedrockModelID) {
				return invalidModelID(c, err)
			}
			return notFound(c)
		}
		if consumerdomain.IsStoreSlug(route.ConsumerSlug) {
			return m.serveStore(c, gw, route)
		}
		data, err := m.dataFinder.FindByGateway(c.UserContext(), gw.ID)
		if err != nil {
			return internalError(c, "failed to load gateway data")
		}
		rc, ok := data.MatchSlug(route.ConsumerSlug)
		if !ok {
			return notFound(c)
		}
		c.Locals(resolver.ProxyRouteLocalsKey, route)
		authCtx, err := m.resolver.Resolve(c, gw, rc)
		if err != nil {
			m.debug(c).Debug("identity resolution failed",
				slog.String("gateway_slug", gw.Slug),
				slog.String("consumer_slug", route.ConsumerSlug),
				slog.String("error", err.Error()))
			if errors.Is(err, resolver.ErrUnauthenticated) && apiKeyAttachedElsewhere(resolver.APIKeyFromRequest(c), data, rc, m.now()) {
				return forbidden(c, resolver.ErrForbidden)
			}
			return writeAuthError(c, err)
		}
		authCtx.GatewayID = gw.ID
		authCtx.GatewaySlug = gw.Slug
		authCtx.ConsumerID = rc.Consumer.ID
		if !consumerAdmitsCaller(rc.Consumer, authCtx) {
			m.debug(c).Debug("caller not bound to consumer",
				slog.String("consumer_slug", route.ConsumerSlug),
				slog.String("method", string(authCtx.Method)))
			return forbidden(c, resolver.ErrForbidden)
		}
		m.attach(c, authCtx, gw, data, rc)
		return c.Next()
	}
}

func (m *AuthMiddleware) serveStore(c *fiber.Ctx, gw *gatewaydomain.Gateway, route resolver.ProxyRoute) error {
	if m.storeKeys == nil || gw.ServedByHybridDataPlane() {
		return notFound(c)
	}
	data, err := m.dataFinder.FindByGateway(c.UserContext(), gw.ID)
	if err != nil {
		return internalError(c, "failed to load gateway data")
	}
	// A gateway with no personal consumer answers like an unknown slug, so a
	// gateway that never used the store keeps its 404. A personal key of the
	// gateway still gets through: its owner lost every model, and the store
	// handler says so instead of claiming the route does not exist.
	inUse := data.HasPersonalConsumers()
	rawKey := resolver.APIKeyFromRequest(c)
	if rawKey == "" {
		if !inUse {
			return notFound(c)
		}
		return unauthenticated(c)
	}
	key, err := m.storeKeys.Resolve(c.UserContext(), gw.ID, rawKey)
	if errors.Is(err, appconsumer.ErrStoreKeyRejected) {
		m.debug(c).Debug("store key rejected", slog.String("gateway_slug", gw.Slug))
		if !inUse {
			return notFound(c)
		}
		return unauthenticated(c)
	}
	if err != nil {
		m.debug(c).Warn("store key resolution failed",
			slog.String("gateway_slug", gw.Slug),
			slog.String("error", err.Error()))
		return internalError(c, "failed to resolve api key")
	}
	c.Locals(resolver.ProxyRouteLocalsKey, route)
	principal := &identity.Principal{Subject: key.OwnerID, Method: identity.MethodAPIKey}
	if key.OwnerEmail != "" {
		// The owner's email, so the key's calls are shown under the person
		// who made them and not under their user id.
		principal.Claims = map[string]any{identity.ClaimEmail: key.OwnerEmail}
	}
	m.attach(c, &appauth.AuthContext{
		Principal:   principal,
		Method:      appauth.MethodAPIKey,
		GatewayID:   gw.ID,
		GatewaySlug: gw.Slug,
		AuthID:      key.ID,
		OwnerID:     key.OwnerID,
		KeyBudget:   key.Budget.Clone(),
		Subject:     key.OwnerID,
	}, gw, data, nil)
	return c.Next()
}

func (m *AuthMiddleware) debug(c *fiber.Ctx) *slog.Logger {
	logger := m.logger
	if logger == nil {
		logger = slog.Default()
	}
	return logger.With(
		slog.String("trace_id", c.Get(HeaderTraceID)),
		slog.String("path", c.Path()),
	)
}

func writeAuthError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appauth.ErrInvalidAuthRequest) {
		return invalidAuthRequest(c, err)
	}
	if errors.Is(err, commonerrors.ErrInvalidConfig) || errors.Is(err, commonerrors.ErrValidation) {
		return invalidAuthRequest(c, err)
	}
	if errors.Is(err, resolver.ErrForbidden) {
		return forbidden(c, err)
	}
	return unauthenticated(c)
}

func isAuthMappableError(err error) bool {
	return errors.Is(err, appauth.ErrInvalidAuthRequest) ||
		errors.Is(err, commonerrors.ErrInvalidConfig) ||
		errors.Is(err, commonerrors.ErrValidation) ||
		errors.Is(err, resolver.ErrForbidden) ||
		errors.Is(err, resolver.ErrUnauthenticated)
}

func unauthenticated(c *fiber.Ctx) error {
	return writeAuthBody(c, fiber.StatusUnauthorized, httpio.ErrorBody{
		Error:   "unauthenticated",
		Message: resolver.ErrUnauthenticated.Error(),
	})
}

func forbidden(c *fiber.Ctx, err error) error {
	return writeAuthBody(c, fiber.StatusForbidden, httpio.ErrorBody{
		Error:   "forbidden",
		Message: err.Error(),
	})
}

func invalidAuthRequest(c *fiber.Ctx, err error) error {
	return writeAuthBody(c, fiber.StatusBadRequest, httpio.ErrorBody{
		Error:   "invalid_auth_request",
		Message: err.Error(),
	})
}

func invalidModelID(c *fiber.Ctx, err error) error {
	return writeAuthBody(c, fiber.StatusBadRequest, httpio.ErrorBody{
		Error:   "invalid_model",
		Message: err.Error(),
	})
}

func notFound(c *fiber.Ctx) error {
	return writeAuthBody(c, fiber.StatusNotFound, httpio.ErrorBody{
		Error: "not_found",
	})
}

func internalError(c *fiber.Ctx, message string) error {
	return writeAuthBody(c, fiber.StatusInternalServerError, httpio.ErrorBody{
		Error:   "internal_error",
		Message: message,
	})
}

// writeAuthBody sends the gateway's error body. On a native Bedrock path it
// carries the AWS envelope as well, with the x-amzn-ErrorType header, because
// an AWS SDK reads the exception name from there and cannot classify a bare
// gateway error.
func writeAuthBody(c *fiber.Ctx, status int, body httpio.ErrorBody) error {
	if !isBedrockNativePath(c) {
		return c.Status(status).JSON(body)
	}
	return httpio.WriteBedrockError(c, status, body)
}

// isBedrockNativePath reports whether the request is addressed to a native
// Bedrock Runtime route, including one whose model identifier was refused. The
// route may not have been resolved yet when the gateway fails, so it is parsed
// from the path again.
func isBedrockNativePath(c *fiber.Ctx) bool {
	if route, ok := c.Locals(resolver.ProxyRouteLocalsKey).(resolver.ProxyRoute); ok {
		return route.IsBedrockNative()
	}
	route, err := resolver.ResolveProxyPath(c.Path())
	if err != nil {
		return errors.Is(err, resolver.ErrInvalidBedrockModelID)
	}
	return route.IsBedrockNative()
}

func (m *AuthMiddleware) attach(
	c *fiber.Ctx,
	authCtx *appauth.AuthContext,
	gw *gatewaydomain.Gateway,
	data *appconsumer.Data,
	rc *appconsumer.RoutableConsumer,
) {
	c.Locals(string(appconsumer.GatewayIDKey), authCtx.GatewayID)
	if authCtx.AuthID != (ids.AuthID{}) {
		c.Locals(string(appconsumer.AuthIDKey), authCtx.AuthID)
	}
	c.Locals(string(appconsumer.ConsumerDataKey), data)
	ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
	if authCtx.Principal != nil {
		ctx = identity.WithPrincipal(ctx, authCtx.Principal)
	}
	ctx = appconsumer.WithGatewayID(ctx, authCtx.GatewayID)
	if authCtx.AuthID != (ids.AuthID{}) {
		ctx = appconsumer.WithAuthID(ctx, authCtx.AuthID)
	}
	ctx = appconsumer.WithData(ctx, data)
	if rc != nil {
		c.Locals(string(appconsumer.ConsumerKey), rc)
		ctx = appconsumer.WithConsumer(ctx, rc)
	}
	ctx = appgateway.WithGateway(ctx, gw)
	c.SetUserContext(ctx)
}

func apiKeyAttachedElsewhere(rawKey string, data *appconsumer.Data, rc *appconsumer.RoutableConsumer, now time.Time) bool {
	if rawKey == "" || data == nil || rc == nil || rc.Consumer == nil {
		return false
	}
	hash := authdomain.HashAPIKey(rawKey)
	for i := range data.Consumers {
		other := &data.Consumers[i]
		if other.Consumer == nil || other.Consumer.ID == rc.Consumer.ID || other.Consumer.IsPersonal() {
			continue
		}
		for _, a := range other.Auths {
			if a.AcceptsAPIKey(hash, now) {
				return true
			}
		}
	}
	return false
}

// consumerAdmitsCaller applies the consumer's auth binding to a verified
// caller: a bearer token from a shared IdP must have been issued to one of the
// consumer's allowed clients, and a client certificate must carry an allowed
// subject. API keys and playground tokens are already bound to one consumer.
func consumerAdmitsCaller(cons *consumerdomain.Consumer, authCtx *appauth.AuthContext) bool {
	if cons == nil || authCtx == nil {
		return false
	}
	switch authCtx.Method {
	case appauth.MethodOAuth2, appauth.MethodOIDC:
		return cons.AuthBinding.AllowsClient(authCtx.Claims)
	case appauth.MethodMTLS:
		return cons.AuthBinding.AllowsCertificateClaims(authCtx.Claims)
	default:
		return true
	}
}
