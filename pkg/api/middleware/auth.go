package middleware

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	"github.com/NeuralTrust/AgentGateway/pkg/api/resolver"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	identitydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// HeaderAPIKey, ErrUnauthenticated, Identity and IdentityResolver back the
// MCP-plane chain resolver (auth_chain.go). They will be folded into the
// unified resolver package during the post-merge auth consolidation.
const HeaderAPIKey = "X-AG-API-Key" // #nosec G101 -- HTTP header name, not a credential

var ErrUnauthenticated = errors.New("unauthenticated")

type Identity struct {
	GatewayID ids.GatewayID
	AuthID    ids.AuthID
	Principal *identitydomain.Principal
}

type IdentityResolver interface {
	Resolve(c *fiber.Ctx) (Identity, error)
}

type apiKeyIdentityResolver struct {
	finder appauth.APIKeyFinder
}

func NewAPIKeyIdentityResolver(finder appauth.APIKeyFinder) IdentityResolver {
	return apiKeyIdentityResolver{finder: finder}
}

func (r apiKeyIdentityResolver) Resolve(c *fiber.Ctx) (Identity, error) {
	rawKey := c.Get(HeaderAPIKey)
	if rawKey == "" {
		return Identity{}, ErrUnauthenticated
	}
	a, err := r.finder.FindByAPIKey(c.UserContext(), rawKey)
	if err != nil || a == nil || !a.Enabled || a.Type != authdomain.TypeAPIKey {
		return Identity{}, ErrUnauthenticated
	}
	return Identity{GatewayID: a.GatewayID, AuthID: a.ID}, nil
}

type AuthMiddleware struct {
	resolver        resolver.IdentityResolver
	dataFinder      appconsumer.DataFinder
	gatewayResolver resolver.GatewayResolver
	roleResolver    approle.IDPResolver
}

func NewAuthMiddleware(
	identityResolver resolver.IdentityResolver,
	dataFinder appconsumer.DataFinder,
	gatewayResolver resolver.GatewayResolver,
	roleResolver approle.IDPResolver,
) *AuthMiddleware {
	return &AuthMiddleware{
		resolver:        identityResolver,
		dataFinder:      dataFinder,
		gatewayResolver: gatewayResolver,
		roleResolver:    roleResolver,
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
			return notFound(c)
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
			if errors.Is(err, resolver.ErrUnauthenticated) && apiKeyAttachedElsewhere(c.Get(resolver.HeaderAPIKey), data, rc) {
				return forbidden(c, resolver.ErrForbidden)
			}
			return writeAuthError(c, err)
		}
		authCtx.GatewayID = gw.ID
		authCtx.GatewaySlug = gw.Slug
		authCtx.ConsumerID = rc.Consumer.ID
		if authCtx.Method == appauth.MethodIDP {
			if m.roleResolver == nil {
				return internalError(c, "failed to resolve idp roles")
			}
			roleIDs, err := m.roleResolver.ResolveIDPRoles(c.UserContext(), data.Roles, authCtx.Claims)
			if err != nil {
				return invalidAuthRequest(c, err)
			}
			authCtx.RoleIDs = intersectRoleIDs(roleIDs, rc.Consumer.RoleIDs)
			if len(authCtx.RoleIDs) == 0 {
				return forbidden(c, resolver.ErrForbidden)
			}
		}
		m.attach(c, authCtx, gw, data, rc)
		return c.Next()
	}
}

func writeAuthError(c *fiber.Ctx, err error) error {
	if errors.Is(err, appauth.ErrInvalidAuthRequest) || errors.Is(err, appauth.ErrAmbiguousIDPConfig) {
		return invalidAuthRequest(c, err)
	}
	if errors.Is(err, commonerrors.ErrInvalidConfig) || errors.Is(err, commonerrors.ErrValidation) {
		return invalidAuthRequest(c, err)
	}
	if errors.Is(err, resolver.ErrForbidden) {
		return forbidden(c, err)
	}
	if errors.Is(err, appauth.ErrTokenAcquisition) {
		return authUpstreamUnavailable(c)
	}
	return unauthenticated(c)
}

func isAuthMappableError(err error) bool {
	return errors.Is(err, appauth.ErrInvalidAuthRequest) ||
		errors.Is(err, appauth.ErrAmbiguousIDPConfig) ||
		errors.Is(err, commonerrors.ErrInvalidConfig) ||
		errors.Is(err, commonerrors.ErrValidation) ||
		errors.Is(err, resolver.ErrForbidden) ||
		errors.Is(err, resolver.ErrUnauthenticated)
}

func unauthenticated(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(helpers.ErrorBody{
		Error:   "unauthenticated",
		Message: resolver.ErrUnauthenticated.Error(),
	})
}

func forbidden(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusForbidden).JSON(helpers.ErrorBody{
		Error:   "forbidden",
		Message: err.Error(),
	})
}

func invalidAuthRequest(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusBadRequest).JSON(helpers.ErrorBody{
		Error:   "invalid_auth_request",
		Message: err.Error(),
	})
}

func notFound(c *fiber.Ctx) error {
	return c.Status(fiber.StatusNotFound).JSON(helpers.ErrorBody{
		Error: "not_found",
	})
}

func authUpstreamUnavailable(c *fiber.Ctx) error {
	return c.Status(fiber.StatusServiceUnavailable).JSON(helpers.ErrorBody{
		Error:   "auth_upstream_unavailable",
		Message: appauth.ErrTokenAcquisition.Error(),
	})
}

func internalError(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(helpers.ErrorBody{
		Error:   "internal_error",
		Message: message,
	})
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
	c.Locals(string(appconsumer.ConsumerKey), rc)
	ctx := appauth.WithAuthContext(c.UserContext(), authCtx)
	ctx = appconsumer.WithGatewayID(ctx, authCtx.GatewayID)
	if authCtx.AuthID != (ids.AuthID{}) {
		ctx = appconsumer.WithAuthID(ctx, authCtx.AuthID)
	}
	ctx = appconsumer.WithData(ctx, data)
	ctx = appconsumer.WithConsumer(ctx, rc)
	ctx = appgateway.WithGateway(ctx, gw)
	c.SetUserContext(ctx)
}

func apiKeyAttachedElsewhere(rawKey string, data *appconsumer.Data, rc *appconsumer.RoutableConsumer) bool {
	if rawKey == "" || data == nil || rc == nil || rc.Consumer == nil {
		return false
	}
	hash := authdomain.HashAPIKey(rawKey)
	for i := range data.Consumers {
		other := &data.Consumers[i]
		if other.Consumer == nil || other.Consumer.ID == rc.Consumer.ID {
			continue
		}
		for _, a := range other.Auths {
			if a != nil && a.Enabled && a.Type == authdomain.TypeAPIKey && a.KeyHash == hash {
				return true
			}
		}
	}
	return false
}

func intersectRoleIDs(resolved, assigned []ids.RoleID) []ids.RoleID {
	assignedSet := make(map[ids.RoleID]struct{}, len(assigned))
	for _, id := range assigned {
		assignedSet[id] = struct{}{}
	}
	out := make([]ids.RoleID, 0, len(resolved))
	for _, id := range resolved {
		if _, ok := assignedSet[id]; ok {
			out = append(out, id)
		}
	}
	return out
}
