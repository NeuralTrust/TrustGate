package middleware

import (
	"errors"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// ErrUnauthenticated is returned by an IdentityResolver when a request carries
// no resolvable gateway identity.
var ErrUnauthenticated = errors.New("unauthenticated")

// IdentityResolver resolves the gateway a request belongs to from its
// credentials. This is the seam for the follow-up auth work: the real
// implementations will derive the gateway from an API key's consumer, an OAuth
// JWT claim, or the mTLS client certificate. The interim skeleton reads the
// X-Gateway-Id header so the routing contract can be exercised end to end.
type IdentityResolver interface {
	ResolveGatewayID(c *fiber.Ctx) (ids.GatewayID, error)
}

type headerIdentityResolver struct{}

// NewHeaderIdentityResolver is the interim IdentityResolver. It trusts the
// X-Gateway-Id header. TODO: replace with API key -> consumer -> gateway, OAuth
// JWT claim, and mTLS client-cert resolution.
func NewHeaderIdentityResolver() IdentityResolver { return headerIdentityResolver{} }

func (headerIdentityResolver) ResolveGatewayID(c *fiber.Ctx) (ids.GatewayID, error) {
	id, err := ids.Parse[ids.GatewayKind](c.Get(headerGatewayID))
	if err != nil {
		return ids.GatewayID{}, ErrUnauthenticated
	}
	return id, nil
}

// AuthMiddleware resolves the gateway identity, loads the gateway's consumer
// read model, and stores both gatewayID and *consumer.Data on the request
// context for downstream handlers (path -> consumer routing). Credential
// validation itself is deferred to the follow-up that completes the resolver.
type AuthMiddleware struct {
	resolver   IdentityResolver
	dataFinder appconsumer.DataFinder
	gateways   appgateway.Finder
}

func NewAuthMiddleware(
	resolver IdentityResolver,
	dataFinder appconsumer.DataFinder,
	gateways appgateway.Finder,
) *AuthMiddleware {
	return &AuthMiddleware{
		resolver:   resolver,
		dataFinder: dataFinder,
		gateways:   gateways,
	}
}

func (m *AuthMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		gatewayID, err := m.resolver.ResolveGatewayID(c)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
		}
		if _, err := m.gateways.FindByID(c.UserContext(), gatewayID); err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")
		}
		data, err := m.dataFinder.FindByGateway(c.UserContext(), gatewayID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to load gateway data")
		}
		m.attach(c, gatewayID, data)
		return c.Next()
	}
}

func (m *AuthMiddleware) attach(c *fiber.Ctx, gatewayID ids.GatewayID, data *appconsumer.Data) {
	c.Locals(string(appconsumer.GatewayIDKey), gatewayID)
	c.Locals(string(appconsumer.ConsumerDataKey), data)
	ctx := appconsumer.WithGatewayID(c.UserContext(), gatewayID)
	ctx = appconsumer.WithData(ctx, data)
	c.SetUserContext(ctx)
}
