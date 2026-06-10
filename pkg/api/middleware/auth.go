package middleware

import (
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

const HeaderAPIKey = "X-AG-API-Key" // #nosec G101 -- HTTP header name, not a credential

var ErrUnauthenticated = errors.New("unauthenticated")

type Identity struct {
	GatewayID ids.GatewayID
	AuthID    ids.AuthID
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
		identity, err := m.resolver.Resolve(c)
		if err != nil {
			return unauthenticated(c)
		}
		gw, err := m.gateways.FindByID(c.UserContext(), identity.GatewayID)
		if err != nil {
			return unauthenticated(c)
		}
		data, err := m.dataFinder.FindByGateway(c.UserContext(), identity.GatewayID)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "failed to load gateway data")
		}
		m.attach(c, identity, gw, data)
		return c.Next()
	}
}

func unauthenticated(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(helpers.ErrorBody{
		Error:   "unauthenticated",
		Message: ErrUnauthenticated.Error(),
	})
}

func (m *AuthMiddleware) attach(c *fiber.Ctx, identity Identity, gw *gatewaydomain.Gateway, data *appconsumer.Data) {
	c.Locals(string(appconsumer.GatewayIDKey), identity.GatewayID)
	c.Locals(string(appconsumer.AuthIDKey), identity.AuthID)
	c.Locals(string(appconsumer.ConsumerDataKey), data)
	ctx := appconsumer.WithGatewayID(c.UserContext(), identity.GatewayID)
	ctx = appconsumer.WithAuthID(ctx, identity.AuthID)
	ctx = appconsumer.WithData(ctx, data)
	ctx = appgateway.WithGateway(ctx, gw)
	c.SetUserContext(ctx)
}
