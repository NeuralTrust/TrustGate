package resolver

import (
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type ChainedIdentityResolver struct {
	playground IdentityResolver
	apiKey     IdentityResolver
	oauth2     IdentityResolver
	idp        IdentityResolver
}

func NewIdentityResolver(
	playground *PlaygroundIdentityResolver,
	apiKey *APIKeyIdentityResolver,
	oauth2 *OAuth2IdentityResolver,
	idp *IDPIdentityResolver,
) IdentityResolver {
	return ChainedIdentityResolver{
		playground: playground,
		apiKey:     apiKey,
		oauth2:     oauth2,
		idp:        idp,
	}
}

func (r ChainedIdentityResolver) Resolve(
	c *fiber.Ctx,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	if c.Get(HeaderPlaygroundToken) != "" {
		return r.playground.Resolve(c, gw, rc)
	}
	if c.Get(HeaderAPIKey) != "" {
		return r.apiKey.Resolve(c, gw, rc)
	}
	if strings.TrimSpace(c.Get(fiber.HeaderAuthorization)) == "" {
		return nil, ErrUnauthenticated
	}
	if rc != nil && rc.Consumer != nil && rc.Consumer.RoutingMode == consumerdomain.RoutingModeInline {
		return r.oauth2.Resolve(c, gw, rc)
	}
	if hasAttachedAuthType(rc, authdomain.TypeOAuth2) && !hasAttachedAuthType(rc, authdomain.TypeIDP) {
		return nil, ErrForbidden
	}
	return r.idp.Resolve(c, gw, rc)
}
