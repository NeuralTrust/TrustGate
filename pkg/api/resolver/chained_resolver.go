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
	playground   IdentityResolver
	apiKey       IdentityResolver
	oauth2       IdentityResolver
	oauth2Client IdentityResolver
	idp          IdentityResolver
}

func NewIdentityResolver(
	playground *PlaygroundIdentityResolver,
	apiKey *APIKeyIdentityResolver,
	oauth2 *OAuth2IdentityResolver,
	oauth2Client *OAuth2ClientIdentityResolver,
	idp *IDPIdentityResolver,
) IdentityResolver {
	return ChainedIdentityResolver{
		playground:   playground,
		apiKey:       apiKey,
		oauth2:       oauth2,
		oauth2Client: oauth2Client,
		idp:          idp,
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
		if hasAttachedAuthType(rc, authdomain.TypeOAuth2Client) {
			return r.oauth2Client.Resolve(c, gw, rc)
		}
		return r.oauth2.Resolve(c, gw, rc)
	}
	if (hasAttachedAuthType(rc, authdomain.TypeOAuth2) || hasAttachedAuthType(rc, authdomain.TypeOAuth2Client)) &&
		!hasAttachedAuthType(rc, authdomain.TypeIDP) {
		return nil, ErrForbidden
	}
	return r.idp.Resolve(c, gw, rc)
}
