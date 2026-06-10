package resolver

import (
	"crypto/subtle"
	"fmt"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type OAuth2ClientIdentityResolver struct {
	tokens appauth.OAuth2ClientTokenSource
}

func NewOAuth2ClientIdentityResolver(tokens appauth.OAuth2ClientTokenSource) *OAuth2ClientIdentityResolver {
	return &OAuth2ClientIdentityResolver{tokens: tokens}
}

func (r *OAuth2ClientIdentityResolver) Resolve(
	c *fiber.Ctx,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	token, err := bearerToken(c.Get(fiber.HeaderAuthorization))
	if err != nil {
		return nil, err
	}
	if rc == nil || rc.Consumer == nil || rc.Consumer.RoutingMode == consumerdomain.RoutingModeRoleBased {
		return nil, ErrForbidden
	}
	var attached bool
	for _, a := range rc.Auths {
		if a == nil || !a.Enabled || a.Type != authdomain.TypeOAuth2Client || a.Config.OAuth2Client == nil {
			continue
		}
		attached = true
		acquired, err := r.tokens.Token(c.UserContext(), *a.Config.OAuth2Client)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", appauth.ErrTokenAcquisition, err)
		}
		if subtle.ConstantTimeCompare([]byte(acquired), []byte(token)) == 1 {
			return &appauth.AuthContext{
				Method:      appauth.MethodOAuth2Client,
				GatewayID:   gw.ID,
				GatewaySlug: gw.Slug,
				ConsumerID:  rc.Consumer.ID,
				AuthID:      a.ID,
			}, nil
		}
	}
	if attached {
		return nil, ErrUnauthenticated
	}
	return nil, ErrForbidden
}
