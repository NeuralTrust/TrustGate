package middleware

import (
	"errors"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type OAuth2IdentityResolver struct {
	verifier appauth.OAuth2Verifier
}

func NewOAuth2IdentityResolver(verifier appauth.OAuth2Verifier) *OAuth2IdentityResolver {
	return &OAuth2IdentityResolver{verifier: verifier}
}

func (r *OAuth2IdentityResolver) Resolve(
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
	var invalidCredential bool
	for _, a := range rc.Auths {
		if a == nil || !a.Enabled || a.Type != authdomain.TypeOAuth2 || a.Config.OAuth2 == nil {
			continue
		}
		verified, err := r.verifier.Verify(c.UserContext(), token, *a.Config.OAuth2)
		if err == nil {
			return &appauth.AuthContext{
				Method:      appauth.MethodOAuth2,
				GatewayID:   gw.ID,
				GatewaySlug: gw.Slug,
				ConsumerID:  rc.Consumer.ID,
				AuthID:      a.ID,
				Subject:     verified.Subject,
				Claims:      verified.Claims,
				Scopes:      verified.Scopes,
			}, nil
		}
		if errors.Is(err, appauth.ErrInvalidAuthRequest) {
			return nil, err
		}
		invalidCredential = true
	}
	if invalidCredential || hasAttachedAuthType(rc, authdomain.TypeOAuth2) {
		return nil, ErrUnauthenticated
	}
	return nil, ErrForbidden
}
