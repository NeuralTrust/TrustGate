package resolver

import (
	"fmt"
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type IDPIdentityResolver struct {
	finder   appauth.IDPFinder
	verifier appauth.IDPVerifier
}

func NewIDPIdentityResolver(finder appauth.IDPFinder, verifier appauth.IDPVerifier) *IDPIdentityResolver {
	return &IDPIdentityResolver{finder: finder, verifier: verifier}
}

func (r *IDPIdentityResolver) Resolve(
	c *fiber.Ctx,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	token, err := bearerToken(c.Get(fiber.HeaderAuthorization))
	if err != nil {
		return nil, err
	}
	if rc == nil || rc.Consumer == nil || rc.Consumer.RoutingMode != consumerdomain.RoutingModeRoleBased {
		return nil, ErrForbidden
	}
	a, err := r.finder.FindIDPAuth(c.UserContext(), rc.Auths, token)
	if err != nil {
		return nil, err
	}
	if a.Config.IDP == nil {
		return nil, fmt.Errorf("%w: selected auth has no idp config", appauth.ErrInvalidAuthRequest)
	}
	verified, err := r.verifier.Verify(c.UserContext(), token, *a.Config.IDP)
	if err != nil {
		return nil, err
	}
	return &appauth.AuthContext{
		Method:      appauth.MethodIDP,
		GatewayID:   gw.ID,
		GatewaySlug: gw.Slug,
		ConsumerID:  rc.Consumer.ID,
		AuthID:      a.ID,
		Subject:     verified.Subject,
		Claims:      verified.Claims,
		Scopes:      verified.Scopes,
	}, nil
}

func bearerToken(header string) (string, error) {
	if strings.TrimSpace(header) == "" {
		return "", ErrUnauthenticated
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("%w: malformed bearer authorization header", appauth.ErrInvalidAuthRequest)
	}
	return parts[1], nil
}
