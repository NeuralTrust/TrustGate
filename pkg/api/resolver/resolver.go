// Package resolver contains the proxy-plane identity and gateway resolution
// strategies. Resolvers translate transport-level credentials (API key header,
// bearer tokens) and gateway identification (slug header, subdomain host) into
// an authenticated context; the auth middleware orchestrates them.
package resolver

import (
	"errors"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

const HeaderAPIKey = "X-AG-API-Key" // #nosec G101 -- HTTP header name, not a credential

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
)

type IdentityResolver interface {
	Resolve(c *fiber.Ctx, gw *gatewaydomain.Gateway, rc *appconsumer.RoutableConsumer) (*appauth.AuthContext, error)
}

func hasAttachedAuthType(rc *appconsumer.RoutableConsumer, authType authdomain.Type) bool {
	if rc == nil {
		return false
	}
	for _, a := range rc.Auths {
		if a != nil && a.Enabled && a.Type == authType {
			return true
		}
	}
	return false
}
