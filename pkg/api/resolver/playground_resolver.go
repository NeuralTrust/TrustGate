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

package resolver

import (
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
)

// HeaderPlaygroundToken carries a short-lived, server-minted JWT that lets the
// dashboard playground exercise a consumer route without that consumer's
// credentials. Minting requires SERVER_SECRET_KEY, so the trust boundary is
// the same as the admin API.
const HeaderPlaygroundToken = "X-AG-Playground-Token" // #nosec G101 -- HTTP header name, not a credential

// PlaygroundIdentityResolver authenticates playground tokens: JWTs tagged with
// purpose "playground" and bound to a single consumer slug. Signatures are
// checked by the PlaygroundVerifier — RS256 against the control-plane issuer
// keys (env or config-sync snapshot) or HS256 with this deployment's server
// secret.
type PlaygroundIdentityResolver struct {
	verifier jwt.PlaygroundVerifier
}

func NewPlaygroundIdentityResolver(verifier jwt.PlaygroundVerifier) *PlaygroundIdentityResolver {
	return &PlaygroundIdentityResolver{verifier: verifier}
}

func (r *PlaygroundIdentityResolver) Resolve(
	c *fiber.Ctx,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	token := c.Get(HeaderPlaygroundToken)
	if token == "" {
		return nil, ErrUnauthenticated
	}
	if rc == nil || rc.Consumer == nil {
		return nil, ErrForbidden
	}
	claims, err := r.verifier.Verify(token)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if claims.Purpose != jwt.PurposePlayground {
		return nil, ErrForbidden
	}
	if claims.ConsumerSlug == "" || claims.ConsumerSlug != rc.Consumer.Slug {
		return nil, ErrForbidden
	}
	// Grant the consumer's own roles so role-based consumers resolve their
	// registries without an IDP token; inline consumers ignore RoleIDs.
	return &appauth.AuthContext{
		Method:      appauth.MethodPlayground,
		GatewayID:   gw.ID,
		GatewaySlug: gw.Slug,
		ConsumerID:  rc.Consumer.ID,
		Subject:     claims.UserID,
		RoleIDs:     rc.Consumer.RoleIDs,
	}, nil
}
