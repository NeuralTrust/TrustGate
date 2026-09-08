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
	"strings"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type ChainedIdentityResolver struct {
	playground IdentityResolver
	apiKey     IdentityResolver
	oauth2     IdentityResolver
	oidc       IdentityResolver
	mtls       *MTLSIdentityResolver
}

// NewIdentityResolver chains the proxy-plane identity resolvers. mtls may be
// nil on a plane that never sees client certificates.
func NewIdentityResolver(
	playground *PlaygroundIdentityResolver,
	apiKey *APIKeyIdentityResolver,
	oauth2 *OAuth2IdentityResolver,
	oidc *OIDCIdentityResolver,
	mtls *MTLSIdentityResolver,
) IdentityResolver {
	return ChainedIdentityResolver{
		playground: playground,
		apiKey:     apiKey,
		oauth2:     oauth2,
		oidc:       oidc,
		mtls:       mtls,
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
	if APIKeyFromRequest(c) != "" {
		return r.apiKey.Resolve(c, gw, rc)
	}
	// A client certificate authenticates a consumer that trusts a CA; an
	// explicit credential (api key, bearer) still wins when both are present,
	// so a TLS-terminating proxy's cert never shadows the application's own.
	if r.mtls != nil && strings.TrimSpace(c.Get(fiber.HeaderAuthorization)) == "" &&
		hasAttachedAuthType(rc, authdomain.TypeMTLS) && r.mtls.ClientCertificate(c) != nil {
		return r.mtls.Resolve(c, gw, rc)
	}
	if strings.TrimSpace(c.Get(fiber.HeaderAuthorization)) == "" {
		return nil, ErrUnauthenticated
	}
	// A bearer token is verified against the consumer's OAuth2 auths; consumers
	// that only carry OIDC auths keep resolving through the OIDC verifier.
	if hasAttachedAuthType(rc, authdomain.TypeOIDC) && !hasAttachedAuthType(rc, authdomain.TypeOAuth2) {
		return r.oidc.Resolve(c, gw, rc)
	}
	return r.oauth2.Resolve(c, gw, rc)
}
