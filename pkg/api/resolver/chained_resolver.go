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
	oidc       IdentityResolver
}

func NewIdentityResolver(
	playground *PlaygroundIdentityResolver,
	apiKey *APIKeyIdentityResolver,
	oauth2 *OAuth2IdentityResolver,
	oidc *OIDCIdentityResolver,
) IdentityResolver {
	return ChainedIdentityResolver{
		playground: playground,
		apiKey:     apiKey,
		oauth2:     oauth2,
		oidc:       oidc,
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
	if hasAttachedAuthType(rc, authdomain.TypeOAuth2) && !hasAttachedAuthType(rc, authdomain.TypeOIDC) {
		return nil, ErrForbidden
	}
	return r.oidc.Resolve(c, gw, rc)
}
