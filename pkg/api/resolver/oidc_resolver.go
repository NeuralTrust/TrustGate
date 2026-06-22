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
	"fmt"
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type OIDCIdentityResolver struct {
	finder   appauth.OIDCFinder
	verifier appauth.OIDCVerifier
}

func NewOIDCIdentityResolver(finder appauth.OIDCFinder, verifier appauth.OIDCVerifier) *OIDCIdentityResolver {
	return &OIDCIdentityResolver{finder: finder, verifier: verifier}
}

func (r *OIDCIdentityResolver) Resolve(
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
	a, err := r.finder.FindOIDCAuth(c.UserContext(), rc.Auths, token)
	if err != nil {
		return nil, err
	}
	if a.Config.OIDC == nil {
		return nil, fmt.Errorf("%w: selected auth has no oidc config", appauth.ErrInvalidAuthRequest)
	}
	verified, err := r.verifier.Verify(c.UserContext(), token, *a.Config.OIDC)
	if err != nil {
		return nil, err
	}
	return &appauth.AuthContext{
		Method:      appauth.MethodOIDC,
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
