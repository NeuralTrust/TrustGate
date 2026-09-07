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
	"errors"
	"fmt"
	"log/slog"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type OAuth2IdentityResolver struct {
	finder   appauth.IdentityProviderFinder
	verifier appauth.OAuth2Verifier
	logger   *slog.Logger
}

func NewOAuth2IdentityResolver(
	finder appauth.IdentityProviderFinder,
	verifier appauth.OAuth2Verifier,
	logger *slog.Logger,
) *OAuth2IdentityResolver {
	return &OAuth2IdentityResolver{finder: finder, verifier: verifier, logger: logger}
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
	if !hasEnabledIdentityProvider(rc) {
		return nil, ErrForbidden
	}
	candidates, err := r.finder.FindCandidates(c.UserContext(), rc.Auths, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if len(candidates) == 0 {
		return nil, ErrUnauthenticated
	}
	if len(candidates) > 1 {
		r.logAmbiguousCandidates(gw.ID, candidates)
	}
	for _, a := range candidates {
		verified, err := r.verifier.Verify(c.UserContext(), token, *a.Config.OAuth2)
		if err != nil {
			if errors.Is(err, appauth.ErrInvalidAuthRequest) {
				return nil, err
			}
			continue
		}
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
	return nil, ErrUnauthenticated
}

// logAmbiguousCandidates records overlapping identity providers at debug level:
// the overlap is a persistent property of the gateway's configuration, so
// warning on every request would repeat the same operator action forever.
func (r *OAuth2IdentityResolver) logAmbiguousCandidates(gatewayID ids.GatewayID, candidates []*authdomain.Auth) {
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	authIDs := make([]string, 0, len(candidates))
	for _, a := range candidates {
		authIDs = append(authIDs, a.ID.String())
	}
	logger.Debug("multiple identity providers match token hints",
		slog.String("gateway_id", gatewayID.String()),
		slog.Any("auth_ids", authIDs),
	)
}
