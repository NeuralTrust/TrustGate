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

package auth

import (
	"context"
	"errors"
	"fmt"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

var ErrInvalidAuthRequest = errors.New("invalid auth request")

//go:generate mockery --name=IdentityProviderFinder --dir=. --output=./mocks --filename=auth_identity_provider_finder_mock.go --case=underscore --with-expecter
type IdentityProviderFinder interface {
	FindCandidates(ctx context.Context, auths []*domain.Auth, token string) ([]*domain.Auth, error)
}

var _ IdentityProviderFinder = (*identityProviderFinder)(nil)

type identityProviderFinder struct {
	verifier OIDCVerifier
}

func NewIdentityProviderFinder(verifier OIDCVerifier) IdentityProviderFinder {
	return &identityProviderFinder{verifier: verifier}
}

func (f *identityProviderFinder) FindCandidates(
	ctx context.Context,
	auths []*domain.Auth,
	token string,
) ([]*domain.Auth, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hints, err := f.verifier.Peek(token)
	if err != nil {
		return nil, fmt.Errorf("peek token hints: %w", err)
	}
	candidates := make([]*domain.Auth, 0, len(auths))
	for _, a := range auths {
		candidate, ok := IdentityProviderCandidate(a)
		if !ok {
			continue
		}
		if oauth2ConfigMatchesHints(*candidate.Config.OAuth2, hints) {
			candidates = append(candidates, candidate)
		}
	}
	return candidates, nil
}

// IdentityProviderCandidate reports whether the auth is a usable identity
// provider and, when it is, returns a view of it whose Config.OAuth2 is always
// populated. An oidc config is projected onto the oauth2 shape on a copy, so
// callers may hold the result without mutating shared or cached auths.
func IdentityProviderCandidate(a *domain.Auth) (*domain.Auth, bool) {
	if a == nil || !a.Enabled || !a.Type.IsIdentityProvider() {
		return nil, false
	}
	if a.Config.OAuth2 != nil {
		return a, true
	}
	if a.Config.OIDC == nil {
		return nil, false
	}
	projected := *a
	projected.Config.OAuth2 = oauth2ConfigFromOIDC(*a.Config.OIDC)
	return &projected, true
}

func oauth2ConfigFromOIDC(cfg domain.OIDCConfig) *domain.OAuth2Config {
	return &domain.OAuth2Config{
		Issuer:         cfg.Issuer,
		Audiences:      cfg.Audiences,
		JWKSURL:        cfg.JWKSURL,
		PublicKeys:     cfg.PublicKeys,
		RequiredScopes: cfg.RequiredScopes,
		Algorithms:     cfg.AllowedAlgorithms,
		SubjectClaim:   cfg.SubjectClaim,
	}
}

func oauth2ConfigMatchesHints(cfg domain.OAuth2Config, hints TokenHints) bool {
	if cfg.Issuer != "" && hints.Issuer != "" && cfg.Issuer != hints.Issuer {
		return false
	}
	if len(cfg.Audiences) == 0 || len(hints.Audiences) == 0 {
		return true
	}
	return identity.AudienceMatches(hints.Audiences, cfg.Audiences)
}
