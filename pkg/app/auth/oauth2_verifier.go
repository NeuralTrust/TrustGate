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
	"fmt"
	"strings"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

type OAuth2Verifier interface {
	Verify(ctx context.Context, token string, cfg domain.OAuth2Config) (*VerifiedClaims, error)
}

var _ OAuth2Verifier = (*oauth2Verifier)(nil)

type oauth2Verifier struct {
	jwtVerifier OIDCVerifier
}

func NewOAuth2Verifier(jwtVerifier OIDCVerifier) OAuth2Verifier {
	return &oauth2Verifier{jwtVerifier: jwtVerifier}
}

func (v *oauth2Verifier) Verify(ctx context.Context, token string, cfg domain.OAuth2Config) (*VerifiedClaims, error) {
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, fmt.Errorf("%w: oauth2 introspection-only configs are not supported for proxy auth", ErrInvalidAuthRequest)
	}
	return v.jwtVerifier.Verify(ctx, token, domain.OIDCConfig{
		Issuer:            cfg.Issuer,
		Audiences:         cfg.Audiences,
		JWKSURL:           cfg.JWKSURL,
		RequiredScopes:    cfg.RequiredScopes,
		AllowedAlgorithms: cfg.Algorithms,
	})
}
