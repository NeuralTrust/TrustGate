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
	jwtVerifier IDPVerifier
}

func NewOAuth2Verifier(jwtVerifier IDPVerifier) OAuth2Verifier {
	return &oauth2Verifier{jwtVerifier: jwtVerifier}
}

func (v *oauth2Verifier) Verify(ctx context.Context, token string, cfg domain.OAuth2Config) (*VerifiedClaims, error) {
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, fmt.Errorf("%w: oauth2 introspection-only configs are not supported for proxy auth", ErrInvalidAuthRequest)
	}
	return v.jwtVerifier.Verify(ctx, token, domain.IDPConfig{
		Issuer:            cfg.Issuer,
		Audiences:         cfg.Audiences,
		JWKSURL:           cfg.JWKSURL,
		RequiredScopes:    cfg.RequiredScopes,
		AllowedAlgorithms: cfg.Algorithms,
	})
}
