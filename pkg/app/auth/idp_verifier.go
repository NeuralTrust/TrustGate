package auth

import (
	"context"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

type TokenHints struct {
	Issuer    string
	Audiences []string
	KeyID     string
	Algorithm string
}

type VerifiedClaims struct {
	Subject string
	Claims  map[string]any
	Scopes  []string
}

//go:generate mockery --name=IDPVerifier --dir=. --output=./mocks --filename=idp_verifier_mock.go --case=underscore --with-expecter
type IDPVerifier interface {
	Peek(token string) (TokenHints, error)
	Verify(ctx context.Context, token string, cfg domain.IDPConfig) (*VerifiedClaims, error)
}
