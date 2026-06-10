package auth

import (
	"context"
	"errors"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

var (
	ErrInvalidAuthRequest = errors.New("invalid auth request")
	ErrAmbiguousIDPConfig = errors.New("ambiguous idp auth config")
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

type IDPFinder interface {
	FindIDPAuth(ctx context.Context, auths []*domain.Auth, token string) (*domain.Auth, error)
}

var _ IDPFinder = (*idpFinder)(nil)

type idpFinder struct {
	verifier IDPVerifier
}

func NewIDPFinder(verifier IDPVerifier) IDPFinder {
	return &idpFinder{verifier: verifier}
}

func (f *idpFinder) FindIDPAuth(_ context.Context, auths []*domain.Auth, token string) (*domain.Auth, error) {
	hints, err := f.verifier.Peek(token)
	if err != nil {
		return nil, err
	}
	matches := make([]*domain.Auth, 0, len(auths))
	for _, a := range auths {
		if a == nil || !a.Enabled || a.Type != domain.TypeIDP || a.Config.IDP == nil {
			continue
		}
		if idpConfigMatchesHints(*a.Config.IDP, hints) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return nil, domain.ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, ErrAmbiguousIDPConfig
	}
}

func idpConfigMatchesHints(cfg domain.IDPConfig, hints TokenHints) bool {
	if cfg.Issuer != "" && hints.Issuer != "" && cfg.Issuer != hints.Issuer {
		return false
	}
	if len(cfg.Audiences) == 0 || len(hints.Audiences) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(cfg.Audiences))
	for _, audience := range cfg.Audiences {
		allowed[audience] = struct{}{}
	}
	for _, audience := range hints.Audiences {
		if _, ok := allowed[audience]; ok {
			return true
		}
	}
	return false
}
