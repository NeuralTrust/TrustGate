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

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

var (
	ErrInvalidAuthRequest  = errors.New("invalid auth request")
	ErrAmbiguousOIDCConfig = errors.New("ambiguous oidc auth config")
)

//go:generate mockery --name=OIDCFinder --dir=. --output=./mocks --filename=oidc_finder_mock.go --case=underscore --with-expecter
type OIDCFinder interface {
	FindOIDCAuth(ctx context.Context, auths []*domain.Auth, token string) (*domain.Auth, error)
}

var _ OIDCFinder = (*oidcFinder)(nil)

type oidcFinder struct {
	verifier OIDCVerifier
}

func NewOIDCFinder(verifier OIDCVerifier) OIDCFinder {
	return &oidcFinder{verifier: verifier}
}

func (f *oidcFinder) FindOIDCAuth(_ context.Context, auths []*domain.Auth, token string) (*domain.Auth, error) {
	hints, err := f.verifier.Peek(token)
	if err != nil {
		return nil, err
	}
	matches := make([]*domain.Auth, 0, len(auths))
	for _, a := range auths {
		if a == nil || !a.Enabled || a.Type != domain.TypeOIDC || a.Config.OIDC == nil {
			continue
		}
		if oidcConfigMatchesHints(*a.Config.OIDC, hints) {
			matches = append(matches, a)
		}
	}
	switch len(matches) {
	case 0:
		return nil, domain.ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, ErrAmbiguousOIDCConfig
	}
}

func oidcConfigMatchesHints(cfg domain.OIDCConfig, hints TokenHints) bool {
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
