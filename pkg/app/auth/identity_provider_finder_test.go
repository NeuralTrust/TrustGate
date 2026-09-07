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

package auth_test

import (
	"context"
	"errors"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const candidateToken = "header.payload.signature"

func oauth2IdP(name, issuer string, audiences []string) *domain.Auth {
	return &domain.Auth{
		ID:      ids.New[ids.AuthKind](),
		Name:    name,
		Type:    domain.TypeOAuth2,
		Enabled: true,
		Config: domain.Config{
			OAuth2: &domain.OAuth2Config{Issuer: issuer, Audiences: audiences},
		},
	}
}

func oidcIdP(name, issuer string, audiences []string) *domain.Auth {
	return &domain.Auth{
		ID:      ids.New[ids.AuthKind](),
		Name:    name,
		Type:    domain.TypeOIDC,
		Enabled: true,
		Config: domain.Config{
			OIDC: &domain.OIDCConfig{Issuer: issuer, Audiences: audiences},
		},
	}
}

func oidcIdPWithPublicKeys(name, issuer string, audiences, publicKeys []string) *domain.Auth {
	a := oidcIdP(name, issuer, audiences)
	a.Config.OIDC.PublicKeys = publicKeys
	return a
}

func candidateNames(auths []*domain.Auth) []string {
	names := make([]string, 0, len(auths))
	for _, a := range auths {
		names = append(names, a.Name)
	}
	return names
}

func equalNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestIdentityProviderFinder_FindCandidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		auths     []*domain.Auth
		hints     appauth.TokenHints
		wantNames []string
	}{
		{
			name:      "no auths yields no candidates",
			auths:     nil,
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{},
		},
		{
			name:      "issuer mismatch excludes the only auth",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://other.example", Audiences: []string{"client-id"}},
			wantNames: []string{},
		},
		{
			name:      "audience mismatch excludes the only auth",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"another-client"}},
			wantNames: []string{},
		},
		{
			name:      "single matching auth is the only candidate",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"entra"},
		},
		{
			name: "several matching auths keep declaration order",
			auths: []*domain.Auth{
				oauth2IdP("first", "https://issuer.example", []string{"client-id"}),
				oauth2IdP("second", "https://issuer.example", []string{"client-id"}),
				oauth2IdP("third", "https://issuer.example", []string{"client-id"}),
			},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"first", "second", "third"},
		},
		{
			name: "non matching auths are filtered out of an ordered set",
			auths: []*domain.Auth{
				oauth2IdP("other-issuer", "https://other.example", []string{"client-id"}),
				oauth2IdP("match", "https://issuer.example", []string{"client-id"}),
				oauth2IdP("other-audience", "https://issuer.example", []string{"another-client"}),
			},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"match"},
		},
		{
			name:      "empty configured audiences keeps the auth",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", nil)},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"entra"},
		},
		{
			name:      "empty token audiences keeps the auth",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example"},
			wantNames: []string{"entra"},
		},
		{
			name:      "empty configured issuer keeps the auth",
			auths:     []*domain.Auth{oauth2IdP("entra", "", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"entra"},
		},
		{
			name:      "empty token issuer keeps the auth",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Audiences: []string{"client-id"}},
			wantNames: []string{"entra"},
		},
		{
			name:      "resource uri token audience matches a bare identifier config",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"api://client-id"}},
			wantNames: []string{"entra"},
		},
		{
			name:      "bare token audience matches a resource uri config",
			auths:     []*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"api://client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"entra"},
		},
		{
			name:      "oidc shaped auth is selected",
			auths:     []*domain.Auth{oidcIdP("legacy-oidc", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"legacy-oidc"},
		},
		{
			name:      "oidc shaped auth matches a resource uri token audience",
			auths:     []*domain.Auth{oidcIdP("legacy-oidc", "https://issuer.example", []string{"client-id"})},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"api://client-id"}},
			wantNames: []string{"legacy-oidc"},
		},
		{
			name: "oidc shaped auth whose only key material is public keys is selected",
			auths: []*domain.Auth{oidcIdPWithPublicKeys(
				"air-gapped-oidc",
				"https://issuer.example",
				[]string{"client-id"},
				[]string{"-----BEGIN PUBLIC KEY-----"},
			)},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"air-gapped-oidc"},
		},
		{
			name: "oidc and oauth2 auths are both candidates in declaration order",
			auths: []*domain.Auth{
				oidcIdP("legacy-oidc", "https://issuer.example", []string{"client-id"}),
				oauth2IdP("unified", "https://issuer.example", []string{"client-id"}),
			},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"legacy-oidc", "unified"},
		},
		{
			name: "disabled nil and non identity provider auths are skipped",
			auths: []*domain.Auth{
				nil,
				disable(oauth2IdP("disabled", "https://issuer.example", []string{"client-id"})),
				{
					ID:      ids.New[ids.AuthKind](),
					Name:    "api-key",
					Type:    domain.TypeAPIKey,
					Enabled: true,
				},
				{
					ID:      ids.New[ids.AuthKind](),
					Name:    "configless-oauth2",
					Type:    domain.TypeOAuth2,
					Enabled: true,
				},
				oauth2IdP("enabled", "https://issuer.example", []string{"client-id"}),
			},
			hints:     appauth.TokenHints{Issuer: "https://issuer.example", Audiences: []string{"client-id"}},
			wantNames: []string{"enabled"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verifier := authmocks.NewOIDCVerifier(t)
			verifier.EXPECT().Peek(candidateToken).Return(tt.hints, nil).Once()

			finder := appauth.NewIdentityProviderFinder(verifier)
			got, err := finder.FindCandidates(context.Background(), tt.auths, candidateToken)
			if err != nil {
				t.Fatalf("FindCandidates: unexpected error %v", err)
			}
			if names := candidateNames(got); !equalNames(names, tt.wantNames) {
				t.Fatalf("FindCandidates candidates = %v, want %v", names, tt.wantNames)
			}
		})
	}
}

func disable(a *domain.Auth) *domain.Auth {
	a.Enabled = false
	return a
}

func TestIdentityProviderFinder_PeekFailurePropagates(t *testing.T) {
	t.Parallel()
	errPeek := errors.New("token is not a parseable jwt")
	verifier := authmocks.NewOIDCVerifier(t)
	verifier.EXPECT().Peek(candidateToken).Return(appauth.TokenHints{}, errPeek).Once()

	finder := appauth.NewIdentityProviderFinder(verifier)
	got, err := finder.FindCandidates(
		context.Background(),
		[]*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
		candidateToken,
	)
	if !errors.Is(err, errPeek) {
		t.Fatalf("FindCandidates error = %v, want it to wrap %v", err, errPeek)
	}
	if got != nil {
		t.Fatalf("FindCandidates candidates = %v, want nil on peek failure", got)
	}
}

func TestIdentityProviderFinder_CancelledContextIsHonoured(t *testing.T) {
	t.Parallel()
	verifier := authmocks.NewOIDCVerifier(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	finder := appauth.NewIdentityProviderFinder(verifier)
	got, err := finder.FindCandidates(
		ctx,
		[]*domain.Auth{oauth2IdP("entra", "https://issuer.example", []string{"client-id"})},
		candidateToken,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FindCandidates error = %v, want context.Canceled", err)
	}
	if got != nil {
		t.Fatalf("FindCandidates candidates = %v, want nil on cancelled context", got)
	}
}

func TestIdentityProviderFinder_OIDCAuthIsProjectedWithoutMutatingInput(t *testing.T) {
	t.Parallel()
	verifier := authmocks.NewOIDCVerifier(t)
	verifier.EXPECT().Peek(candidateToken).Return(appauth.TokenHints{
		Issuer:    "https://issuer.example",
		Audiences: []string{"client-id"},
	}, nil).Once()

	stored := &domain.Auth{
		ID:      ids.New[ids.AuthKind](),
		Name:    "legacy-oidc",
		Type:    domain.TypeOIDC,
		Enabled: true,
		Config: domain.Config{
			OIDC: &domain.OIDCConfig{
				Issuer:            "https://issuer.example",
				Audiences:         []string{"client-id"},
				JWKSURL:           "https://issuer.example/jwks",
				RequiredScopes:    []string{"api.read"},
				AllowedAlgorithms: []string{"RS256"},
				SubjectClaim:      "oid",
			},
		},
	}

	finder := appauth.NewIdentityProviderFinder(verifier)
	got, err := finder.FindCandidates(context.Background(), []*domain.Auth{stored}, candidateToken)
	if err != nil {
		t.Fatalf("FindCandidates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindCandidates returned %d candidates, want 1", len(got))
	}
	if stored.Config.OAuth2 != nil {
		t.Fatal("FindCandidates mutated the stored auth config")
	}

	candidate := got[0]
	if candidate.ID != stored.ID {
		t.Fatalf("candidate id = %v, want %v", candidate.ID, stored.ID)
	}
	projected := candidate.Config.OAuth2
	if projected == nil {
		t.Fatal("candidate has no projected oauth2 config")
	}
	if projected.Issuer != "https://issuer.example" {
		t.Fatalf("projected issuer = %q", projected.Issuer)
	}
	if projected.JWKSURL != "https://issuer.example/jwks" {
		t.Fatalf("projected jwks url = %q", projected.JWKSURL)
	}
	if projected.SubjectClaim != "oid" {
		t.Fatalf("projected subject claim = %q", projected.SubjectClaim)
	}
	if !equalNames(projected.Audiences, []string{"client-id"}) {
		t.Fatalf("projected audiences = %v", projected.Audiences)
	}
	if !equalNames(projected.RequiredScopes, []string{"api.read"}) {
		t.Fatalf("projected required scopes = %v", projected.RequiredScopes)
	}
	if !equalNames(projected.Algorithms, []string{"RS256"}) {
		t.Fatalf("projected algorithms = %v", projected.Algorithms)
	}
}

func TestIdentityProviderFinder_ProjectionCarriesInlinePublicKeys(t *testing.T) {
	t.Parallel()
	verifier := authmocks.NewOIDCVerifier(t)
	verifier.EXPECT().Peek(candidateToken).Return(appauth.TokenHints{
		Issuer:    "https://issuer.example",
		Audiences: []string{"client-id"},
	}, nil).Once()

	stored := oidcIdPWithPublicKeys(
		"air-gapped-oidc",
		"https://issuer.example",
		[]string{"client-id"},
		[]string{"-----BEGIN PUBLIC KEY-----first", "-----BEGIN PUBLIC KEY-----second"},
	)

	finder := appauth.NewIdentityProviderFinder(verifier)
	got, err := finder.FindCandidates(context.Background(), []*domain.Auth{stored}, candidateToken)
	if err != nil {
		t.Fatalf("FindCandidates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindCandidates returned %d candidates, want 1", len(got))
	}
	if stored.Config.OAuth2 != nil {
		t.Fatal("FindCandidates mutated the stored auth config")
	}

	projected := got[0].Config.OAuth2
	if projected == nil {
		t.Fatal("candidate has no projected oauth2 config")
	}
	if projected.JWKSURL != "" {
		t.Fatalf("projected jwks url = %q, want empty", projected.JWKSURL)
	}
	want := []string{"-----BEGIN PUBLIC KEY-----first", "-----BEGIN PUBLIC KEY-----second"}
	if !equalNames(projected.PublicKeys, want) {
		t.Fatalf("projected public keys = %v, want %v", projected.PublicKeys, want)
	}
}

func TestIdentityProviderFinder_ReturnsStoredAuthWhenOAuth2ConfigPresent(t *testing.T) {
	t.Parallel()
	verifier := authmocks.NewOIDCVerifier(t)
	verifier.EXPECT().Peek(candidateToken).Return(appauth.TokenHints{
		Issuer:    "https://issuer.example",
		Audiences: []string{"client-id"},
	}, nil).Once()

	stored := oauth2IdP("unified", "https://issuer.example", []string{"client-id"})

	finder := appauth.NewIdentityProviderFinder(verifier)
	got, err := finder.FindCandidates(context.Background(), []*domain.Auth{stored}, candidateToken)
	if err != nil {
		t.Fatalf("FindCandidates: %v", err)
	}
	if len(got) != 1 || got[0] != stored {
		t.Fatalf("FindCandidates = %v, want the stored auth instance", got)
	}
}
