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

package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	cache *JWKSCache
	now   func() time.Time
}

type verificationKey struct {
	value any
}

func NewVerifier() appauth.OIDCVerifier {
	return &Verifier{
		cache: NewJWKSCache(nil, 5*time.Minute),
		now:   time.Now,
	}
}

func NewVerifierWithCache(cache *JWKSCache) *Verifier {
	return &Verifier{cache: cache, now: time.Now}
}

func (v *Verifier) Peek(token string) (appauth.TokenHints, error) {
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		return appauth.TokenHints{}, fmt.Errorf("%w: parse token hints", ErrInvalidToken)
	}
	audiences, _ := claims.GetAudience()
	issuer, _ := claims.GetIssuer()
	return appauth.TokenHints{
		Issuer:    issuer,
		Audiences: audiences,
		KeyID:     stringHeader(parsed, "kid"),
		Algorithm: parsed.Method.Alg(),
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, token string, cfg domain.OIDCConfig) (*appauth.VerifiedClaims, error) {
	headerToken, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: parse token", ErrInvalidToken)
	}
	if headerToken == nil || headerToken.Method == nil {
		return nil, fmt.Errorf("%w: signing method", ErrInvalidToken)
	}
	alg := headerToken.Method.Alg()
	if err := validateAlgorithm(alg, cfg.AllowedAlgorithms); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	kid := stringHeader(headerToken, "kid")

	candidates, err := v.keyCandidates(ctx, kid, alg, cfg, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	refreshed := false
	if len(candidates) == 0 && kid != "" && strings.TrimSpace(cfg.JWKSURL) != "" {
		candidates, err = v.keyCandidates(ctx, kid, alg, cfg, true)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		refreshed = true
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, ErrMissingKey)
	}

	verified, signatureFailure, err := v.verifyWithCandidates(token, cfg, candidates)
	if err == nil {
		return verified, nil
	}
	if signatureFailure && !refreshed && strings.TrimSpace(cfg.JWKSURL) != "" {
		candidates, refreshErr := v.keyCandidates(ctx, kid, alg, cfg, true)
		if refreshErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidToken, refreshErr)
		}
		if len(candidates) > 0 {
			verified, _, retryErr := v.verifyWithCandidates(token, cfg, candidates)
			if retryErr == nil {
				return verified, nil
			}
			err = retryErr
		}
	}
	return nil, err
}

func (v *Verifier) verifyWithCandidates(
	token string,
	cfg domain.OIDCConfig,
	candidates []verificationKey,
) (*appauth.VerifiedClaims, bool, error) {
	signatureFailure := false
	for _, candidate := range candidates {
		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
			if err := validateAlgorithm(t.Method.Alg(), cfg.AllowedAlgorithms); err != nil {
				return nil, err
			}
			return candidate.value, nil
		}, jwt.WithTimeFunc(v.now))
		if err != nil {
			if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
				signatureFailure = true
				continue
			}
			return nil, false, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		if parsed == nil || !parsed.Valid {
			signatureFailure = true
			continue
		}
		if err := v.validateClaims(claims, cfg); err != nil {
			return nil, false, err
		}
		claimMap := map[string]any(claims)
		subject, err := subjectFromClaims(claimMap, cfg.SubjectClaim)
		if err != nil {
			return nil, false, err
		}
		scopes := scopesFromClaims(claimMap)
		return &appauth.VerifiedClaims{
			Subject: subject,
			Claims:  claimMap,
			Scopes:  scopes,
		}, false, nil
	}
	if signatureFailure {
		return nil, true, fmt.Errorf("%w: signature", ErrInvalidToken)
	}
	return nil, false, ErrInvalidToken
}

func (v *Verifier) keyCandidates(
	ctx context.Context,
	kid string,
	alg string,
	cfg domain.OIDCConfig,
	refreshJWKS bool,
) ([]verificationKey, error) {
	keys := make([]verificationKey, 0, len(cfg.PublicKeys)+1)
	includePublicKeys := kid == "" || strings.TrimSpace(cfg.JWKSURL) == ""
	if includePublicKeys {
		for _, raw := range cfg.PublicKeys {
			key, err := parsePEMPublicKey(raw)
			if err != nil {
				return nil, err
			}
			keys = append(keys, verificationKey{value: key})
		}
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return keys, nil
	}
	var (
		set    jwkSet
		err    error
		keyErr error
	)
	if refreshJWKS {
		set, err = v.cache.Refresh(ctx, cfg.JWKSURL)
	} else {
		set, err = v.cache.Get(ctx, cfg.JWKSURL)
	}
	if err != nil {
		return nil, err
	}
	for _, key := range set.Keys {
		if kid != "" && key.KeyID != kid {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != alg {
			continue
		}
		publicKey, err := key.publicKey()
		if err != nil {
			keyErr = err
			continue
		}
		keys = append(keys, verificationKey{value: publicKey})
	}
	if len(keys) == 0 && keyErr != nil {
		return nil, keyErr
	}
	return keys, nil
}

func (v *Verifier) validateClaims(claims jwt.MapClaims, cfg domain.OIDCConfig) error {
	issuer, err := claims.GetIssuer()
	if err != nil || issuer != cfg.Issuer {
		return fmt.Errorf("%w: issuer", ErrInvalidToken)
	}
	audiences, err := claims.GetAudience()
	if err != nil || !hasAudience(audiences, cfg.Audiences) {
		return fmt.Errorf("%w: audience", ErrInvalidToken)
	}
	expiresAt, err := claims.GetExpirationTime()
	if err != nil || expiresAt == nil || !v.now().Before(expiresAt.Time) {
		return fmt.Errorf("%w: exp", ErrInvalidToken)
	}
	notBefore, err := claims.GetNotBefore()
	if err == nil && notBefore != nil && v.now().Before(notBefore.Time) {
		return fmt.Errorf("%w: nbf", ErrInvalidToken)
	}
	if missing := missingScopes(scopesFromClaims(map[string]any(claims)), cfg.RequiredScopes); len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrMissingRequiredScope, strings.Join(missing, ","))
	}
	return nil
}

func validateAlgorithm(alg string, allowed []string) error {
	if strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return ErrUnsupportedAlg
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, value := range allowed {
		if strings.TrimSpace(value) == alg {
			return nil
		}
	}
	return ErrUnsupportedAlg
}

// hasAudience delegates to identity.AudienceMatches so Entra-style
// `api://<id>` resource URIs and bare client ids are treated as equivalent.
func hasAudience(actual []string, allowed []string) bool {
	return identity.AudienceMatches(actual, allowed)
}

func subjectFromClaims(claims map[string]any, subjectClaim string) (string, error) {
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	value, ok := claims[subjectClaim].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%w: subject", ErrInvalidToken)
	}
	return value, nil
}

func scopesFromClaims(claims map[string]any) []string {
	seen := map[string]struct{}{}
	add := func(scope string) {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			seen[scope] = struct{}{}
		}
	}
	for _, key := range []string{"scope", "scp", "scopes"} {
		switch value := claims[key].(type) {
		case string:
			for _, scope := range strings.Fields(value) {
				add(scope)
			}
		case []string:
			for _, scope := range value {
				add(scope)
			}
		case []any:
			for _, item := range value {
				if scope, ok := item.(string); ok {
					add(scope)
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for scope := range seen {
		out = append(out, scope)
	}
	return out
}

func missingScopes(actual []string, required []string) []string {
	actualSet := make(map[string]struct{}, len(actual))
	for _, scope := range actual {
		actualSet[scope] = struct{}{}
	}
	missing := make([]string, 0)
	for _, scope := range required {
		if _, ok := actualSet[scope]; !ok {
			missing = append(missing, scope)
		}
	}
	return missing
}

func stringHeader(t *jwt.Token, key string) string {
	value, _ := t.Header[key].(string)
	return value
}
