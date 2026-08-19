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

package oauth

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"time"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/golang-jwt/jwt/v5"
)

const (
	grantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer" // #nosec G101 -- OAuth grant type URN, not a credential
	idJAGTyp       = "oauth-id-jag+jwt"
	emaExtension   = "io.modelcontextprotocol/enterprise-managed-authorization"
)

type idjagResult struct {
	subject string
	scopes  []string
	claims  map[string]any
	jti     string
	exp     time.Time
}

func (p *authProxy) validateIDJAG(ctx context.Context, baseURL string, auth *authdomain.Auth, req TokenRequest) (*idjagResult, error) {
	cfg := auth.Config.OAuth2
	deny := func(reason string) (*idjagResult, error) {
		logEMADeny(auth.ID.String(), auth.GatewayID.String(), reason)
		return nil, oauthErr("invalid_grant", "invalid assertion")
	}

	typ, alg := jwtHeader(req.Assertion)
	if !strings.EqualFold(typ, idJAGTyp) {
		return deny("typ")
	}
	if algNoneOrHMAC(alg) {
		return deny("alg")
	}
	if p.verifier == nil {
		return deny("verifier")
	}

	hints, err := p.verifier.Peek(req.Assertion)
	if err != nil {
		return deny("peek")
	}
	if algNoneOrHMAC(hints.Algorithm) {
		return deny("alg")
	}
	if !IssuersEqual(hints.Issuer, cfg.Issuer) {
		return deny("iss")
	}

	jwksURL, err := p.configuredJWKSURL(ctx, cfg)
	if err != nil {
		return deny("jwks")
	}

	verified, err := p.verifier.Verify(ctx, req.Assertion, authdomain.OIDCConfig{
		Issuer:            hints.Issuer,
		Audiences:         []string{baseURL},
		JWKSURL:           jwksURL,
		AllowedAlgorithms: cfg.Algorithms,
		SubjectClaim:      strings.TrimSpace(cfg.SubjectClaim),
	})
	if err != nil {
		return deny("verify")
	}

	if !resourceMatches(verified.Claims["resource"], req.Resource) {
		return deny("resource")
	}
	scopes := verified.Scopes
	if !scopesSubset(scopes, cfg.RequiredScopes) {
		return deny("scope")
	}
	if _, ok := verified.Claims["iat"]; !ok {
		return deny("iat")
	}
	clientClaim := coerceClaim(verified.Claims["client_id"])
	if clientClaim == "" || clientClaim != req.ClientID {
		return deny("client_id")
	}
	jti := coerceClaim(verified.Claims["jti"])
	if jti == "" {
		return deny("jti")
	}
	exp, err := jwt.MapClaims(verified.Claims).GetExpirationTime()
	if err != nil || exp == nil || !exp.After(time.Now()) {
		return deny("exp")
	}
	if nbf, nbfErr := jwt.MapClaims(verified.Claims).GetNotBefore(); nbfErr == nil && nbf != nil && nbf.After(time.Now()) {
		return deny("nbf")
	}

	sub := emaSubject(cfg, verified.Claims)
	if sub == "" {
		return deny("sub")
	}

	logEMAAccept(auth.ID.String(), auth.GatewayID.String(), jti)
	return &idjagResult{
		subject: sub,
		scopes:  scopes,
		claims:  verified.Claims,
		jti:     jti,
		exp:     exp.Time,
	}, nil
}

func emaSubject(cfg *authdomain.OAuth2Config, claims map[string]any) string {
	if cfg != nil {
		if claim := strings.TrimSpace(cfg.SubjectClaim); claim != "" {
			return coerceClaim(claims[claim])
		}
	}
	return coerceClaim(claims["sub"])
}

func (p *authProxy) configuredJWKSURL(ctx context.Context, cfg *authdomain.OAuth2Config) (string, error) {
	if u := strings.TrimSpace(cfg.JWKSURL); u != "" {
		if !isHTTPSURL(u) {
			return "", errNotHTTPSJWKS
		}
		return u, nil
	}
	if p.idp == nil || p.idp.meta == nil {
		return "", errNotHTTPSJWKS
	}
	doc, err := p.idp.meta.fetchASMetadata(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}
	jwks, _ := doc["jwks_uri"].(string)
	if !isHTTPSURL(jwks) {
		return "", errNotHTTPSJWKS
	}
	return jwks, nil
}

var errNotHTTPSJWKS = oauthErr("invalid_grant", "jwks is not https")

func jwtHeader(raw string) (typ, alg string) {
	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil || parsed == nil {
		return "", ""
	}
	typ, _ = parsed.Header["typ"].(string)
	if parsed.Method != nil {
		alg = parsed.Method.Alg()
	}
	return typ, alg
}

func algNoneOrHMAC(alg string) bool {
	upper := strings.ToUpper(strings.TrimSpace(alg))
	return upper == "NONE" || strings.HasPrefix(upper, "HS")
}

func resourceMatches(claim any, want string) bool {
	if want == "" {
		return false
	}
	switch v := claim.(type) {
	case string:
		return v == want
	case []string:
		for _, r := range v {
			if r == want {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func scopesSubset(got, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allow[s] = struct{}{}
	}
	for _, s := range got {
		if identity.IsProtocolScope(s) {
			continue
		}
		if _, ok := allow[s]; !ok {
			return false
		}
	}
	return true
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func logEMAAccept(authID, gatewayID, jti string) {
	slog.Info("oauth.ema.accept",
		"auth_id", authID,
		"gateway_id", gatewayID,
		"jti", jti,
	)
}

func logEMADeny(authID, gatewayID, reason string) {
	slog.Warn("oauth.ema.deny",
		"auth_id", authID,
		"gateway_id", gatewayID,
		"reason", reason,
	)
}
