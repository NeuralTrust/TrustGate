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

package config

import (
	stderrors "errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const (
	firewallJWTEnv     = "FIREWALL_JWT"
	firewallJWTIssuer  = "neuraltrust-console"
	firewallJWTType    = "firewall-client"
	firewallBaseURLEnv = "FIREWALL_BASE_URL"
)

type firewallJWTClaims struct {
	jwt.RegisteredClaims
	Type         string `json:"typ"`
	URL          string `json:"url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // #nosec G117 -- claim field, not a hardcoded credential
}

// parseFirewallJWT checks the HS256 signature with the token's own client_secret
// (integrity only, not authorization). Errors never carry the token or claim values.
func parseFirewallJWT(raw string) (*firewallJWTClaims, error) {
	bad := func(msg string) error {
		return fmt.Errorf("%w: %s %s", errors.ErrInvalidConfig, firewallJWTEnv, msg)
	}
	claims := &firewallJWTClaims{}
	unverified, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	if err != nil {
		return nil, bad("is malformed: expected a signed JWT")
	}
	if unverified.Method.Alg() != jwt.SigningMethodHS256.Alg() {
		return nil, bad("uses an unsupported signing algorithm: only HS256 is accepted")
	}
	if claims.ClientSecret == "" {
		return nil, bad("is missing the client_secret claim")
	}
	verified := &firewallJWTClaims{}
	_, err = jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})).ParseWithClaims(raw, verified,
		func(*jwt.Token) (any, error) { return []byte(claims.ClientSecret), nil })
	switch {
	case stderrors.Is(err, jwt.ErrTokenExpired):
		return nil, bad("has expired")
	case stderrors.Is(err, jwt.ErrTokenSignatureInvalid):
		return nil, bad("has an invalid signature: the value was truncated or edited, copy it again from the console")
	case err != nil:
		return nil, bad("could not be verified")
	}
	if verified.Issuer != firewallJWTIssuer {
		return nil, bad("has the wrong issuer: expected " + firewallJWTIssuer)
	}
	if verified.Type != firewallJWTType {
		return nil, bad("has the wrong typ claim: expected " + firewallJWTType)
	}
	if verified.ClientID == "" {
		return nil, bad("is missing the client_id claim")
	}
	if u, perr := url.Parse(verified.URL); perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, bad("has an invalid url claim: expected an absolute http(s) URL")
	}
	return verified, nil
}

func unquoteEnv(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	return v
}

// applyFirewallJWT switches the complexity config to the OAuth client in
// FIREWALL_JWT. An invalid token is recorded rather than returned so the
// gateway still starts; scoring then fails with that error.
func (c *FirewallComplexityConfig) applyFirewallJWT(raw string) {
	c.JWTSet = true
	claims, err := parseFirewallJWT(raw)
	if err != nil {
		c.JWTError = err
		return
	}
	c.ClientID = claims.ClientID
	c.ClientSecret = claims.ClientSecret
	if strings.TrimSpace(c.BaseURL) != "" {
		c.BaseURLSource = firewallBaseURLEnv
		return
	}
	c.BaseURL = strings.TrimRight(claims.URL, "/")
	c.BaseURLSource = firewallJWTEnv
}
