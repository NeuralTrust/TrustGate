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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

// RevocationAuthSource builds the OAuth client a refresh would present and the
// revocation endpoint from that same authorization server. *appoauth's connect
// service implements it via RefreshAuth.
type RevocationAuthSource interface {
	RevocationMaterial(ctx context.Context, gatewayID ids.GatewayID, principalSub string, reg *registrydomain.Registry) (*appoauth.RevocationMaterial, error)
}

// TokenRevoker asks an upstream authorization server to revoke a per-user
// OAuth token at the RFC 7009 revocation endpoint of the token endpoint the
// credential's refresh would use.
type TokenRevoker struct {
	auth RevocationAuthSource
	http *http.Client
}

// NewTokenRevoker builds a revoker. A nil client uses the guarded outbound
// client. Revoke returns nil when the provider does not advertise a revocation
// endpoint on the same https origin as its token endpoint.
func NewTokenRevoker(auth RevocationAuthSource, client *http.Client) *TokenRevoker {
	if client == nil {
		client = netguard.NewHTTPClient(15 * time.Second)
	}
	return &TokenRevoker{auth: auth, http: client}
}

// Revoke revokes the credential's refresh token when it has one, and its
// access token when that is a different value. It presents the client a
// refresh would, and only to a revocation endpoint with the same origin as
// that refresh's token endpoint. The error never includes token material.
func (r *TokenRevoker) Revoke(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	cred *vaultdomain.Credential,
) error {
	if r == nil || cred == nil {
		return nil
	}
	if r.auth == nil {
		return errors.New("oauth revoke: no auth")
	}
	material, err := r.auth.RevocationMaterial(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return fmt.Errorf("oauth revoke: auth: %w", err)
	}
	endpoint, ok, err := revocationEndpoint(material)
	if err != nil || !ok {
		return err
	}
	var errs []error
	if cred.RefreshToken != "" {
		if err := r.postRevoke(ctx, endpoint, cred.RefreshToken, "refresh_token", material.ClientID, material.ClientSecret, material.TokenEndpointAuthMethod); err != nil {
			errs = append(errs, err)
		}
	}
	if cred.AccessToken != "" && cred.AccessToken != cred.RefreshToken {
		if err := r.postRevoke(ctx, endpoint, cred.AccessToken, "access_token", material.ClientID, material.ClientSecret, material.TokenEndpointAuthMethod); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// revocationEndpoint returns the URL to POST to. ok is false when there is
// nothing to call (no endpoint configured, or it is not the token endpoint's
// origin). http is refused unless the operator escape hatch allows private
// networks.
func revocationEndpoint(material *appoauth.RevocationMaterial) (endpoint string, ok bool, err error) {
	if material == nil {
		return "", false, nil
	}
	endpoint = strings.TrimSpace(material.RevocationEndpoint)
	if endpoint == "" {
		return "", false, nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return "", false, errors.New("oauth revoke: revocation endpoint is not an https url")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !netguard.AllowPrivate() {
			return "", false, errors.New("oauth revoke: revocation endpoint is not https")
		}
	default:
		return "", false, errors.New("oauth revoke: revocation endpoint is not an https url")
	}
	token, err := url.Parse(strings.TrimSpace(material.TokenURL))
	if err != nil || token.Hostname() == "" || !sameOrigin(parsed, token) {
		return "", false, nil
	}
	return endpoint, true, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(originHost(a), originHost(b))
}

func originHost(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}

func (r *TokenRevoker) postRevoke(ctx context.Context, endpoint, token, hint, clientID, secret, method string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", hint)
	var basicUser, basicPass string
	if secret != "" && method != registrydomain.TokenEndpointAuthClientSecretPost {
		basicUser, basicPass = clientID, secret
	} else if clientID != "" {
		form.Set("client_id", clientID)
		if secret != "" {
			form.Set("client_secret", secret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("oauth revoke: %s: %w", hint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	res, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("oauth revoke: %s: %w", hint, err)
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < http.StatusOK || res.StatusCode >= 300 {
		return fmt.Errorf("oauth revoke: %s: status %d", hint, res.StatusCode)
	}
	return nil
}
