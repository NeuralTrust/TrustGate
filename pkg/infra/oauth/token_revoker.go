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

// TokenRevoker asks an upstream authorization server to revoke a per-user
// OAuth token at the RFC 7009 revocation_endpoint from its metadata.
type TokenRevoker struct {
	registrar appoauth.UpstreamRegistrar
	http      *http.Client
}

// NewTokenRevoker builds a revoker. A nil client uses the guarded outbound
// client. A provider that does not advertise revocation_endpoint is unsupported
// and Revoke returns nil.
func NewTokenRevoker(registrar appoauth.UpstreamRegistrar, client *http.Client) *TokenRevoker {
	if client == nil {
		client = netguard.NewHTTPClient(15 * time.Second)
	}
	return &TokenRevoker{registrar: registrar, http: client}
}

// Revoke revokes the credential's refresh token when it has one, and its
// access token when that is a different value. It reads a cached dynamic
// client and does not register or delete one. The error never includes token
// material.
func (r *TokenRevoker) Revoke(
	ctx context.Context,
	gatewayID ids.GatewayID,
	_ string,
	reg *registrydomain.Registry,
	cred *vaultdomain.Credential,
) error {
	if r == nil || cred == nil {
		return nil
	}
	if r.registrar == nil {
		return errors.New("oauth revoke: no registrar")
	}
	upstream, err := revokeUpstreamURL(reg)
	if err != nil {
		return err
	}
	meta, err := r.registrar.Discover(ctx, upstream)
	if err != nil {
		return fmt.Errorf("oauth revoke: discover: %w", err)
	}
	if meta == nil || strings.TrimSpace(meta.RevocationEndpoint) == "" {
		return nil
	}
	endpoint := strings.TrimSpace(meta.RevocationEndpoint)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return errors.New("oauth revoke: revocation endpoint is not an http(s) url")
	}
	clientID, secret, method := r.clientAuth(ctx, gatewayID, reg)
	var errs []error
	if cred.RefreshToken != "" {
		if err := r.postRevoke(ctx, endpoint, cred.RefreshToken, "refresh_token", clientID, secret, method); err != nil {
			errs = append(errs, err)
		}
	}
	if cred.AccessToken != "" && cred.AccessToken != cred.RefreshToken {
		if err := r.postRevoke(ctx, endpoint, cred.AccessToken, "access_token", clientID, secret, method); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *TokenRevoker) clientAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (clientID, secret, method string) {
	cfg := reg.ForwardedAuth()
	if cfg == nil {
		return "", "", ""
	}
	clientID = cfg.ClientID
	secret = cfg.ClientSecret
	method = cfg.TokenEndpointAuthMethod
	if cfg.Registration != registrydomain.RegistrationAuto {
		return clientID, secret, method
	}
	// Same key as appoauth.clientKey. Read only: uninstall must not register
	// a new client or drop the one a refresh token was issued to.
	key := gatewayID.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
	cached, err := r.registrar.CachedClient(ctx, key)
	if err != nil || cached == nil {
		return clientID, secret, method
	}
	if cached.ClientID != "" {
		clientID = cached.ClientID
	}
	if cached.ClientSecret != "" {
		secret = cached.ClientSecret
	}
	return clientID, secret, method
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

func revokeUpstreamURL(reg *registrydomain.Registry) (string, error) {
	if reg == nil || reg.MCPTarget == nil {
		return "", errors.New("oauth revoke: registry has no upstream url")
	}
	raw := strings.TrimSpace(reg.MCPTarget.URL)
	if reg.MCPTarget.HasURLVariables() {
		resolved, err := registrydomain.ResolveURL(reg.MCPTarget.URL, reg.MCPTarget.URLVariables, reg.MCPTarget.InstanceConfig)
		if err != nil {
			return "", fmt.Errorf("oauth revoke: resolve upstream url: %w", err)
		}
		if err := registrydomain.ValidateResolvedUpstreamHost(resolved); err != nil {
			return "", fmt.Errorf("oauth revoke: %w", err)
		}
		raw = resolved
	}
	if raw == "" {
		return "", errors.New("oauth revoke: registry has no upstream url")
	}
	return raw, nil
}
