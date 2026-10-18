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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func (s *connectService) effectiveAuth(ctx context.Context, baseURL string, gatewayID ids.GatewayID, principalSub string, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		effective := withIdentityScopes(applyCatalog(applySharedOAuth(cfg, reg, s.sharedOAuth), reg, s.catalog))
		if effective.AuthorizeURL != "" && effective.TokenURL != "" {
			return effective, nil
		}
		meta, err := s.discover(ctx, gatewayID, principalSub, reg)
		if err != nil {
			return nil, err
		}
		return withholdSharedSecret(manualAuth(effective, meta), reg, s.sharedOAuth), nil
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	slot, err := s.clientSlot(ctx, gatewayID, reg, meta)
	if err != nil {
		return nil, err
	}
	client, err := s.registrar.EnsureClient(ctx, slot, meta, connectCallbackURL(baseURL, cfg.Provider))
	if err != nil {
		return nil, err
	}
	return withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog), meta, client)), nil
}

// exchangeAuth builds the token-endpoint configuration for a code that was
// minted for clientID. It does not register a client: an in-flight callback
// must redeem the code with the client that started the flow.
func (s *connectService) exchangeAuth(
	ctx context.Context,
	baseURL string,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	clientID, clientSecret string,
) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto || clientID == "" {
		return s.effectiveAuth(ctx, baseURL, gatewayID, principalSub, reg)
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	used := &RegisteredClient{ClientID: clientID, ClientSecret: clientSecret}
	if clientSecret == "" {
		slot, slotErr := s.clientSlot(ctx, gatewayID, reg, meta)
		if slotErr != nil {
			return nil, slotErr
		}
		cached, cacheErr := s.registrar.CachedClient(ctx, slot)
		if cacheErr != nil {
			return nil, cacheErr
		}
		if cached != nil && cached.ClientID == clientID {
			used = cached
		}
	}
	return withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog), meta, used)), nil
}

func (s *connectService) RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	// A refresh runs on the dial path, as the principal the call is for.
	principalSub := ""
	if p := identity.PrincipalFromContext(ctx); p != nil {
		principalSub = p.Subject
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		effective := withIdentityScopes(applyCatalog(applySharedOAuth(cfg, reg, s.sharedOAuth), reg, s.catalog))
		if effective.AuthorizeURL != "" && effective.TokenURL != "" {
			return effective, nil
		}
		meta, err := s.discover(ctx, gatewayID, principalSub, reg)
		if err != nil {
			return nil, err
		}
		return withholdSharedSecret(manualAuth(effective, meta), reg, s.sharedOAuth), nil
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	slot, err := s.clientSlot(ctx, gatewayID, reg, meta)
	if err != nil {
		return nil, err
	}
	client, err := s.registrar.CachedClient(ctx, slot)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("%w: provider %q", ErrNoRegisteredClient, cfg.Provider)
	}
	return withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog), meta, client)), nil
}

func applySharedOAuth(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, shared mcpoauth.Provider) *registrydomain.MCPAuth {
	if cfg == nil {
		return cfg
	}
	creds, ok := mcpoauth.SharedClientFor(shared, sharedClientQuery(cfg, reg, false))
	if !ok {
		return cfg
	}
	out := *cfg
	out.ClientID = creds.ClientID
	out.ClientSecret = creds.ClientSecret
	return &out
}

// withholdSharedSecret drops the platform's shared client secret from a
// configuration whose endpoints were discovered rather than configured.
// applySharedOAuth accepts empty endpoints, so it cannot know where discovery
// will point; the secret only goes to the provider's own authorization server.
func withholdSharedSecret(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, shared mcpoauth.Provider) *registrydomain.MCPAuth {
	if cfg == nil || shared == nil || cfg.ClientSecret == "" {
		return cfg
	}
	creds, ok := shared.CredentialsFor(mcpoauth.SharedCode(registryCode(reg), cfg.Provider))
	if !ok || cfg.ClientSecret != creds.ClientSecret {
		return cfg
	}
	if _, allowed := mcpoauth.SharedClientFor(shared, sharedClientQuery(cfg, reg, true)); allowed {
		return cfg
	}
	out := *cfg
	out.ClientSecret = ""
	return &out
}

func sharedClientQuery(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, strict bool) mcpoauth.SharedClientQuery {
	return mcpoauth.SharedClientQuery{
		Code:         registryCode(reg),
		Provider:     cfg.Provider,
		ClientID:     cfg.ClientID,
		AuthorizeURL: cfg.AuthorizeURL,
		TokenURL:     cfg.TokenURL,
		Strict:       strict,
	}
}

func registryCode(reg *registrydomain.Registry) string {
	if reg == nil || reg.MCPTarget == nil {
		return ""
	}
	return reg.MCPTarget.Code
}

// applyCatalog lets the curated catalog correct the scopes and resource
// indicator persisted on a registry. Both registration paths need it: these are
// copied onto the registry when it is created, so a registry created against an
// older catalog keeps asking for scopes the upstream may since have dropped, or
// naming a resource its authorization server rejects with invalid_target (Axiom
// only accepts its root resource), and nothing else ever rewrites them.
func applyCatalog(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, cat authCatalog) *registrydomain.MCPAuth {
	if cfg == nil || cat == nil {
		return cfg
	}
	code := ""
	if reg != nil && reg.MCPTarget != nil {
		code = strings.TrimSpace(reg.MCPTarget.Code)
	}
	if code == "" {
		code = strings.TrimSpace(cfg.Provider)
	}
	entry, ok := cat.GetByCode(code)
	if !ok || entry.OAuth == nil {
		return cfg
	}
	resource := strings.TrimSpace(entry.OAuth.Resource)
	if len(entry.OAuth.Scopes) == 0 && resource == "" {
		return cfg
	}
	out := *cfg
	if len(entry.OAuth.Scopes) > 0 {
		out.Scopes = append([]string(nil), entry.OAuth.Scopes...)
	}
	if resource != "" {
		out.Resource = resource
	}
	return &out
}

func autoAuth(cfg *registrydomain.MCPAuth, meta *UpstreamAuthServer, client *RegisteredClient) *registrydomain.MCPAuth {
	out := *cfg
	out.ClientID = client.ClientID
	out.ClientSecret = client.ClientSecret
	out.AuthorizeURL = meta.AuthorizationEndpoint
	out.TokenURL = meta.TokenEndpoint
	out.UserinfoURL = meta.UserinfoEndpoint
	if len(out.Scopes) == 0 {
		out.Scopes = meta.ScopesSupported
	}
	if out.Resource == "" {
		out.Resource = meta.Resource
	}
	return &out
}

func manualAuth(cfg *registrydomain.MCPAuth, meta *UpstreamAuthServer) *registrydomain.MCPAuth {
	out := *cfg
	out.AuthorizeURL = meta.AuthorizationEndpoint
	out.TokenURL = meta.TokenEndpoint
	out.UserinfoURL = meta.UserinfoEndpoint
	if len(out.Scopes) == 0 {
		out.Scopes = meta.ScopesSupported
	}
	if out.Resource == "" {
		out.Resource = meta.Resource
	}
	return &out
}

// clientKey is the legacy cache key: the gateway plus the credential fingerprint
// (registrydomain.ForwardedVaultProvider), never the registry id.
//
// A refresh token can only be redeemed by the client it was issued to. Keyed by
// registry, two instances of one catalog code — the same provider, so one shared
// credential — each registered their own client, and whichever instance a call
// arrived through refreshed the other's token with the wrong client_id: the
// upstream answered invalid_grant and the user was told their session had
// expired while the connect page still said connected.
//
// The fingerprint is the URL template as written, so two principals who resolve
// it to different hosts would share one client. clientCacheKey adds the
// authorization server. Rows already stored under clientKey stay readable for
// the server they were registered with.
func clientKey(gatewayID ids.GatewayID, reg *registrydomain.Registry) string {
	return gatewayID.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
}

func clientCacheKey(gatewayID ids.GatewayID, reg *registrydomain.Registry, meta *UpstreamAuthServer) string {
	return clientKey(gatewayID, reg) + "|" + authorizationServerID(meta)
}

func authorizationServerID(meta *UpstreamAuthServer) string {
	identity := ""
	if meta != nil {
		identity = strings.TrimSpace(meta.Issuer)
		if identity == "" {
			identity = strings.TrimSpace(meta.RegistrationEndpoint)
		}
		if identity == "" {
			identity = strings.TrimSpace(meta.AuthorizationEndpoint)
		}
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

// clientSlot is the cache key a dynamic client is read and written under.
// A live client on the issuer-scoped key wins. Otherwise a row still stored
// under the legacy key is used when it was registered for this authorization
// server — including a row that records no server, which predates the binding
// and would strand every existing grant if it were treated as a mismatch.
func (s *connectService) clientSlot(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry, meta *UpstreamAuthServer) (string, error) {
	scoped := clientCacheKey(gatewayID, reg, meta)
	client, err := s.registrar.CachedClient(ctx, scoped)
	if err != nil || client != nil {
		return scoped, err
	}
	legacy := clientKey(gatewayID, reg)
	old, err := s.registrar.CachedClient(ctx, legacy)
	if err != nil {
		return scoped, err
	}
	if legacyRegistrationFor(old, meta) {
		return legacy, nil
	}
	return scoped, nil
}

// legacyRegistrationFor reports whether a client stored under the legacy key
// belongs to this authorization server. An issuer or registration endpoint
// left empty was stored before the binding existed and is not a mismatch.
func legacyRegistrationFor(cached *RegisteredClient, meta *UpstreamAuthServer) bool {
	if cached == nil || meta == nil {
		return false
	}
	if cached.Issuer != "" && cached.Issuer != meta.Issuer {
		return false
	}
	if cached.RegistrationEndpoint != "" && cached.RegistrationEndpoint != meta.RegistrationEndpoint {
		return false
	}
	return true
}

// DropRegisteredClient marks the cached dynamic client the token endpoint
// rejected unusable, when that client_id is still the one stored. The
// issuer-scoped key and the legacy key are both considered; a row for a
// different client is left alone.
func (s *connectService) DropRegisteredClient(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry, clientID string) error {
	if s == nil || s.registrar == nil || reg == nil || clientID == "" {
		return nil
	}
	principalSub := ""
	if p := identity.PrincipalFromContext(ctx); p != nil {
		principalSub = p.Subject
	}
	var dropErr error
	meta, err := s.discover(ctx, gatewayID, principalSub, reg)
	if err != nil {
		dropErr = err
	} else if err := s.registrar.DropCachedClient(ctx, clientCacheKey(gatewayID, reg, meta), clientID); err != nil {
		dropErr = err
	}
	if err := s.registrar.DropCachedClient(ctx, clientKey(gatewayID, reg), clientID); err != nil && dropErr == nil {
		dropErr = err
	}
	return dropErr
}

// CredentialUsable reports whether a credential stored for this registry can
// still be redeemed — everything the refresh needs beyond the credential
// itself.
//
// For a dynamically registered client that means the registration: the refresh
// token was issued to it and cannot be redeemed without it, and it lives in the
// shared cache while the credential lives in the vault, so the credential
// outlives it whenever that cache is lost. Until this was checked, the Portal
// and the connect page read the vault alone and called such an account
// connected while every tool call was refused with "user consent required".
//
// A registry whose client is configured (not registered on the fly) has nothing
// that can go missing here, and neither has one that forwards no credential.
// A lookup that fails answers "usable": a cache blip must not tell every user
// to reconnect.
func (s *connectService) CredentialUsable(
	ctx context.Context,
	gatewayID ids.GatewayID,
	reg *registrydomain.Registry,
) (bool, error) {
	return s.credentialUsable(ctx, gatewayID, principalFromContext(ctx), reg)
}

func (s *connectService) credentialUsable(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (bool, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil || cfg.Registration != registrydomain.RegistrationAuto || s.registrar == nil {
		return true, nil
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return true, err
	}
	slot, err := s.clientSlot(ctx, gatewayID, reg, meta)
	if err != nil {
		return true, err
	}
	client, err := s.registrar.CachedClient(ctx, slot)
	if err != nil {
		return true, err
	}
	return client != nil, nil
}

func principalFromContext(ctx context.Context) string {
	if p := identity.PrincipalFromContext(ctx); p != nil {
		return p.Subject
	}
	return ""
}
