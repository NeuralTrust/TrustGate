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

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"golang.org/x/sync/singleflight"
)

var ErrNoPrincipal = errors.New("mcp: downstream auth mode requires an authenticated user identity")

var ErrAudienceMismatch = errors.New("mcp: inbound token audience does not match the upstream's expected audience")

type ConsentRequiredError struct {
	Provider string
	Ticket   string
	Path     string
}

func (e *ConsentRequiredError) Error() string {
	return fmt.Sprintf("user consent required to connect provider %q", e.Provider)
}

//go:generate mockery --name=CredentialResolver --dir=. --output=./mocks --filename=mcp_credential_resolver_mock.go --case=underscore --with-expecter
type CredentialResolver interface {
	Apply(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error
}

var _ CredentialResolver = (*credentialResolver)(nil)

type credentialResolver struct {
	exchanger sts.Exchanger
	vault     vaultdomain.Repository
	connect   appoauth.ConnectService
	provider  appoauth.ProviderClient
	refresh   singleflight.Group
}

func NewCredentialResolver(
	exchanger sts.Exchanger,
	vault vaultdomain.Repository,
	connect appoauth.ConnectService,
	provider appoauth.ProviderClient,
) CredentialResolver {
	return &credentialResolver{exchanger: exchanger, vault: vault, connect: connect, provider: provider}
}

const vaultRefreshSkew = 60 * time.Second

func (r *credentialResolver) Apply(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error {
	cfg := reg.MCPTarget.Auth
	if cfg == nil {
		return nil
	}
	switch cfg.Mode {
	case registrydomain.MCPAuthModeNone, registrydomain.MCPAuthModeStatic, "":
		return nil
	case registrydomain.MCPAuthModePassthrough:
		return r.passthrough(ctx, cfg, target)
	case registrydomain.MCPAuthModeExchange:
		return r.exchange(ctx, rc, reg, cfg, target)
	case registrydomain.MCPAuthModeForwarded:
		return r.forwarded(ctx, rc, reg, target)
	default:
		return fmt.Errorf("mcp: unknown downstream auth mode %q", cfg.Mode)
	}
}

func (r *credentialResolver) passthrough(ctx context.Context, cfg *registrydomain.MCPAuth, target *Target) error {
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.RawToken == "" {
		return ErrNoPrincipal
	}
	if !principal.HasAudience(cfg.ExpectedAudience) {
		return ErrAudienceMismatch
	}
	setAuthorization(target, "Bearer "+principal.RawToken)
	return nil
}

func (r *credentialResolver) exchange(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, cfg *registrydomain.MCPAuth, target *Target) error {
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil {
		return ErrNoPrincipal
	}
	cacheKey := fmt.Sprintf("%s|%s|%s", principal.Subject, reg.ID, rc.Consumer.GatewayID)
	token, err := r.exchanger.Exchange(ctx, principal, rc.Consumer.GatewayID, cfg, cacheKey)
	if err != nil {
		return err
	}
	setAuthorization(target, token.TokenType+" "+token.AccessToken)
	return nil
}

func (r *credentialResolver) forwarded(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error {
	cfg := reg.MCPTarget.Auth
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil {
		return ErrNoPrincipal
	}
	gatewayID := rc.Consumer.GatewayID
	cred, err := r.vault.Find(ctx, gatewayID, principal.Subject, cfg.Provider)
	if errors.Is(err, vaultdomain.ErrNotFound) {
		return r.consentRequired(ctx, rc, cfg.Provider, principal.Subject)
	}
	if err != nil {
		return err
	}
	if cred.Expired(vaultRefreshSkew) {
		cred, err = r.refreshCredential(ctx, rc, reg, gatewayID, principal.Subject, cfg.Provider)
		if err != nil {
			return err
		}
	}
	setAuthorization(target, "Bearer "+cred.AccessToken)
	return nil
}

func (r *credentialResolver) refreshCredential(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	gatewayID ids.GatewayID,
	subject, provider string,
) (*vaultdomain.Credential, error) {
	key := gatewayID.String() + "|" + subject + "|" + provider
	v, err, _ := r.refresh.Do(key, func() (any, error) {
		cred, err := r.vault.Find(ctx, gatewayID, subject, provider)
		if err != nil {
			return nil, err
		}
		if !cred.Expired(vaultRefreshSkew) {
			return cred, nil
		}
		if cred.RefreshToken == "" {
			return nil, errGrantExhausted
		}
		refreshCfg, err := r.connect.RefreshAuth(ctx, gatewayID, reg)
		if err != nil {
			return nil, err
		}
		fresh, err := r.provider.Refresh(ctx, refreshCfg, cred.RefreshToken)
		if err != nil {
			return nil, err
		}
		cred.AccessToken = fresh.AccessToken
		if fresh.RefreshToken != "" {
			cred.RefreshToken = fresh.RefreshToken
		}
		cred.ExpiresAt = fresh.ExpiresAt
		if err := r.vault.Upsert(ctx, cred); err != nil {
			return nil, err
		}
		return cred, nil
	})
	if err != nil {
		if errors.Is(err, errGrantExhausted) || errors.Is(err, appoauth.ErrInvalidGrant) || errors.Is(err, vaultdomain.ErrNotFound) {
			return nil, r.consentRequired(ctx, rc, provider, subject)
		}
		return nil, err
	}
	cred, ok := v.(*vaultdomain.Credential)
	if !ok {
		return nil, errors.New("mcp credentials: unexpected singleflight result type")
	}
	return cred, nil
}

var errGrantExhausted = errors.New("mcp credentials: stored grant cannot be refreshed")

func (r *credentialResolver) consentRequired(ctx context.Context, rc *appconsumer.RoutableConsumer, provider, principalSub string) error {
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	ticket, err := r.connect.CreateTicket(ctx, rc.Consumer.GatewayID, principalSub, consumerPath)
	if err != nil {
		return err
	}
	return &ConsentRequiredError{Provider: provider, Ticket: ticket, Path: consumerPath}
}

func setAuthorization(target *Target, value string) {
	if target.Headers == nil {
		target.Headers = map[string]string{}
	}
	target.Headers["Authorization"] = value
}
