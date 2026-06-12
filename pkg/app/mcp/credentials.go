package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
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
	token, err := r.exchanger.Exchange(ctx, principal, cfg, cacheKey)
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
		if cred.RefreshToken == "" {
			return r.consentRequired(ctx, rc, cfg.Provider, principal.Subject)
		}
		refreshCfg, err := r.connect.RefreshAuth(ctx, gatewayID, reg)
		if err != nil {
			return r.consentRequired(ctx, rc, cfg.Provider, principal.Subject)
		}
		fresh, err := r.provider.Refresh(ctx, refreshCfg, cred.RefreshToken)
		if err != nil {
			return r.consentRequired(ctx, rc, cfg.Provider, principal.Subject)
		}
		cred.AccessToken = fresh.AccessToken
		if fresh.RefreshToken != "" {
			cred.RefreshToken = fresh.RefreshToken
		}
		cred.ExpiresAt = fresh.ExpiresAt
		if err := r.vault.Upsert(ctx, cred); err != nil {
			return err
		}
	}
	setAuthorization(target, "Bearer "+cred.AccessToken)
	return nil
}

func (r *credentialResolver) consentRequired(ctx context.Context, rc *appconsumer.RoutableConsumer, provider, principalSub string) error {
	ticket, err := r.connect.CreateTicket(ctx, rc.Consumer.GatewayID, principalSub, rc.Consumer.Path)
	if err != nil {
		return err
	}
	return &ConsentRequiredError{Provider: provider, Ticket: ticket, Path: rc.Consumer.Path}
}

func setAuthorization(target *Target, value string) {
	if target.Headers == nil {
		target.Headers = map[string]string{}
	}
	target.Headers["Authorization"] = value
}
