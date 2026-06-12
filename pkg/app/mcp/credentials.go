package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/vault"
)

// ErrNoPrincipal: the target's auth mode needs a user identity that the
// inbound credential (api_key / machine token) does not carry.
var ErrNoPrincipal = errors.New("mcp: downstream auth mode requires an authenticated user identity")

// ErrAudienceMismatch enforces the passthrough guardrail: forwarding a token
// minted for a different audience is the MCP confused-deputy anti-pattern.
var ErrAudienceMismatch = errors.New("mcp: inbound token audience does not match the upstream's expected audience")

// ConsentRequiredError surfaces the elicitation URL: the user must link a
// third-party account before the forwarded upstream can be reached.
type ConsentRequiredError struct {
	Provider string
	Ticket   string
	Path     string
}

func (e *ConsentRequiredError) Error() string {
	return fmt.Sprintf("user consent required to connect provider %q", e.Provider)
}

// CredentialResolver injects the downstream credential for one upstream MCP
// target, per its auth mode (Phase 4: passthrough/exchange/forwarded; the
// basic none/static modes are inlined in Target()).
//
//go:generate mockery --name=CredentialResolver --dir=. --output=./mocks --filename=mcp_credential_resolver_mock.go --case=underscore --with-expecter
type CredentialResolver interface {
	Apply(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error
}

var _ CredentialResolver = (*credentialResolver)(nil)

type credentialResolver struct {
	exchanger sts.Exchanger
	vault     vaultdomain.Repository
	connect   appoauth.ConnectService
	provider  *appoauth.ProviderClient
}

func NewCredentialResolver(
	exchanger sts.Exchanger,
	vault vaultdomain.Repository,
	connect appoauth.ConnectService,
	provider *appoauth.ProviderClient,
) CredentialResolver {
	return &credentialResolver{exchanger: exchanger, vault: vault, connect: connect, provider: provider}
}

// vaultRefreshSkew refreshes vaulted tokens slightly before expiry.
const vaultRefreshSkew = 60 * time.Second

func (r *credentialResolver) Apply(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error {
	cfg := reg.MCPTarget.Auth
	if cfg == nil {
		return nil
	}
	switch cfg.Mode {
	case registrydomain.MCPAuthModeNone, registrydomain.MCPAuthModeStatic, "":
		return nil // handled in Target()
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
	if !hasAudience(principal, cfg.ExpectedAudience) {
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
	// Strict per-principal isolation: the cache key pins subject + target +
	// gateway so one user's token can never serve another's call.
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
		// RefreshAuth resolves the effective client: the manual app, or the
		// DCR-registered one plus discovered endpoints in auto mode.
		refreshCfg, err := r.connect.RefreshAuth(ctx, gatewayID, reg)
		if err != nil {
			return r.consentRequired(ctx, rc, cfg.Provider, principal.Subject)
		}
		fresh, err := r.provider.Refresh(ctx, refreshCfg, cred.RefreshToken)
		if err != nil {
			// Refresh token revoked upstream: back to consent.
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

// hasAudience checks the inbound token aud claim (string or array) against
// the configured expected audience.
func hasAudience(p *identity.Principal, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	switch aud := p.Claims["aud"].(type) {
	case string:
		return aud == expected
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, a := range aud {
			if a == expected {
				return true
			}
		}
	}
	return false
}
