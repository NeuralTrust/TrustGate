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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/common/logref"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"golang.org/x/sync/singleflight"
)

var ErrNoPrincipal = errors.New("mcp: downstream auth mode requires an authenticated user identity")

// ErrUpstreamNeedsCallerToken: the upstream is configured to reuse the caller's
// own bearer token (passthrough, or an on-behalf-of / token-exchange), and this
// caller has none — it authenticated as the application itself, with an API key
// or a client certificate. Configuration, not something a retry fixes: give the
// upstream a credential of its own (static or client_credentials), link an
// account for the application (forwarded), or call this consumer with a token
// from an identity provider.
var ErrUpstreamNeedsCallerToken = errors.New(
	"mcp: this upstream reuses the caller's own token, but the caller authenticated as the application (api key or client certificate) and carries none; " +
		"give the upstream its own credential (static or client_credentials), link an account for the application (forwarded), or call this consumer with an identity-provider token")

var ErrAudienceMismatch = errors.New("mcp: inbound token audience does not match the upstream's expected audience")

type ConsentRequiredError struct {
	Provider string
	Ticket   string
	Path     string
	// Cause names the condition that produced the prompt, as one of the
	// ConsentCause codes. It travels with the refusal because "connect this
	// again" is not a diagnosis: a credential that was never linked, one the
	// vault key can no longer read, a refresh token the provider rejected and a
	// registered client that went missing all reach the user as the same
	// sentence, and telling them apart afterwards took the gateway's own logs.
	//
	// A code, not the log's prose: the prose names internals (an env var, a
	// flushed store) that a tenant's client has no use for.
	Cause string
}

// The conditions that make the gateway ask a user to connect. Stable strings:
// they are what a client reports and what an operator greps for.
const (
	// ConsentCauseNoCredential: this user never linked an account here.
	ConsentCauseNoCredential = "no_credential" // #nosec G101 -- OAuth cause code, not a secret
	// ConsentCauseUndecryptable: the credential is stored but cannot be read
	// with the current vault key.
	ConsentCauseUndecryptable = "credential_undecryptable"
	// ConsentCauseNoRefreshToken: the access token expired and the grant carries
	// nothing to refresh it with.
	ConsentCauseNoRefreshToken = "no_refresh_token"
	// ConsentCauseRefreshRejected: the provider refused the stored refresh token.
	ConsentCauseRefreshRejected = "refresh_rejected"
	// ConsentCauseRefreshAlreadyRejected: the same refresh token was refused
	// before and is not retried until the user reconnects.
	ConsentCauseRefreshAlreadyRejected = "refresh_already_rejected"
	// ConsentCauseCredentialVanished: the credential disappeared mid-refresh.
	ConsentCauseCredentialVanished = "credential_vanished" // #nosec G101 -- OAuth cause code, not a secret
	// ConsentCauseRegisteredClientLost: the dynamically registered OAuth client
	// the grant was issued to is gone, so the token cannot be redeemed.
	ConsentCauseRegisteredClientLost = "registered_client_lost"
)

func (e *ConsentRequiredError) Error() string {
	return fmt.Sprintf("user consent required to connect provider %q", e.Provider)
}

//go:generate mockery --name=CredentialResolver --dir=. --output=./mocks --filename=mcp_credential_resolver_mock.go --case=underscore --with-expecter
type CredentialResolver interface {
	Apply(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry, target *Target) error
}

type CredentialConnectGateway interface {
	CreateTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath string) (string, error)
	CreateServerTicket(ctx context.Context, gatewayID ids.GatewayID, principalSub, consumerPath, code, instanceID string) (string, error)
	RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error)
}

var _ CredentialResolver = (*credentialResolver)(nil)

type credentialResolver struct {
	exchanger sts.Exchanger
	vault     vaultdomain.Repository
	connect   CredentialConnectGateway
	provider  appoauth.ProviderClient
	logger    *slog.Logger
	refresh   singleflight.Group
	attempts  sync.Map // gateway|subject|provider → time.Time
	ccFlight  singleflight.Group
	ccCache   sync.Map // key → *ccCacheEntry
	dead      sync.Map // gateway|subject|provider → deadGrant
}

type deadGrant struct {
	fingerprint string
	at          time.Time
}

type ccCacheEntry struct {
	token     string
	expiresAt time.Time
	// fingerprint pins the entry to the registry revision it was minted for, so
	// editing the credential invalidates it without leaving a stale key behind.
	fingerprint string
}

func NewCredentialResolver(
	exchanger sts.Exchanger,
	vault vaultdomain.Repository,
	connect CredentialConnectGateway,
	provider appoauth.ProviderClient,
	logger *slog.Logger,
) CredentialResolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &credentialResolver{
		exchanger: exchanger,
		vault:     vault,
		connect:   connect,
		provider:  provider,
		logger:    logger,
	}
}

const vaultRefreshSkew = 60 * time.Second

const rejectedCredentialRefreshCooldown = 30 * time.Second

// Backstop for a provider that answered invalid_grant spuriously.
const deadGrantRetryInterval = 15 * time.Minute

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
	case registrydomain.MCPAuthModeClientCredentials:
		return r.clientCredentials(ctx, reg, cfg, target)
	default:
		return fmt.Errorf("mcp: unknown downstream auth mode %q", cfg.Mode)
	}
}

func (r *credentialResolver) passthrough(ctx context.Context, cfg *registrydomain.MCPAuth, target *Target) error {
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil {
		return ErrNoPrincipal
	}
	if principal.RawToken == "" {
		// Authenticated, just not with a token this mode can forward.
		return ErrUpstreamNeedsCallerToken
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
	// Impersonation and delegation are minted from the subject, so a machine
	// caller is fine; on-behalf-of and token-exchange present the caller's own
	// token to the IdP and cannot be served without one.
	if cfg.NeedsCallerToken() && principal.RawToken == "" {
		return ErrUpstreamNeedsCallerToken
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
		return r.consentRequired(ctx, rc, reg, cfg.Provider, principal.Subject,
			ConsentCauseNoCredential, "no stored credential for this user and provider")
	}
	if errors.Is(err, vaultdomain.ErrUndecryptable) {
		// The credential exists but the vault key can no longer read it — the
		// user did connect, so "no stored credential" would be a lie and send
		// them round a reconnect loop that only papers over one provider at a
		// time. Name the real cause; reconnecting rewrites it under the current
		// key, but the fix is to stop SERVER_SECRET_KEY from changing.
		return r.consentRequired(ctx, rc, reg, cfg.Provider, principal.Subject,
			ConsentCauseUndecryptable,
			"stored credential is undecryptable (SERVER_SECRET_KEY changed since it was saved)")
	}
	if err != nil {
		return err
	}
	if cred.Expired(vaultRefreshSkew) {
		cred, err = r.refreshCredential(ctx, rc, reg, gatewayID, principal.Subject, cfg.Provider, "")
		if err != nil {
			return err
		}
	}
	setAuthorization(target, "Bearer "+cred.AccessToken)
	stampAccountRef(ctx, cred.AccountRef)
	return nil
}

// Refresh replaces a forwarded OAuth credential rejected by an upstream.
func (r *credentialResolver) Refresh(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	target *Target,
) error {
	cfg := reg.MCPTarget.Auth
	if cfg == nil || cfg.Mode != registrydomain.MCPAuthModeForwarded {
		return errCredentialRefreshUnsupported
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil {
		return ErrNoPrincipal
	}
	rejected := bearerToken(target.Headers["Authorization"])
	cred, err := r.refreshCredential(
		ctx,
		rc,
		reg,
		rc.Consumer.GatewayID,
		principal.Subject,
		cfg.Provider,
		rejected,
	)
	if err != nil {
		return err
	}
	setAuthorization(target, "Bearer "+cred.AccessToken)
	stampAccountRef(ctx, cred.AccountRef)
	return nil
}

func (r *credentialResolver) refreshCredential(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	gatewayID ids.GatewayID,
	subject, provider, rejectedAccessToken string,
) (*vaultdomain.Credential, error) {
	key := gatewayID.String() + "|" + subject + "|" + provider
	v, err, _ := r.refresh.Do(key, func() (any, error) {
		cred, err := r.vault.Find(ctx, gatewayID, subject, provider)
		if err != nil {
			return nil, err
		}
		if rejectedAccessToken == "" && !cred.Expired(vaultRefreshSkew) {
			return cred, nil
		}
		if rejectedAccessToken != "" && cred.AccessToken != rejectedAccessToken {
			return cred, nil
		}
		if cred.RefreshToken == "" {
			return nil, errGrantExhausted
		}
		if rejectedAccessToken != "" {
			if value, ok := r.attempts.Load(key); ok {
				attemptedAt, valid := value.(time.Time)
				if valid && time.Since(attemptedAt) < rejectedCredentialRefreshCooldown {
					return nil, errCredentialRefreshThrottled
				}
				r.attempts.Delete(key)
			}
		}
		// A rejected grant recovers on reconnect, never on retry; replaying it only amplifies.
		if r.grantIsDead(key, cred.RefreshToken) {
			return nil, errGrantRejected
		}
		refreshCfg, err := r.connect.RefreshAuth(ctx, gatewayID, reg)
		if err != nil {
			return nil, err
		}
		fresh, err := r.provider.Refresh(ctx, refreshCfg, cred.RefreshToken)
		if err != nil {
			// Providers that rotate refresh tokens (Notion, and OAuth 2.1 in
			// general) invalidate the previous one on every refresh, and
			// singleflight only dedupes within this process. A sibling replica
			// may therefore have rotated the token between our read and this
			// call, which the provider reports as invalid_grant. Re-read before
			// giving up: if the stored credential is usable again the peer's
			// refresh succeeded and there is nothing for the user to consent to.
			if errors.Is(err, appoauth.ErrInvalidGrant) {
				latest, findErr := r.vault.Find(ctx, gatewayID, subject, provider)
				peerRefreshed := findErr == nil && ((rejectedAccessToken != "" &&
					latest.AccessToken != rejectedAccessToken) ||
					(rejectedAccessToken == "" && !latest.Expired(vaultRefreshSkew)))
				if peerRefreshed {
					r.logger.Info("mcp credentials: refresh raced a concurrent rotation; reusing the credential stored by the peer",
						"provider", provider, "principal_ref", logref.Opaque(subject), "gateway_id", gatewayID.String())
					return latest, nil
				}
				r.markGrantDead(key, cred.RefreshToken)
			}
			return nil, err
		}
		previousRefreshToken := cred.RefreshToken
		cred.AccessToken = fresh.AccessToken
		if fresh.RefreshToken != "" {
			cred.RefreshToken = fresh.RefreshToken
		}
		cred.ExpiresAt = fresh.ExpiresAt
		if err := r.vault.Upsert(ctx, cred); err != nil {
			r.logger.Error("mcp credentials: failed to persist refreshed credential",
				"provider", provider, "subject", subject, "gateway_id", gatewayID.String(),
				"from", grantFingerprint(previousRefreshToken), "to", grantFingerprint(cred.RefreshToken),
				"error", err,
				"context_error", ctx.Err(),
				"canceled", errors.Is(err, context.Canceled),
				"deadline_exceeded", errors.Is(err, context.DeadlineExceeded),
				"error_type", fmt.Sprintf("%T", err))
			return nil, err
		}
		r.dead.Delete(key)
		// Divergent outputs for the same input help identify concurrent refreshes.
		r.logger.Info("mcp credentials: refresh token rotated",
			"provider", provider,
			"subject", subject,
			"gateway_id", gatewayID.String(),
			"from", grantFingerprint(previousRefreshToken),
			"to", grantFingerprint(cred.RefreshToken),
			"rotated", fresh.RefreshToken != "")
		if rejectedAccessToken != "" {
			r.attempts.Store(key, time.Now())
		}
		return cred, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errGrantExhausted):
			return nil, r.consentRequired(ctx, rc, reg, provider, subject,
				ConsentCauseNoRefreshToken,
				"stored grant carries no refresh token and the access token expired")
		case errors.Is(err, appoauth.ErrInvalidGrant):
			var diagnostic *appoauth.InvalidGrantError
			var attrs []any
			if errors.As(err, &diagnostic) {
				attrs = append(attrs, "oauth_error", diagnostic.Code, "oauth_error_description", diagnostic.Description)
			}
			return nil, r.consentRequired(ctx, rc, reg, provider, subject,
				ConsentCauseRefreshRejected,
				"provider rejected the stored refresh token", attrs...)
		case errors.Is(err, errGrantRejected):
			return nil, r.consentRequired(ctx, rc, reg, provider, subject,
				ConsentCauseRefreshAlreadyRejected,
				"stored refresh token was already rejected; not retried until the user reconnects")
		case errors.Is(err, vaultdomain.ErrNotFound):
			return nil, r.consentRequired(ctx, rc, reg, provider, subject,
				ConsentCauseCredentialVanished,
				"stored credential vanished while refreshing")
		case errors.Is(err, appoauth.ErrNoRegisteredClient):
			// The DCR client the refresh token was issued to is gone from the
			// store. The token cannot be redeemed without it, so this is a
			// consent case — reconnecting re-registers the client — not an
			// unreachable upstream to be skipped in silence.
			return nil, r.consentRequired(ctx, rc, reg, provider, subject,
				ConsentCauseRegisteredClientLost,
				"dynamically registered client was lost (store flushed?); reconnect re-registers it")
		}
		return nil, err
	}
	cred, ok := v.(*vaultdomain.Credential)
	if !ok {
		return nil, errors.New("mcp credentials: unexpected singleflight result type")
	}
	return cred, nil
}

func (r *credentialResolver) grantIsDead(key, refreshToken string) bool {
	value, ok := r.dead.Load(key)
	if !ok {
		return false
	}
	marker, valid := value.(deadGrant)
	if !valid {
		return false
	}
	if time.Since(marker.at) >= deadGrantRetryInterval {
		r.dead.Delete(key)
		return false
	}
	// A different token means the account was reconnected, so the marker is stale.
	if marker.fingerprint != grantFingerprint(refreshToken) {
		r.dead.Delete(key)
		return false
	}
	return true
}

func (r *credentialResolver) markGrantDead(key, refreshToken string) {
	r.dead.Store(key, deadGrant{fingerprint: grantFingerprint(refreshToken), at: time.Now()})
}

// Fingerprinted so markers and logs never hold the refresh token itself.
func grantFingerprint(refreshToken string) string {
	if refreshToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(sum[:4])
}

var errGrantExhausted = errors.New("mcp credentials: stored grant cannot be refreshed")

var errGrantRejected = errors.New("mcp credentials: stored refresh token was already rejected by the provider")

var errCredentialRefreshUnsupported = errors.New("mcp credentials: auth mode cannot refresh after an upstream rejection")

var errCredentialRefreshThrottled = errors.New("mcp credentials: rejected credential was refreshed too recently")

// consentRequired is the single funnel through which a downstream call asks the
// user to (re)connect a provider. The reason is logged so an unexpected consent
// prompt can be traced to the condition that produced it instead of being
// guessed at from the client-side error alone.
func (r *credentialResolver) consentRequired(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	provider, principalSub, cause, reason string,
	diagnostics ...any,
) error {
	attrs := []any{
		"provider", provider,
		"principal_ref", logref.Opaque(principalSub),
		"gateway_id", rc.Consumer.GatewayID.String(),
		"cause", cause,
		"reason", reason,
	}
	r.logger.Info("mcp credentials: user consent required", append(attrs, diagnostics...)...)
	consumerPath := appconsumer.MCPPath(rc.Consumer.Slug)
	var ticket string
	var err error
	if code := storeServerCode(rc, reg); code != "" {
		ticket, err = r.connect.CreateServerTicket(ctx, rc.Consumer.GatewayID, principalSub, consumerPath, code, "")
	} else {
		ticket, err = r.connect.CreateTicket(ctx, rc.Consumer.GatewayID, principalSub, consumerPath)
	}
	if err != nil {
		return err
	}
	return &ConsentRequiredError{Provider: provider, Ticket: ticket, Path: consumerPath, Cause: cause}
}

func storeServerCode(rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
	if rc == nil || !consumerdomain.IsStoreConsumer(rc.Consumer) || reg == nil || reg.MCPTarget == nil {
		return ""
	}
	return strings.TrimSpace(reg.MCPTarget.Code)
}

func (r *credentialResolver) clientCredentials(
	ctx context.Context,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
	target *Target,
) error {
	if r.provider == nil {
		return errors.New("mcp: client_credentials requires an OAuth provider client")
	}
	// Keyed by registry id alone so the map stays bounded by the number of MCP
	// registries; a credential edit overwrites its entry instead of adding one.
	key := reg.ID.String()
	fingerprint := ccFingerprint(reg)
	if cached, ok := r.cachedCCToken(key, fingerprint); ok {
		setAuthorization(target, "Bearer "+cached.token)
		return nil
	}
	v, err, _ := r.ccFlight.Do(key+"|"+fingerprint, func() (any, error) {
		if cached, ok := r.cachedCCToken(key, fingerprint); ok {
			return cached, nil
		}
		tok, err := r.provider.ClientCredentials(ctx, cfg)
		if err != nil {
			return nil, err
		}
		if tok.AccessToken == "" {
			return nil, errors.New("mcp: client_credentials returned empty access token")
		}
		expiresAt := tok.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(defaultCCTokenTTL)
		}
		cached := &ccCacheEntry{token: tok.AccessToken, expiresAt: expiresAt, fingerprint: fingerprint}
		r.ccCache.Store(key, cached)
		return cached, nil
	})
	if err != nil {
		return err
	}
	cached, ok := v.(*ccCacheEntry)
	if !ok {
		return errors.New("mcp credentials: unexpected singleflight result type")
	}
	setAuthorization(target, "Bearer "+cached.token)
	return nil
}

const defaultCCTokenTTL = time.Hour

func (r *credentialResolver) cachedCCToken(key, fingerprint string) (*ccCacheEntry, bool) {
	v, ok := r.ccCache.Load(key)
	if !ok {
		return nil, false
	}
	cached, ok := v.(*ccCacheEntry)
	if !ok || cached.fingerprint != fingerprint {
		return nil, false
	}
	if !time.Now().Before(cached.expiresAt.Add(-vaultRefreshSkew)) {
		return nil, false
	}
	return cached, true
}

func ccFingerprint(reg *registrydomain.Registry) string {
	return reg.UpdatedAt.UTC().Format(time.RFC3339Nano)
}

func setAuthorization(target *Target, value string) {
	if target.Headers == nil {
		target.Headers = map[string]string{}
	}
	target.Headers["Authorization"] = value
}

func stampAccountRef(ctx context.Context, accountRef string) {
	if accountRef == "" {
		return
	}
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPAccountRef(accountRef)
	}
}

func bearerToken(authorization string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
