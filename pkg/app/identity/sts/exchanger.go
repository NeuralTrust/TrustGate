package sts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInteractionRequired propagates an IdP claims challenge: the client
	// must re-authenticate (401 + WWW-Authenticate, never a 500).
	ErrInteractionRequired = errors.New("sts: interaction required")
	// ErrNoUserIdentity means the exchange pattern needs an inbound user JWT
	// (api_key / machine principals cannot be exchanged on behalf of).
	ErrNoUserIdentity = errors.New("sts: exchange requires an inbound user token")
)

// Token is one minted/exchanged downstream credential.
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresAt   time.Time
}

// Exchanger turns the inbound Principal into a downstream credential per the
// target's exchange pattern. Results are cached per (principal, target) with
// strict isolation; a cache leak here is cross-user escalation.
//
//go:generate mockery --name=Exchanger --dir=. --output=./mocks --filename=sts_exchanger_mock.go --case=underscore --with-expecter
type Exchanger interface {
	Exchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth, cacheKey string) (*Token, error)
}

var _ Exchanger = (*exchanger)(nil)

type exchanger struct {
	signer      *Signer
	credentials appauth.CredentialFinder
	client      *http.Client

	mu        sync.Mutex
	cache     map[string]*Token
	lastSweep time.Time

	epMu      sync.Mutex
	endpoints map[string]endpointEntry
}

type endpointEntry struct {
	tokenEndpoint string
	fetchedAt     time.Time
}

func NewExchanger(signer *Signer, credentials appauth.CredentialFinder, client *http.Client) Exchanger {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &exchanger{
		signer:      signer,
		credentials: credentials,
		client:      client,
		cache:       map[string]*Token{},
		endpoints:   map[string]endpointEntry{},
	}
}

const refreshSkew = 30 * time.Second

func (e *exchanger) Exchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth, cacheKey string) (*Token, error) {
	if principal == nil {
		return nil, ErrNoUserIdentity
	}
	e.mu.Lock()
	if t, ok := e.cache[cacheKey]; ok && time.Now().Add(refreshSkew).Before(t.ExpiresAt) {
		e.mu.Unlock()
		return t, nil
	}
	e.mu.Unlock()

	var (
		token *Token
		err   error
	)
	switch cfg.Pattern {
	case registrydomain.ExchangeImpersonation:
		token, err = e.mint(principal, cfg, false)
	case registrydomain.ExchangeDelegation:
		token, err = e.mint(principal, cfg, true)
	case registrydomain.ExchangeOBO:
		token, err = e.entraOBO(ctx, principal, cfg)
	case registrydomain.ExchangeTokenExchange:
		token, err = e.tokenExchange(ctx, principal, cfg)
	default:
		return nil, fmt.Errorf("sts: unknown exchange pattern %q", cfg.Pattern)
	}
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.sweepLocked()
	e.cache[cacheKey] = token
	e.mu.Unlock()
	return token, nil
}

const cacheSweepInterval = time.Minute

// sweepLocked drops expired tokens at most once per cacheSweepInterval; the
// cache is keyed per (principal x target), so without eviction it grows
// unbounded with the tenant population. Callers must hold e.mu.
func (e *exchanger) sweepLocked() {
	now := time.Now()
	if now.Sub(e.lastSweep) < cacheSweepInterval {
		return
	}
	e.lastSweep = now
	for k, t := range e.cache {
		if now.After(t.ExpiresAt) {
			delete(e.cache, k)
		}
	}
}

// mint issues a TrustGate-signed JWT: same subject, target audience, and for
// delegation an RFC 8693 act claim naming the agent.
func (e *exchanger) mint(principal *identity.Principal, cfg *registrydomain.MCPAuth, delegation bool) (*Token, error) {
	claims := jwt.MapClaims{
		"sub": principal.Subject,
		"aud": cfg.Audience,
	}
	if principal.Issuer != "" {
		claims["orig_iss"] = principal.Issuer
	}
	if len(principal.Scopes) > 0 {
		claims["scope"] = strings.Join(principal.Scopes, " ")
	}
	if delegation {
		claims["act"] = map[string]any{"sub": cfg.Actor}
	}
	signed, err := e.signer.MintClaims(claims, defaultTokenTTL)
	if err != nil {
		return nil, err
	}
	return &Token{AccessToken: signed, TokenType: "Bearer", ExpiresAt: time.Now().Add(defaultTokenTTL)}, nil
}

// entraOBO performs the Microsoft Entra On-Behalf-Of exchange: the inbound
// user token (aud = the gateway's Entra app) becomes a token for the target
// resource. Authority derives from the principal's issuer.
func (e *exchanger) entraOBO(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth) (*Token, error) {
	if principal.RawToken == "" || principal.Method != identity.MethodJWT {
		return nil, ErrNoUserIdentity
	}
	idp, err := e.idpFor(ctx, principal.Issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("requested_token_use", "on_behalf_of")
	form.Set("assertion", principal.RawToken)
	form.Set("scope", cfg.Scope)
	form.Set("client_id", idp.ClientID)
	form.Set("client_secret", idp.ClientSecret)
	return e.idpTokenCall(ctx, e.tokenEndpointFor(ctx, principal.Issuer), form)
}

// tokenExchange is generic RFC 8693 (Okta and friends).
func (e *exchanger) tokenExchange(ctx context.Context, principal *identity.Principal, cfg *registrydomain.MCPAuth) (*Token, error) {
	if principal.RawToken == "" {
		return nil, ErrNoUserIdentity
	}
	idp, err := e.idpFor(ctx, principal.Issuer)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", principal.RawToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", cfg.Audience)
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}
	form.Set("client_id", idp.ClientID)
	form.Set("client_secret", idp.ClientSecret)
	return e.idpTokenCall(ctx, e.tokenEndpointFor(ctx, principal.Issuer), form)
}

// idpFor finds the oauth2 Auth entry matching the principal's issuer, which
// holds the gateway's IdP app credentials for the exchange.
func (e *exchanger) idpFor(ctx context.Context, issuer string) (*authdomain.OAuth2Config, error) {
	auths, err := e.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("sts: load oauth2 auths: %w", err)
	}
	for _, a := range auths {
		if a.Config.OAuth2 != nil && a.Config.OAuth2.Issuer == issuer {
			if a.Config.OAuth2.ClientID == "" || a.Config.OAuth2.ClientSecret == "" {
				return nil, fmt.Errorf("sts: oauth2 auth for %s lacks client_id/client_secret needed for exchange", issuer)
			}
			return a.Config.OAuth2, nil
		}
	}
	return nil, fmt.Errorf("sts: no oauth2 auth configured for issuer %s", issuer)
}

const endpointTTL = time.Hour

// tokenEndpointFor resolves the IdP token endpoint via OIDC discovery
// (cached per issuer). Guessing by URL convention breaks any IdP that is
// not Entra or Okta (Auth0 uses /oauth/token, Keycloak
// /protocol/openid-connect/token), so the heuristic is only a fallback
// when the well-known document cannot be fetched.
func (e *exchanger) tokenEndpointFor(ctx context.Context, issuer string) string {
	e.epMu.Lock()
	if ent, ok := e.endpoints[issuer]; ok && time.Since(ent.fetchedAt) < endpointTTL {
		e.epMu.Unlock()
		return ent.tokenEndpoint
	}
	e.epMu.Unlock()

	endpoint := e.discoverTokenEndpoint(ctx, issuer)
	if endpoint == "" {
		endpoint = fallbackTokenEndpoint(issuer)
	}
	e.epMu.Lock()
	e.endpoints[issuer] = endpointEntry{tokenEndpoint: endpoint, fetchedAt: time.Now()}
	e.epMu.Unlock()
	return endpoint
}

func (e *exchanger) discoverTokenEndpoint(ctx context.Context, issuer string) string {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return ""
	}
	res, err := e.client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&doc); err != nil {
		return ""
	}
	return doc.TokenEndpoint
}

// fallbackTokenEndpoint derives the token endpoint from the issuer URL when
// discovery is unavailable: Entra v2 issuers map to /oauth2/v2.0/token and
// anything else gets the Okta org-server convention.
func fallbackTokenEndpoint(issuer string) string {
	base := strings.TrimSuffix(issuer, "/")
	if strings.HasPrefix(base, "https://login.microsoftonline.com/") {
		return strings.TrimSuffix(base, "/v2.0") + "/oauth2/v2.0/token"
	}
	return base + "/v1/token"
}

func (e *exchanger) idpTokenCall(ctx context.Context, endpoint string, form url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sts: IdP exchange call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("sts: read IdP response: %w", err)
	}
	var doc struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
		Claims      string `json:"claims"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("sts: IdP response is not JSON (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		if doc.Error == "interaction_required" || doc.Error == "invalid_grant" {
			return nil, fmt.Errorf("%w: %s", ErrInteractionRequired, doc.ErrorDesc)
		}
		return nil, fmt.Errorf("sts: IdP exchange failed (%s): %s", doc.Error, doc.ErrorDesc)
	}
	if doc.AccessToken == "" {
		return nil, fmt.Errorf("sts: IdP returned 200 with no access_token")
	}
	ttl := time.Duration(doc.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	tokenType := doc.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	return &Token{AccessToken: doc.AccessToken, TokenType: tokenType, ExpiresAt: time.Now().Add(ttl)}, nil
}
