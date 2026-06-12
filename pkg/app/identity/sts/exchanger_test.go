package sts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/golang-jwt/jwt/v5"
)

type stubCredentials struct {
	auths []*authdomain.Auth
}

func (s *stubCredentials) OAuth2Auths(context.Context) ([]*authdomain.Auth, error) {
	return s.auths, nil
}

func (s *stubCredentials) MTLSAuths(context.Context) ([]*authdomain.Auth, error) { return nil, nil }

type fakeSigner struct {
	mints int
}

func (f *fakeSigner) Issuer() string { return "https://gw.example.com" }

func (f *fakeSigner) MintClaims(claims jwt.MapClaims, _ time.Duration) (string, error) {
	f.mints++
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d|%s", f.mints, b), nil
}

func (f *fakeSigner) JWKS() map[string]any { return map[string]any{"keys": []map[string]any{}} }

func decodeFakeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	_, payload, ok := cutToken(token)
	if !ok {
		t.Fatalf("not a fake token: %q", token)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return claims
}

func cutToken(token string) (string, string, bool) {
	for i := range token {
		if token[i] == '|' {
			return token[:i], token[i+1:], true
		}
	}
	return "", "", false
}

type fakeIdP struct {
	gotIssuer string
	gotForm   url.Values
	token     *Token
	err       error
}

func (f *fakeIdP) Call(_ context.Context, issuer string, form url.Values) (*Token, error) {
	f.gotIssuer = issuer
	f.gotForm = form
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

func userPrincipal() *identity.Principal {
	return &identity.Principal{
		Subject:  "alice",
		Method:   identity.MethodJWT,
		Issuer:   "https://idp.example.com",
		RawToken: "inbound-token",
		Scopes:   []string{"mcp.access"},
		Claims:   map[string]any{"aud": "gateway"},
	}
}

func idpAuths(issuer string) []*authdomain.Auth {
	return []*authdomain.Auth{{
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: issuer, ClientID: "gw-app", ClientSecret: "gw-secret",
		}},
	}}
}

func TestExchanger_Impersonation_MintsAndCaches(t *testing.T) {
	t.Parallel()
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{}, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeImpersonation,
		Audience: "https://up.example.com",
	}
	tok, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claims := decodeFakeClaims(t, tok.AccessToken)
	if claims["sub"] != "alice" || claims["aud"] != "https://up.example.com" {
		t.Fatalf("claims = %v", claims)
	}
	if _, hasAct := claims["act"]; hasAct {
		t.Fatal("impersonation must not carry act claim")
	}
	again, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k1")
	if err != nil || again.AccessToken != tok.AccessToken {
		t.Fatal("expected cached token for same key")
	}
	other, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k2")
	if err != nil || other.AccessToken == tok.AccessToken {
		t.Fatal("cache must isolate per key")
	}
}

func TestExchanger_Delegation_AddsActClaim(t *testing.T) {
	t.Parallel()
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{}, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeDelegation,
		Audience: "https://up.example.com", Actor: "agent-bot",
	}
	tok, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claims := decodeFakeClaims(t, tok.AccessToken)
	act, ok := claims["act"].(map[string]any)
	if !ok || act["sub"] != "agent-bot" {
		t.Fatalf("act = %v, want sub=agent-bot", claims["act"])
	}
}

func TestExchanger_OBO_BuildsOnBehalfOfGrant(t *testing.T) {
	t.Parallel()
	idp := &fakeIdP{token: &Token{AccessToken: "obo-token", TokenType: "Bearer", ExpiresAt: time.Now().Add(10 * time.Minute)}}
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{auths: idpAuths("https://idp.example.com")}, idp)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeOBO,
		Scope: "api://target/.default",
	}
	tok, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "obo-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if idp.gotIssuer != "https://idp.example.com" {
		t.Fatalf("issuer = %q", idp.gotIssuer)
	}
	if idp.gotForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
		idp.gotForm.Get("requested_token_use") != "on_behalf_of" ||
		idp.gotForm.Get("assertion") != "inbound-token" ||
		idp.gotForm.Get("scope") != "api://target/.default" ||
		idp.gotForm.Get("client_id") != "gw-app" ||
		idp.gotForm.Get("client_secret") != "gw-secret" {
		t.Fatalf("OBO form = %v", idp.gotForm)
	}
}

func TestExchanger_OBO_InteractionRequiredPropagates(t *testing.T) {
	t.Parallel()
	idp := &fakeIdP{err: fmt.Errorf("%w: MFA needed", ErrInteractionRequired)}
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{auths: idpAuths("https://idp.example.com")}, idp)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeOBO, Scope: "x/.default",
	}
	_, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k")
	if err == nil || !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("error = %v, want ErrInteractionRequired", err)
	}
}

func TestExchanger_TokenExchange_RFC8693Form(t *testing.T) {
	t.Parallel()
	idp := &fakeIdP{token: &Token{AccessToken: "xt", ExpiresAt: time.Now().Add(time.Minute)}}
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{auths: idpAuths("https://idp.example.com")}, idp)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeTokenExchange,
		Audience: "https://up.example.com",
	}
	if _, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if idp.gotForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		idp.gotForm.Get("subject_token") != "inbound-token" ||
		idp.gotForm.Get("audience") != "https://up.example.com" {
		t.Fatalf("token-exchange form = %v", idp.gotForm)
	}
}

func TestExchanger_OBO_RequiresUserJWT(t *testing.T) {
	t.Parallel()
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{}, &fakeIdP{})
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeOBO, Scope: "x/.default",
	}
	apiKeyPrincipal := &identity.Principal{Subject: "m2m", Method: identity.MethodAPIKey}
	if _, err := ex.Exchange(context.Background(), apiKeyPrincipal, cfg, "k"); !errors.Is(err, ErrNoUserIdentity) {
		t.Fatalf("error = %v, want ErrNoUserIdentity", err)
	}
}

func TestExchanger_MissingIdPConfigFails(t *testing.T) {
	t.Parallel()
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{}, &fakeIdP{})
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeTokenExchange,
		Audience: "https://up.example.com",
	}
	if _, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k"); err == nil {
		t.Fatal("exchange without a configured IdP must fail")
	}
}

func TestExchanger_CacheSweepsExpiredTokens(t *testing.T) {
	t.Parallel()
	ex := NewExchanger(&fakeSigner{}, &stubCredentials{}, nil).(*exchanger)
	now := time.Now()
	ex.cache["stale"] = &Token{AccessToken: "old", ExpiresAt: now.Add(-time.Minute)}
	ex.lastSweep = now.Add(-2 * cacheSweepInterval)

	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeImpersonation,
		Audience: "https://up.example.com",
	}
	if _, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "fresh"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	ex.mu.Lock()
	_, staleAlive := ex.cache["stale"]
	_, freshAlive := ex.cache["fresh"]
	ex.mu.Unlock()
	if staleAlive {
		t.Fatal("expired cache entry not purged on insert")
	}
	if !freshAlive {
		t.Fatal("fresh entry must be cached")
	}
}
