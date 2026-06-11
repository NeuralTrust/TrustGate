package sts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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

func TestExchanger_Impersonation_MintsAndCaches(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	ex := NewExchanger(signer, &stubCredentials{}, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeImpersonation,
		Audience: "https://up.example.com",
	}
	tok, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claims := decodeClaims(t, signer, tok.AccessToken)
	if claims["sub"] != "alice" || claims["aud"] != "https://up.example.com" {
		t.Fatalf("claims = %v", claims)
	}
	if _, hasAct := claims["act"]; hasAct {
		t.Fatal("impersonation must not carry act claim")
	}
	// Cache hit: same key returns the same token.
	again, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k1")
	if err != nil || again.AccessToken != tok.AccessToken {
		t.Fatal("expected cached token for same key")
	}
	// Different key (other principal/target): a distinct token.
	other, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k2")
	if err != nil || other.AccessToken == tok.AccessToken {
		t.Fatal("cache must isolate per key")
	}
}

func TestExchanger_Delegation_AddsActClaim(t *testing.T) {
	t.Parallel()
	signer := newTestSigner(t)
	ex := NewExchanger(signer, &stubCredentials{}, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeDelegation,
		Audience: "https://up.example.com", Actor: "agent-bot",
	}
	tok, err := ex.Exchange(context.Background(), userPrincipal(), cfg, "k")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claims := decodeClaims(t, signer, tok.AccessToken)
	act, ok := claims["act"].(map[string]any)
	if !ok || act["sub"] != "agent-bot" {
		t.Fatalf("act = %v, want sub=agent-bot", claims["act"])
	}
}

func TestExchanger_OBO_CallsIdPTokenEndpoint(t *testing.T) {
	t.Parallel()
	var gotForm map[string]string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = map[string]string{}
		for k := range r.Form {
			gotForm[k] = r.Form.Get(k)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "obo-token", "token_type": "Bearer", "expires_in": 600,
		})
	}))
	defer idp.Close()

	signer := newTestSigner(t)
	creds := &stubCredentials{auths: []*authdomain.Auth{{
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: idp.URL, ClientID: "gw-app", ClientSecret: "gw-secret",
		}},
	}}}
	ex := NewExchanger(signer, creds, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeOBO,
		Scope: "api://target/.default",
	}
	p := userPrincipal()
	p.Issuer = idp.URL
	tok, err := ex.Exchange(context.Background(), p, cfg, "k")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "obo-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if gotForm["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
		gotForm["requested_token_use"] != "on_behalf_of" ||
		gotForm["assertion"] != "inbound-token" ||
		gotForm["scope"] != "api://target/.default" {
		t.Fatalf("OBO form = %v", gotForm)
	}
}

func TestExchanger_OBO_InteractionRequiredPropagates(t *testing.T) {
	t.Parallel()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "interaction_required", "error_description": "MFA needed",
		})
	}))
	defer idp.Close()

	creds := &stubCredentials{auths: []*authdomain.Auth{{
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: idp.URL, ClientID: "id", ClientSecret: "s",
		}},
	}}}
	ex := NewExchanger(newTestSigner(t), creds, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeOBO, Scope: "x/.default",
	}
	p := userPrincipal()
	p.Issuer = idp.URL
	_, err := ex.Exchange(context.Background(), p, cfg, "k")
	if err == nil || !errorIs(err, ErrInteractionRequired) {
		t.Fatalf("error = %v, want ErrInteractionRequired", err)
	}
}

func TestExchanger_TokenExchange_RFC8693Form(t *testing.T) {
	t.Parallel()
	var gotForm map[string]string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = map[string]string{}
		for k := range r.Form {
			gotForm[k] = r.Form.Get(k)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "xt", "expires_in": 60})
	}))
	defer idp.Close()

	creds := &stubCredentials{auths: []*authdomain.Auth{{
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer: idp.URL, ClientID: "id", ClientSecret: "s",
		}},
	}}}
	ex := NewExchanger(newTestSigner(t), creds, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeTokenExchange,
		Audience: "https://up.example.com",
	}
	p := userPrincipal()
	p.Issuer = idp.URL
	if _, err := ex.Exchange(context.Background(), p, cfg, "k"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotForm["grant_type"] != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		gotForm["subject_token"] != "inbound-token" ||
		gotForm["audience"] != "https://up.example.com" {
		t.Fatalf("token-exchange form = %v", gotForm)
	}
}

func TestExchanger_OBO_RequiresUserJWT(t *testing.T) {
	t.Parallel()
	ex := NewExchanger(newTestSigner(t), &stubCredentials{}, nil)
	cfg := &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeExchange, Pattern: registrydomain.ExchangeOBO, Scope: "x/.default",
	}
	apiKeyPrincipal := &identity.Principal{Subject: "m2m", Method: identity.MethodAPIKey}
	if _, err := ex.Exchange(context.Background(), apiKeyPrincipal, cfg, "k"); !errorIs(err, ErrNoUserIdentity) {
		t.Fatalf("error = %v, want ErrNoUserIdentity", err)
	}
}

func TestTokenEndpointFor(t *testing.T) {
	t.Parallel()
	entra := tokenEndpointFor("https://login.microsoftonline.com/tid/v2.0")
	if entra != "https://login.microsoftonline.com/tid/oauth2/v2.0/token" {
		t.Fatalf("entra endpoint = %q", entra)
	}
	okta := tokenEndpointFor("https://org.okta.com/oauth2/default")
	if okta != "https://org.okta.com/oauth2/default/v1/token" {
		t.Fatalf("okta endpoint = %q", okta)
	}
}

func decodeClaims(t *testing.T, s *Signer, token string) jwt.MapClaims {
	t.Helper()
	pub := publicKeyFromJWKS(t, s)
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	return parsed.Claims.(jwt.MapClaims)
}

func errorIs(err, target error) bool { return errors.Is(err, target) }
