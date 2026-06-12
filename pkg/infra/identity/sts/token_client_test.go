package sts

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	appsts "github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
)

func TestFallbackTokenEndpoint(t *testing.T) {
	t.Parallel()
	entra := fallbackTokenEndpoint("https://login.microsoftonline.com/tid/v2.0")
	if entra != "https://login.microsoftonline.com/tid/oauth2/v2.0/token" {
		t.Fatalf("entra endpoint = %q", entra)
	}
	okta := fallbackTokenEndpoint("https://org.okta.com/oauth2/default")
	if okta != "https://org.okta.com/oauth2/default/v1/token" {
		t.Fatalf("okta endpoint = %q", okta)
	}
}

func TestTokenClient_EndpointResolvedViaDiscoveryAndCached(t *testing.T) {
	t.Parallel()
	var tokenPathHit string
	var discoveryCalls int
	mux := http.NewServeMux()
	var idp *httptest.Server
	mux.HandleFunc("/realms/acme/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		discoveryCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_endpoint": idp.URL + "/realms/acme/protocol/openid-connect/token",
		})
	})
	mux.HandleFunc("/realms/acme/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		tokenPathHit = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "kc-token", "expires_in": 60})
	})
	idp = httptest.NewServer(mux)
	defer idp.Close()

	issuer := idp.URL + "/realms/acme"
	c := NewTokenClient(nil)
	tok, err := c.Call(context.Background(), issuer, url.Values{"grant_type": {"x"}})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if tok.AccessToken != "kc-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if tokenPathHit != "/realms/acme/protocol/openid-connect/token" {
		t.Fatalf("token endpoint hit = %q, want the discovered one", tokenPathHit)
	}
	if _, err := c.Call(context.Background(), issuer, url.Values{}); err != nil {
		t.Fatalf("second Call: %v", err)
	}
	if discoveryCalls != 1 {
		t.Fatalf("discovery calls = %d, want 1 (cached)", discoveryCalls)
	}
}

func TestTokenClient_InteractionRequiredMapsToSentinel(t *testing.T) {
	t.Parallel()
	idp := newIdPStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "interaction_required", "error_description": "MFA needed",
		})
	})
	_, err := NewTokenClient(nil).Call(context.Background(), idp, url.Values{})
	if !errors.Is(err, appsts.ErrInteractionRequired) {
		t.Fatalf("error = %v, want ErrInteractionRequired", err)
	}
}

func TestTokenClient_RejectsEmptyAccessTokenOn200(t *testing.T) {
	t.Parallel()
	idp := newIdPStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer"})
	})
	if _, err := NewTokenClient(nil).Call(context.Background(), idp, url.Values{}); err == nil {
		t.Fatal("200 without access_token must be an error")
	}
}

func newIdPStub(t *testing.T, token http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"token_endpoint": srv.URL + "/token"})
	})
	mux.HandleFunc("/token", token)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}
