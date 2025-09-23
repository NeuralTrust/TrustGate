package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func readBody(r *http.Request) url.Values {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return url.Values{}
	}
	_ = r.Body.Close()
	vals, err := url.ParseQuery(string(b))
	if err != nil {
		return url.Values{}
	}
	return vals
}

func TestGetToken_ValidationErrors(t *testing.T) {
	c := NewTokenClient(&http.Client{Timeout: time.Second})
	ctx := context.Background()

	if _, _, err := c.GetToken(ctx, TokenRequestDTO{GrantType: GrantTypeClientCredentials}); err == nil {
		t.Fatalf("expected error for missing token url")
	}

	if _, _, err := c.GetToken(ctx, TokenRequestDTO{TokenURL: "http://example"}); err == nil {
		t.Fatalf("expected error for missing grant type")
	}
}

func TestGetToken_UnsupportedGrant(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 1}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	c := NewTokenClient(ts.Client())
	ctx := context.Background()
	_, _, err := c.GetToken(ctx, TokenRequestDTO{TokenURL: ts.URL, GrantType: GrantType("unknown")})
	if err == nil || !strings.Contains(err.Error(), "unsupported grant_type") {
		t.Fatalf("expected unsupported grant_type error, got %v", err)
	}
}

func TestClientCredentials_BasicAuth(t *testing.T) {
	expectedToken := "t123"
	expires := int64(3600)
	var gotAuth string
	var gotBody url.Values

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Fatalf("unexpected content-type: %s", ct)
		}
		gotBody = readBody(r)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": expectedToken,
			"token_type":   "bearer",
			"expires_in":   expires,
		}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	c := NewTokenClient(ts.Client())
	ctx := context.Background()
	_, _, err := c.GetToken(ctx, TokenRequestDTO{
		TokenURL:     ts.URL,
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "cid",
		ClientSecret: "sec",
		UseBasicAuth: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	exp := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:sec"))
	if gotAuth != exp {
		t.Fatalf("expected auth %q, got %q", exp, gotAuth)
	}

	if gotBody.Get("client_id") != "" || gotBody.Get("client_secret") != "" {
		t.Fatalf("did not expect client credentials in body when using basic auth")
	}
	if gotBody.Get("grant_type") != string(GrantTypeClientCredentials) {
		t.Fatalf("grant_type mismatch")
	}
}

func TestClientCredentials_BodyCredentialsAndExtras(t *testing.T) {
	expectedToken := "tok-body"
	var gotBody url.Values

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = readBody(r)
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": expectedToken, "expires_in": 2}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	c := NewTokenClient(ts.Client())
	ctx := context.Background()
	tok, expAt, err := c.GetToken(ctx, TokenRequestDTO{
		TokenURL:     ts.URL,
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "cid",
		ClientSecret: "sec",
		Scopes:       []string{"a", "b"},
		Audience:     "aud",
		Extra:        map[string]string{"custom": "x"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != expectedToken {
		t.Fatalf("token mismatch: %s", tok)
	}

	now := time.Now()
	if expAt.Before(now.Add(time.Second)) || expAt.After(now.Add(3*time.Second)) {
		t.Fatalf("expiresAt not in expected window: %v", expAt)
	}
	if gotBody.Get("client_id") != "cid" || gotBody.Get("client_secret") != "sec" {
		t.Fatalf("expected client credentials in body")
	}
	if gotBody.Get("scope") != "a b" {
		t.Fatalf("expected scope 'a b', got %q", gotBody.Get("scope"))
	}
	if gotBody.Get("audience") != "aud" {
		t.Fatalf("expected audience, got %q", gotBody.Get("audience"))
	}
	if gotBody.Get("custom") != "x" {
		t.Fatalf("expected extra field 'custom' in form")
	}
}

func TestAuthorizationCode_ValidationAndFields(t *testing.T) {

	if _, _, err := NewTokenClient(&http.Client{}).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  "http://example",
		GrantType: GrantTypeAuthorizationCode,
	}); err == nil {
		t.Fatalf("expected error for missing code")
	}

	if _, _, err := NewTokenClient(&http.Client{}).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  "http://example",
		GrantType: GrantTypeAuthorizationCode,
		Code:      "abc",
	}); err == nil {
		t.Fatalf("expected error for missing redirect_uri")
	}

	var gotBody url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = readBody(r)
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "ok", "expires_in": 1}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	_, _, err := NewTokenClient(ts.Client()).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:     ts.URL,
		GrantType:    GrantTypeAuthorizationCode,
		Code:         "abc",
		RedirectURI:  "https://cb",
		CodeVerifier: "ver",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody.Get("code") != "abc" || gotBody.Get("redirect_uri") != "https://cb" {
		t.Fatalf("authorization_code fields missing in form: %v", gotBody)
	}
	if gotBody.Get("code_verifier") != "ver" {
		t.Fatalf("expected code_verifier in form")
	}
}

func TestPassword_ValidationAndFields(t *testing.T) {
	if _, _, err := NewTokenClient(&http.Client{}).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  "http://example",
		GrantType: GrantTypePassword,
	}); err == nil {
		t.Fatalf("expected error for missing username/password")
	}

	var gotBody url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = readBody(r)
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "ok", "expires_in": 1}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	_, _, err := NewTokenClient(ts.Client()).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  ts.URL,
		GrantType: GrantTypePassword,
		Username:  "u",
		Password:  "p",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody.Get("username") != "u" || gotBody.Get("password") != "p" {
		t.Fatalf("password grant fields missing in form: %v", gotBody)
	}
}

func TestGetToken_ErrorResponses(t *testing.T) {
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		if _, err := w.Write([]byte("bad request")); err != nil {
			t.Fatalf("failed to write body: %v", err)
		}
	}))
	defer ts1.Close()
	_, _, err := NewTokenClient(ts1.Client()).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  ts1.URL,
		GrantType: GrantTypeClientCredentials,
	})
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected error containing status 400, got %v", err)
	}

	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("not-json")); err != nil {
			t.Fatalf("failed to write body: %v", err)
		}
	}))
	defer ts2.Close()
	_, _, err = NewTokenClient(ts2.Client()).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  ts2.URL,
		GrantType: GrantTypeClientCredentials,
	})
	if err == nil || !strings.Contains(err.Error(), "failed to decode token response") {
		t.Fatalf("expected json decode error, got %v", err)
	}

	ts3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "", "expires_in": 10}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts3.Close()
	_, _, err = NewTokenClient(ts3.Client()).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  ts3.URL,
		GrantType: GrantTypeClientCredentials,
	})
	if err == nil || !strings.Contains(err.Error(), "empty access_token") {
		t.Fatalf("expected empty access_token error, got %v", err)
	}
}

func TestTokenURLCleanup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "ok", "expires_in": 1}); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	u := "@" + ts.URL + "  "
	_, _, err := NewTokenClient(ts.Client()).GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  u,
		GrantType: GrantTypeClientCredentials,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
