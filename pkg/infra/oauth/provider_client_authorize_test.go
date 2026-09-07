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
	"net/url"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestAuthorizeURL_GoogleRequestsOfflineAccess(t *testing.T) {
	t.Parallel()
	p := NewProviderClient(nil)
	cfg := &registrydomain.MCPAuth{
		ClientID:     "google-client",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		Scopes:       []string{"https://www.googleapis.com/auth/calendar.events"},
	}
	raw := p.AuthorizeURL(cfg, "https://gw.example/oauth/callback/com.google.workspace/calendar", "state-1", "challenge-1")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if got := q.Get("access_type"); got != "offline" {
		t.Fatalf("access_type = %q, want offline", got)
	}
	if got := q.Get("prompt"); got != "consent" {
		t.Fatalf("prompt = %q, want consent", got)
	}
	if got := q.Get("client_id"); got != "google-client" {
		t.Fatalf("client_id = %q", got)
	}
	if got := q.Get("code_challenge"); got != "challenge-1" {
		t.Fatalf("code_challenge = %q", got)
	}
	if got := q.Get("redirect_uri"); got != "https://gw.example/oauth/callback/com.google.workspace/calendar" {
		t.Fatalf("redirect_uri = %q", got)
	}
}

func TestAuthorizeURL_NonGoogleLeavesOfflineParamsUnset(t *testing.T) {
	t.Parallel()
	p := NewProviderClient(nil)
	cfg := &registrydomain.MCPAuth{
		ClientID:     "gh",
		AuthorizeURL: "https://github.com/login/oauth/authorize",
		Scopes:       []string{"repo"},
	}
	raw := p.AuthorizeURL(cfg, "https://gw.example/oauth/callback/github", "s", "c")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("access_type") != "" {
		t.Fatalf("access_type unexpectedly set for GitHub: %q", q.Get("access_type"))
	}
	if q.Get("prompt") != "" {
		t.Fatalf("prompt unexpectedly set for GitHub: %q", q.Get("prompt"))
	}
}

func TestAuthorizeURL_PreservesCatalogGoogleOverrides(t *testing.T) {
	t.Parallel()
	p := NewProviderClient(nil)
	cfg := &registrydomain.MCPAuth{
		ClientID:     "google-client",
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth?prompt=select_account",
	}
	raw := p.AuthorizeURL(cfg, "https://gw.example/oauth/callback/x", "s", "")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if got := q.Get("access_type"); got != "offline" {
		t.Fatalf("access_type = %q, want offline default", got)
	}
	if got := q.Get("prompt"); got != "select_account" {
		t.Fatalf("prompt = %q, want catalog override select_account", got)
	}
}

func TestIsGoogleAuthorizeURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"https://accounts.google.com/o/oauth2/v2/auth", true},
		{"https://ACCOUNTS.GOOGLE.COM/o/oauth2/v2/auth", true},
		{"https://github.com/login/oauth/authorize", false},
		{"https://login.microsoftonline.com/common/oauth2/v2.0/authorize", false},
		{"not-a-url", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isGoogleAuthorizeURL(tc.in); got != tc.want {
			t.Fatalf("isGoogleAuthorizeURL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
