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
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureDefaultSlog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func assertNoSecrets(t *testing.T, logged string) {
	t.Helper()
	for _, secret := range []string{
		"idp-code-secret",
		"gw-secret",
		"client_secret",
		"access_token",
		"refresh_token",
		"Bearer ",
		"authorization_code",
	} {
		if strings.Contains(logged, secret) {
			t.Fatalf("security log leaked %q: %s", secret, logged)
		}
	}
}

func TestIssuersEqual_SlashTrim(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "identical", a: "https://idp.example", b: "https://idp.example", want: true},
		{name: "trailing slash on a", a: "https://idp.example/", b: "https://idp.example", want: true},
		{name: "trailing slash on b", a: "https://idp.example", b: "https://idp.example/", want: true},
		{name: "both slashes", a: "https://idp.example/", b: "https://idp.example/", want: true},
		{name: "scheme differs", a: "http://idp.example", b: "https://idp.example", want: false},
		{name: "host differs", a: "https://a.example", b: "https://b.example", want: false},
		{name: "empty vs empty", a: "", b: "", want: true},
		{name: "empty vs value", a: "", b: "https://idp.example", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := issuersEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("issuersEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			if got := IssuersEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("IssuersEqual(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestValidateResponseISS(t *testing.T) {
	t.Parallel()
	const expected = "https://idp.example"
	cases := []struct {
		name       string
		got        string
		advertised bool
		wantErr    bool
	}{
		{name: "matching iss", got: expected, advertised: true, wantErr: false},
		{name: "matching iss slash trim", got: expected + "/", advertised: true, wantErr: false},
		{name: "matching iss not advertised", got: expected, advertised: false, wantErr: false},
		{name: "mismatch advertised", got: "https://attacker.example", advertised: true, wantErr: true},
		{name: "mismatch not advertised", got: "https://attacker.example", advertised: false, wantErr: true},
		{name: "missing iss advertised", got: "", advertised: true, wantErr: true},
		{name: "missing iss not advertised", got: "", advertised: false, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateResponseISS(tc.got, expected, tc.advertised)
			if tc.wantErr {
				var oe *OAuthError
				if !errors.As(err, &oe) || oe.Code != "invalid_request" {
					t.Fatalf("error = %v, want invalid_request", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestApplicationTypeForURIs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		uris []string
		want string
	}{
		{name: "https web", uris: []string{"https://app.example/cb"}, want: applicationTypeWeb},
		{name: "loopback ipv4", uris: []string{"http://127.0.0.1:33418/callback"}, want: applicationTypeNative},
		{name: "loopback localhost", uris: []string{"http://localhost:8080/cb"}, want: applicationTypeNative},
		{name: "loopback ipv6", uris: []string{"http://[::1]/cb"}, want: applicationTypeNative},
		{name: "private-use cursor", uris: []string{"cursor://anysphere.cursor-mcp/oauth/callback"}, want: applicationTypeNative},
		{name: "private-use reverse dns", uris: []string{"com.example.agent:/oauth2redirect"}, want: applicationTypeNative},
		{name: "mixed https and loopback", uris: []string{"https://app.example/cb", "http://127.0.0.1/cb"}, want: ""},
		{name: "mixed https and cursor", uris: []string{"https://app.example/cb", "cursor://anysphere.cursor-mcp/oauth/callback"}, want: ""},
		{name: "http non-loopback", uris: []string{"http://attacker.example/cb"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := applicationTypeForURIs(tc.uris); got != tc.want {
				t.Fatalf("applicationTypeForURIs(%v) = %q, want %q", tc.uris, got, tc.want)
			}
		})
	}
}

func TestResolveApplicationType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		requested string
		uris      []string
		want      string
		wantErr   bool
	}{
		{name: "omit infers web", requested: "", uris: []string{"https://app.example/cb"}, want: applicationTypeWeb},
		{name: "omit infers native loopback", requested: "", uris: []string{"http://127.0.0.1:1/cb"}, want: applicationTypeNative},
		{name: "omit infers native private-use", requested: "", uris: []string{"cursor://anysphere.cursor-mcp/oauth/callback"}, want: applicationTypeNative},
		{name: "native matches loopback", requested: "native", uris: []string{"http://localhost/cb"}, want: applicationTypeNative},
		{name: "web matches https", requested: "web", uris: []string{"https://app.example/cb"}, want: applicationTypeWeb},
		{name: "web with private-use rejected", requested: "web", uris: []string{"cursor://anysphere.cursor-mcp/oauth/callback"}, wantErr: true},
		{name: "native with https rejected", requested: "native", uris: []string{"https://app.example/cb"}, wantErr: true},
		{name: "unknown type rejected", requested: "service", uris: []string{"https://app.example/cb"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveApplicationType(tc.requested, tc.uris)
			if tc.wantErr {
				var oe *OAuthError
				if !errors.As(err, &oe) || oe.Code != "invalid_client_metadata" {
					t.Fatalf("error = %v, want invalid_client_metadata", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOAuthSecurityLogsOmitSecrets(t *testing.T) {
	buf := captureDefaultSlog(t)
	logIssuerMismatch("https://idp-a.example", "https://idp-b.example", "gw-1", "github", "gw-1|reg-1")
	logInvalidMetadata("https://idp-a.example", "https://attacker.example", "gw-1|reg-1")
	logged := buf.String()
	if !strings.Contains(logged, `"msg":"oauth.issuer_mismatch"`) {
		t.Fatalf("missing oauth.issuer_mismatch: %s", logged)
	}
	if !strings.Contains(logged, `"msg":"oauth.invalid_metadata"`) {
		t.Fatalf("missing oauth.invalid_metadata: %s", logged)
	}
	if !strings.Contains(logged, "https://idp-a.example") || !strings.Contains(logged, "gw-1") {
		t.Fatalf("expected issuer URLs and ids in log: %s", logged)
	}
	assertNoSecrets(t, logged)
}
