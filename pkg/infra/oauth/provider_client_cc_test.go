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
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestProviderClient_ClientCredentials_Basic(t *testing.T) {
	t.Parallel()
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-basic",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)

	p := NewProviderClient(srv.Client())
	tok, err := p.ClientCredentials(context.Background(), &registrydomain.MCPAuth{
		ClientID: "cid", ClientSecret: "csec",
		TokenURL:                srv.URL,
		TokenEndpointAuthMethod: registrydomain.TokenEndpointAuthClientSecretBasic,
		Resource:                "https://mcp.example/mcp",
		Scopes:                  []string{"mcp"},
	})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if tok.AccessToken != "tok-basic" {
		t.Fatalf("token = %q", tok.AccessToken)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:csec"))
	if gotAuth != want {
		t.Fatalf("Authorization = %q, want %q", gotAuth, want)
	}
	form, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if form.Get("grant_type") != "client_credentials" {
		t.Fatalf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("client_id") != "" || form.Get("client_secret") != "" {
		t.Fatalf("basic must not put credentials in body: %v", form)
	}
	if form.Get("resource") != "https://mcp.example/mcp" {
		t.Fatalf("resource = %q", form.Get("resource"))
	}
	if form.Get("scope") != "mcp" {
		t.Fatalf("scope = %q", form.Get("scope"))
	}
}

func TestProviderClient_ClientCredentials_Post(t *testing.T) {
	t.Parallel()
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-post",
			"token_type":   "Bearer",
			"expires_in":   60,
		})
	}))
	t.Cleanup(srv.Close)

	p := NewProviderClient(srv.Client())
	tok, err := p.ClientCredentials(context.Background(), &registrydomain.MCPAuth{
		ClientID: "cid", ClientSecret: "csec",
		TokenURL:                srv.URL,
		TokenEndpointAuthMethod: registrydomain.TokenEndpointAuthClientSecretPost,
	})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if tok.AccessToken != "tok-post" {
		t.Fatalf("token = %q", tok.AccessToken)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization = %q, want empty for post", gotAuth)
	}
	if !strings.Contains(gotBody, "client_id=cid") || !strings.Contains(gotBody, "client_secret=csec") {
		t.Fatalf("body missing credentials: %q", gotBody)
	}
}
