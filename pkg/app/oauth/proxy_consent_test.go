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
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func consentTestRequest(redirectURI string) AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "agw-abc",
		RedirectURI:         redirectURI,
		State:               "client-state",
		CodeChallenge:       s256("v"),
		CodeChallengeMethod: "S256",
	}
}

func newConsentProxy(t *testing.T, redirectURI string) (AuthProxy, *memFlowStore, string) {
	t.Helper()
	idp, _ := fakeIdP(t)
	store := newMemFlowStore()
	_ = store.SaveGatewayClient(context.Background(), RegisteredGatewayClient{ClientID: "agw-abc", RedirectURIs: []string{redirectURI}})
	return newProxyUnderTest(t, idp.URL, store), store, idp.URL
}

func TestAuthorizeParksTheIdPLegForConsent(t *testing.T) {
	t.Parallel()
	proxy, store, idpURL := newConsentProxy(t, "https://client.example.com/cb")

	res, err := proxy.Authorize(context.Background(), "http://gw.example.com", consentTestRequest("https://client.example.com/cb"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if res.ConsentState == "" || !strings.HasPrefix(res.Location, idpURL+"/authorize?") {
		t.Fatalf("expected a parked IdP leg, got %+v", res)
	}
	pending, ok := store.pending[res.ConsentState]
	if !ok || pending.AuthorizeURL != res.Location {
		t.Fatalf("the IdP redirect must be parked under the consent state, got %+v", pending)
	}
}

func TestAuthorizeClientRedirectNeverAsksForConsent(t *testing.T) {
	t.Parallel()
	redirect := "https://client.example.com/cb?tab=1"
	store := newMemFlowStore()
	_ = store.SaveGatewayClient(context.Background(), RegisteredGatewayClient{ClientID: "agw-abc", RedirectURIs: []string{redirect}})
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/cons/mcp": {{GatewayID: ids.New[ids.GatewayKind](), Auths: nil}},
	}}
	proxy := NewAuthProxy(&fakeCredentialFinder{}, paths, http.DefaultClient, store, nil, nil, nil)
	req := consentTestRequest(redirect)
	req.Resource = "http://gw.example.com/cons/mcp"

	res, err := proxy.Authorize(context.Background(), "http://gw.example.com", req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if res.ConsentState != "" {
		t.Fatalf("a client redirect must not be treated as an IdP leg, got %+v", res)
	}
	if u, _ := url.Parse(res.Location); u == nil || u.Query().Get("error") != "invalid_target" {
		t.Fatalf("expected the refusal on the client redirect, got %q", res.Location)
	}
	if len(store.pending) != 0 {
		t.Fatal("nothing may be parked for a refused request")
	}
}

func TestApproveReleasesTheParkedIdPRedirect(t *testing.T) {
	t.Parallel()
	proxy, store, _ := newConsentProxy(t, "https://client.example.com/cb")
	res, err := proxy.Authorize(context.Background(), "http://gw.example.com", consentTestRequest("https://client.example.com/cb"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	location, err := proxy.Approve(context.Background(), res.ConsentState)
	if err != nil || location != res.Location {
		t.Fatalf("approve = %q, %v; want the parked IdP redirect", location, err)
	}
	if _, ok := store.pending[res.ConsentState]; !ok {
		t.Fatal("approval must leave the authorization parked for the callback")
	}

	var oe *OAuthError
	if _, err := proxy.Approve(context.Background(), "unknown-state"); !errors.As(err, &oe) || oe.Code != "invalid_request" {
		t.Fatalf("approving an unknown state must fail with invalid_request, got %v", err)
	}
}

func TestDenyReportsAccessDeniedToTheClient(t *testing.T) {
	t.Parallel()
	proxy, store, _ := newConsentProxy(t, "https://client.example.com/cb")
	res, err := proxy.Authorize(context.Background(), "http://gw.example.com", consentTestRequest("https://client.example.com/cb"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	location, err := proxy.Deny(context.Background(), res.ConsentState)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	u, _ := url.Parse(location)
	if u == nil || u.Host != "client.example.com" || u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "client-state" {
		t.Fatalf("expected access_denied on the client redirect, got %q", location)
	}
	if _, ok := store.pending[res.ConsentState]; ok {
		t.Fatal("a denied authorization must not stay parked")
	}
}

func TestCallbackRedeemsOnlyApprovedAuthorizations(t *testing.T) {
	t.Parallel()
	proxy, store, _ := newConsentProxy(t, "https://client.example.com/cb")
	res, err := proxy.Authorize(context.Background(), "http://gw.example.com", consentTestRequest("https://client.example.com/cb"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	_, err = proxy.Callback(context.Background(), "http://gw.example.com", res.ConsentState, "idp-code", "", "")
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "access_denied" {
		t.Fatalf("an authorization nobody approved must not be redeemed, got %v", err)
	}
	if len(store.codes) != 0 {
		t.Fatal("no gateway code may be minted for an unapproved authorization")
	}
}
