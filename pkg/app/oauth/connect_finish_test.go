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

package oauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

type finishFixture struct {
	svc      oauth.ConnectService
	handoff  oauth.ConnectHandoff
	store    *memConnectStore
	vault    *memVaultRepo
	gateway  ids.GatewayID
	consumer *consumerdomain.Consumer
}

// newFinishFixture builds the connect service and its handoff over one store.
// gateways and baseDomains decide the accepted start origins besides the
// callback origin; a nil gateways accepts only the callback origin.
func newFinishFixture(t *testing.T, gateways oauth.ConnectGatewayFinder, baseDomains ...string) finishFixture {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "gh-access", "expires_in": 3600})
	}))
	t.Cleanup(provider.Close)
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "github-mcp", "", &registrydomain.MCPTarget{
		URL: "https://up.example.com/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode: registrydomain.MCPAuthModeForwarded, Provider: "github",
			ClientID: "cid", ClientSecret: "csecret",
			AuthorizeURL: "https://github.com/login/oauth/authorize",
			TokenURL:     provider.URL,
			Scopes:       []string{"repo"},
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	consumer := &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Name: "Support Assistant",
		Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
	}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer:   consumer,
		Registries: []*registrydomain.Registry{reg},
	}})
	store := newMemConnectStore()
	vault := &memVaultRepo{}
	handoff := oauth.NewConnectHandoff(store, gateways, baseDomains...)
	svc := oauth.NewConnectService(
		store,
		vault,
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		infraoauth.NewUpstreamRegistrar(store, nil),
		discardConnectAuditor(),
		nil, nil, nil, nil,
		oauth.WithConnectHandoff(handoff),
	)
	return finishFixture{svc: svc, handoff: handoff, store: store, vault: vault, gateway: gw, consumer: consumer}
}

func TestConnectService_CallbackIsHandedBackToTheStartOrigin(t *testing.T) {
	t.Parallel()
	gateways := stubGatewayFinder{}
	fx := newFinishFixture(t, gateways, "gateway.example")
	gateways[fx.gateway] = &gatewaydomain.Gateway{ID: fx.gateway, Slug: "tenant"}
	ctx := context.Background()
	ticket, err := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}

	started, err := fx.svc.Start(ctx, "https://callback.example.com", "https://tenant.gateway.example", ticket, "github", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	authorize, _ := url.Parse(started.Location)
	if authorize.Query().Get("state") != started.State {
		t.Fatalf("authorize URL %q does not carry the started state", started.Location)
	}
	if got := authorize.Query().Get("redirect_uri"); got != "https://callback.example.com/oauth/callback/github" {
		t.Fatalf("redirect_uri = %q", got)
	}

	receipt, err := fx.handoff.ReceiveCallback(ctx, "github", started.State, "the-code", "", "")
	if err != nil {
		t.Fatalf("ReceiveCallback: %v", err)
	}
	location := receipt.FinishURL
	if !strings.HasPrefix(location, "https://tenant.gateway.example"+oauth.ConnectFinishPath+"?f=") {
		t.Fatalf("location = %q, want the finish path on the start origin", location)
	}
	if _, ok := fx.store.connects[started.State]; !ok {
		t.Fatal("receiving the callback must leave the started authorization in place")
	}
	if len(fx.vault.creds) != 0 {
		t.Fatal("receiving the callback must not store a credential")
	}

	u, _ := url.Parse(location)
	token := u.Query().Get("f")
	finish, err := fx.handoff.TakeFinish(ctx, token)
	if err != nil {
		t.Fatalf("TakeFinish: %v", err)
	}
	want := oauth.ConnectFinish{Provider: "github", State: started.State, Code: "the-code"}
	if *finish != want {
		t.Fatalf("finish = %+v, want %+v", *finish, want)
	}
	if _, err := fx.handoff.TakeFinish(ctx, token); !errors.Is(err, oauth.ErrConnectFinishNotFound) {
		t.Fatalf("second TakeFinish err = %v, want ErrConnectFinishNotFound", err)
	}

	if _, err := fx.svc.Callback(ctx, "https://callback.example.com", finish.Provider, finish.State, finish.Code, "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if _, err := fx.vault.Find(ctx, fx.gateway, "alice", vaultKey(t, "github", "https://up.example.com/mcp")); err != nil {
		t.Fatalf("credential not stored after finishing: %v", err)
	}
}

func TestConnectService_ProviderErrorsAreHandedBackToo(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t, nil)
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	started, err := fx.svc.Start(ctx, "https://gw.example", "https://gw.example", ticket, "github", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	receipt, err := fx.handoff.ReceiveCallback(ctx, "github", started.State, "", "access_denied", "no")
	if err != nil {
		t.Fatalf("ReceiveCallback: %v", err)
	}
	location := receipt.FinishURL
	u, _ := url.Parse(location)
	finish, err := fx.handoff.TakeFinish(ctx, u.Query().Get("f"))
	if err != nil {
		t.Fatalf("TakeFinish: %v", err)
	}
	if finish.ErrCode != "access_denied" || finish.ErrDesc != "no" || finish.Code != "" {
		t.Fatalf("finish = %+v", finish)
	}
}

func TestConnectService_ReceiveCallbackRefusesAnUnknownState(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t, nil)
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	started, err := fx.svc.Start(ctx, "https://gw.example", "https://gw.example", ticket, "github", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	for name, tc := range map[string]struct{ provider, state string }{
		"unknown state":  {"github", "nope"},
		"empty state":    {"github", ""},
		"other provider": {"linear", started.State},
	} {
		if _, err := fx.handoff.ReceiveCallback(ctx, tc.provider, tc.state, "c", "", ""); err == nil {
			t.Fatalf("%s: ReceiveCallback accepted it", name)
		}
	}
	if len(fx.store.finishes) != 0 {
		t.Fatalf("a refused callback left %d finish records", len(fx.store.finishes))
	}
	if _, err := fx.svc.Start(ctx, "https://gw.example", "", ticket, "github", ""); err == nil {
		t.Fatal("Start must refuse an empty start origin")
	}
	if _, err := fx.handoff.TakeFinish(ctx, ""); !errors.Is(err, oauth.ErrConnectFinishNotFound) {
		t.Fatalf("empty finish token err = %v", err)
	}
}

func TestConnectService_PageNamesWhoAccountsAreLinkedTo(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t, nil)
	ctx := context.Background()
	endUser := consumerdomain.EndUserSubject(fx.consumer.ID, "user-42")
	app := consumerdomain.AppSubject(fx.consumer.ID)
	other := consumerdomain.EndUserSubject(ids.New[ids.ConsumerKind](), "user-42")
	cases := map[string]oauth.ConnectPrincipal{
		endUser:          {Subject: endUser, Application: "Support Assistant", EndUser: "user-42"},
		app:              {Subject: app, Application: "Support Assistant"},
		"user-subject-1": {Subject: "user-subject-1"},
		other:            {Subject: other},
	}
	for subject, want := range cases {
		ticket, err := fx.svc.CreateTicket(ctx, fx.gateway, subject, "/dev/mcp")
		if err != nil {
			t.Fatalf("%s: CreateTicket: %v", subject, err)
		}
		page, err := fx.svc.Page(ctx, ticket)
		if err != nil {
			t.Fatalf("%s: Page: %v", subject, err)
		}
		if page.Principal != want {
			t.Fatalf("%s: principal = %+v, want %+v", subject, page.Principal, want)
		}
	}
}

func TestConnectService_RepeatedCallbacksKeepOnePendingFinish(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t, nil)
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	started, err := fx.svc.Start(ctx, "https://gw.example", "https://gw.example", ticket, "github", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	var last string
	for range 5 {
		receipt, err := fx.handoff.ReceiveCallback(ctx, "github", started.State, "the-code", "", "")
		if err != nil {
			t.Fatalf("ReceiveCallback: %v", err)
		}
		last = receipt.FinishURL
	}
	if len(fx.store.finishes) != 1 {
		t.Fatalf("pending finishes = %d, want 1", len(fx.store.finishes))
	}
	u, _ := url.Parse(last)
	if _, err := fx.handoff.TakeFinish(ctx, u.Query().Get("f")); err != nil {
		t.Fatalf("the latest finish must be the one kept: %v", err)
	}
}

// An authorization saved by the version before start origins were recorded
// has none; its callback completes on the callback itself, as it did then.
func TestConnectService_StatesWithoutAStartOriginCompleteOnTheCallback(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t, nil)
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	started, err := fx.svc.Start(ctx, "https://gw.example", "https://gw.example", ticket, "github", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	legacy := fx.store.connects[started.State]
	legacy.StartOrigin = ""
	fx.store.connects[started.State] = legacy

	receipt, err := fx.handoff.ReceiveCallback(ctx, "github", started.State, "the-code", "", "")
	if err != nil {
		t.Fatalf("ReceiveCallback: %v", err)
	}
	if !receipt.Direct || receipt.FinishURL != "" || len(fx.store.finishes) != 0 {
		t.Fatalf("receipt = %+v, finishes = %d; want a direct completion and no finish record", receipt, len(fx.store.finishes))
	}
	if _, ok := fx.store.connects[started.State]; !ok {
		t.Fatal("receiving the callback must leave the state for Callback to use")
	}
	if _, err := fx.svc.Callback(ctx, "https://gw.example", "github", started.State, "the-code", "", ""); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if _, err := fx.vault.Find(ctx, fx.gateway, "alice", vaultKey(t, "github", "https://up.example.com/mcp")); err != nil {
		t.Fatalf("credential not stored: %v", err)
	}
}
