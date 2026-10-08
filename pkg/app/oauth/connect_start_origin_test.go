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
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type stubGatewayFinder map[ids.GatewayID]*gatewaydomain.Gateway

func (f stubGatewayFinder) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if gw, ok := f[id]; ok {
		return gw, nil
	}
	return nil, commonerrors.ErrNotFound
}

func TestConnectService_StartsOnlyFromTheTicketGatewaysOwnHosts(t *testing.T) {
	t.Parallel()
	gateways := stubGatewayFinder{}
	fx := newFinishFixture(t, oauth.WithConnectStartOrigins(gateways, "mcp.example.com", " MCP.Sandbox.example. "))
	gateways[fx.gateway] = &gatewaydomain.Gateway{ID: fx.gateway, Slug: "acme", Domain: "mcp.acme-corp.com"}
	ctx := context.Background()
	ticket, err := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	const callback = "https://gateway-mcp.example.com"
	cases := []struct {
		origin string
		want   string
	}{
		{callback, callback},
		{"HTTPS://Gateway-MCP.example.com:443", callback},
		{"https://acme.mcp.example.com", "https://acme.mcp.example.com"},
		{"https://ACME.mcp.example.com", "https://acme.mcp.example.com"},
		{"https://acme.mcp.example.com:443", "https://acme.mcp.example.com"},
		{"https://acme.mcp.sandbox.example", "https://acme.mcp.sandbox.example"},
		{"https://mcp.acme-corp.com", ""},
		{"http://acme.mcp.example.com", ""},
		{"https://acme.mcp.example.com:8443", ""},
		{"https://acme.mcp.example.com/", ""},
		{"https://acme.mcp.example.com/path", ""},
		{"https://acme.mcp.example.com?x=1", ""},
		{"https://acme.mcp.example.com#x", ""},
		{"https://user@acme.mcp.example.com", ""},
		{"https:acme.mcp.example.com", ""},
		{"https://other.mcp.example.com", ""},
		{"https://a.acme.mcp.example.com", ""},
		{"https://acme.mcp.example.com.elsewhere.example", ""},
		{"https://mcp.example.com", ""},
		{"https://elsewhere.example", ""},
		{"ftp://acme.mcp.example.com", ""},
		{"", ""},
	}
	for _, tc := range cases {
		before := len(fx.store.connects)
		_, err := fx.svc.Start(ctx, callback, tc.origin, ticket, "github", "")
		got, checkErr := fx.svc.StartOrigin(ctx, callback, tc.origin, ticket)
		if tc.want == "" {
			if !errors.Is(err, oauth.ErrStartOriginNotServed) || !errors.Is(checkErr, oauth.ErrStartOriginNotServed) {
				t.Fatalf("%q: errs = %v / %v, want ErrStartOriginNotServed", tc.origin, err, checkErr)
			}
			if len(fx.store.connects) != before {
				t.Fatalf("%q: a refused start saved an authorization", tc.origin)
			}
			continue
		}
		if err != nil || checkErr != nil {
			t.Fatalf("%q: refused: %v / %v", tc.origin, err, checkErr)
		}
		if got != tc.want {
			t.Fatalf("%q: start origin = %q, want %q", tc.origin, got, tc.want)
		}
	}
	for state, st := range fx.store.connects {
		if st.StartOrigin != callback && st.StartOrigin != "https://acme.mcp.example.com" && st.StartOrigin != "https://acme.mcp.sandbox.example" {
			t.Fatalf("state %s stored start origin %q, want the rebuilt origin", state[:4], st.StartOrigin)
		}
	}
	if _, err := fx.svc.StartOrigin(ctx, callback, callback, "unknown-ticket"); !errors.Is(err, oauth.ErrTicketNotFound) {
		t.Fatalf("unknown ticket err = %v, want ErrTicketNotFound", err)
	}
}

func TestConnectService_HTTPStartOriginsOnlyWhenTheCallbackIsHTTP(t *testing.T) {
	t.Parallel()
	gateways := stubGatewayFinder{}
	fx := newFinishFixture(t, oauth.WithConnectStartOrigins(gateways, "mcp.localhost"))
	gateways[fx.gateway] = &gatewaydomain.Gateway{ID: fx.gateway, Slug: "acme"}
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	const callback = "http://localhost:8083"
	for origin, want := range map[string]string{
		"http://acme.mcp.localhost:8083": "http://acme.mcp.localhost:8083",
		"http://acme.mcp.localhost":      "http://acme.mcp.localhost",
		"http://acme.mcp.localhost:9000": "",
	} {
		got, err := fx.svc.StartOrigin(ctx, callback, origin, ticket)
		if want == "" {
			if !errors.Is(err, oauth.ErrStartOriginNotServed) {
				t.Fatalf("%s: err = %v, want ErrStartOriginNotServed", origin, err)
			}
			continue
		}
		if err != nil || got != want {
			t.Fatalf("%s: got %q, %v; want %q", origin, got, err, want)
		}
	}
}

func TestConnectService_StartOriginWithoutGatewayLookup(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t)
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")

	if _, err := fx.svc.Start(ctx, "http://localhost:8083", "http://localhost:8083", ticket, "github", ""); err != nil {
		t.Fatalf("a local plane starting and finishing on one origin was refused: %v", err)
	}
	if _, err := fx.svc.Start(ctx, "http://localhost:8083", "http://acme.mcp.example.com", ticket, "github", ""); !errors.Is(err, oauth.ErrStartOriginNotServed) {
		t.Fatalf("err = %v, want ErrStartOriginNotServed", err)
	}
}

func TestConnectService_StartOriginOfAnUnknownGatewayIsRefused(t *testing.T) {
	t.Parallel()
	fx := newFinishFixture(t, oauth.WithConnectStartOrigins(stubGatewayFinder{}, "mcp.example.com"))
	ctx := context.Background()
	ticket, _ := fx.svc.CreateTicket(ctx, fx.gateway, "alice", "/dev/mcp")
	if _, err := fx.svc.Start(ctx, "https://gateway-mcp.example.com", "https://acme.mcp.example.com", ticket, "github", ""); !errors.Is(err, oauth.ErrStartOriginNotServed) {
		t.Fatalf("err = %v, want ErrStartOriginNotServed", err)
	}
}
