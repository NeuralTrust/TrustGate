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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// slotDropRegistrar serves one registered client per authorization server, both
// under the same client_id. A drop that re-discovers after the install values
// flip would tombstone the second server's client.
type slotDropRegistrar struct {
	clients    map[string]*RegisteredClient
	discovered []string
	dropped    []string
}

func (r *slotDropRegistrar) Discover(_ context.Context, upstream string) (*UpstreamAuthServer, error) {
	r.discovered = append(r.discovered, upstream)
	host := upstreamHost(upstream)
	return &UpstreamAuthServer{
		AuthorizationEndpoint: "https://" + host + "/authorize",
		TokenEndpoint:         "https://" + host + "/token",
		ValidatedIssuer:       "https://" + host,
	}, nil
}

func (r *slotDropRegistrar) EnsureClient(context.Context, string, *UpstreamAuthServer, string) (*RegisteredClient, error) {
	return nil, errors.New("drop-slot test must not register a client")
}

func (r *slotDropRegistrar) CachedClient(_ context.Context, key string) (*RegisteredClient, error) {
	client := r.clients[key]
	if client == nil {
		return nil, nil
	}
	out := *client
	return &out, nil
}

func (r *slotDropRegistrar) DropCachedClient(_ context.Context, key, clientID string) error {
	r.dropped = append(r.dropped, key)
	client := r.clients[key]
	if client != nil && client.ClientID == clientID {
		client.ClientSecretExpiresAt = 1
	}
	return nil
}

func issuerMeta(host string) *UpstreamAuthServer {
	return &UpstreamAuthServer{ValidatedIssuer: "https://" + host}
}

// The failing exchange and refresh read the install once. The values then name
// another authorization server that stores the same client_id. The drop must
// tombstone only the slot the failing call used.
func TestDropUsesTheSlotFromTheFailingCall(t *testing.T) {
	t.Parallel()
	const (
		first    = "evil.example"
		second   = "victim.example"
		sharedID = "shared-client"
	)

	type call struct {
		name string
		run  func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) error
	}
	calls := []call{
		{
			name: "exchange",
			run: func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) error {
				auth, err := s.exchangeAuth(ctx, "https://gw.example.com", gw, "alice", reg, sharedID)
				if err != nil {
					return err
				}
				s.rejectDynamicClient(ctx, gw, reg, auth.ClientID, auth.ClientSlot)
				return nil
			},
		},
		{
			name: "refresh",
			run: func(s *connectService, ctx context.Context, gw ids.GatewayID, reg *registrydomain.Registry) error {
				auth, err := s.RefreshAuth(ctx, gw, reg)
				if err != nil {
					return err
				}
				return s.DropRegisteredClient(ctx, gw, reg, auth.ClientID, auth.ClientSlot)
			},
		},
	}

	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gw := ids.New[ids.GatewayKind]()
			reg := flippingAutoRegistry()
			original := clientCacheKey(gw, reg, issuerMeta(first))
			victim := clientCacheKey(gw, reg, issuerMeta(second))
			if original == victim {
				t.Fatal("the two authorization servers share a cache key")
			}
			registrar := &slotDropRegistrar{clients: map[string]*RegisteredClient{
				original: {ClientID: sharedID, ClientSecret: "original-secret"},
				victim:   {ClientID: sharedID, ClientSecret: "victim-secret"},
			}}
			flip := &flippingURLValues{values: []map[string]string{
				{"account_url": first},
				{"account_url": second},
			}}
			svc := &connectService{registrar: registrar, urlValues: flip}
			ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice"})

			if err := tc.run(svc, ctx, gw, reg); err != nil {
				t.Fatalf("call: %v", err)
			}
			if flip.calls != 1 {
				t.Fatalf("install values read %d times, want the failing call's resolution only", flip.calls)
			}
			if len(registrar.discovered) != 1 || registrar.discovered[0] != "https://"+first+"/mcp" {
				t.Fatalf("discovered %v, want only the first host", registrar.discovered)
			}
			if len(registrar.dropped) != 1 || registrar.dropped[0] != original {
				t.Fatalf("dropped %v, want only %s", registrar.dropped, original)
			}
			if registrar.clients[original].ClientSecretExpiresAt != 1 {
				t.Fatal("original slot was not tombstoned")
			}
			if registrar.clients[victim].ClientSecretExpiresAt != 0 {
				t.Fatal("the other server's client was tombstoned")
			}
		})
	}
}
