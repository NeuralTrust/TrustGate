//go:build functional

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

package consumer_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	catalogrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/catalog"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/stretchr/testify/require"
)

func markersAfter(t *testing.T, f fixture, afterSeq int64) []configsyncport.Marker {
	t.Helper()
	markers, _, err := outboxrepo.NewRepository(f.conn).ReadSince(context.Background(), afterSeq)
	require.NoError(t, err)
	return markers
}

func lastSeq(t *testing.T, f fixture) int64 {
	t.Helper()
	var seq int64
	require.NoError(t, f.conn.Pool.QueryRow(context.Background(), `SELECT COALESCE(MAX(seq), 0) FROM config_snapshot_outbox`).Scan(&seq))
	return seq
}

func gatewayMarker(id ids.GatewayID) configsyncport.Marker {
	return configsyncport.Marker{Kind: configsyncport.MarkerGateway, GatewayID: id}
}

func withoutSeq(markers []configsyncport.Marker) []configsyncport.Marker {
	out := make([]configsyncport.Marker, len(markers))
	for i, m := range markers {
		m.Seq = 0
		out[i] = m
	}
	return out
}

func TestOutboxMarkers_WritersNameWhatTheyDirty(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = f.conn.Pool.Exec(context.Background(), "TRUNCATE TABLE config_snapshot_outbox, providers_catalog CASCADE")
	})

	gwID := seedGateway(t, f.gw, "marked")
	beID := seedRegistry(t, f.be, gwID, "marked-be")
	c := validConsumer(t, gwID, "marked-consumer")
	var restampA, restampB ids.GatewayID

	cases := []struct {
		name  string
		write func(t *testing.T)
		want  func() []configsyncport.Marker
	}{
		{
			name: "consumer save names its gateway",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.Save(ctx, c))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "attach registry by consumer id resolves the gateway",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.AttachRegistry(ctx, c.ID, beID, weightPtr(1)))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "detach registry names the consumer's gateway",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.DetachRegistry(ctx, c.ID, beID))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "detach auth by consumer id resolves the gateway",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.DetachAuth(ctx, c.ID, ids.New[ids.AuthKind]()))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "detach policy by consumer id resolves the gateway",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.DetachPolicy(ctx, c.ID, ids.New[ids.PolicyKind]()))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "unlinking from a consumer that no longer exists leaves no marker",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.DetachAuth(ctx, ids.New[ids.ConsumerKind](), ids.New[ids.AuthKind]()))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{} },
		},
		{
			name: "consumer delete names its gateway",
			write: func(t *testing.T) {
				require.NoError(t, f.repo.Delete(ctx, gwID, c.ID))
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "registry save names its gateway",
			write: func(t *testing.T) {
				seedRegistry(t, f.be, gwID, "marked-be-2")
			},
			want: func() []configsyncport.Marker { return []configsyncport.Marker{gatewayMarker(gwID)} },
		},
		{
			name: "a plan restamp names every gateway of the tenant",
			write: func(t *testing.T) {
				for _, name := range []string{"restamp-a", "restamp-b"} {
					g, err := gatewaydomain.New(name)
					require.NoError(t, err)
					g.Metadata = map[string]string{"tenant_id": "marked-tenant"}
					require.NoError(t, f.gw.Save(ctx, g))
					if restampA.IsNil() {
						restampA = g.ID
					} else {
						restampB = g.ID
					}
				}
				before := lastSeq(t, f)
				_, err := f.gw.RestampEntitlementsByTenantID(ctx, "marked-tenant", gatewaydomain.Entitlements{Tier: "standard"})
				require.NoError(t, err)
				got := withoutSeq(markersAfter(t, f, before))
				require.ElementsMatch(t, []configsyncport.Marker{gatewayMarker(restampA), gatewayMarker(restampB)}, got)
			},
		},
		{
			name: "a catalog write names the catalog",
			write: func(t *testing.T) {
				r := catalogrepo.NewRepository(f.conn, outboxrepo.NewRepository(f.conn))
				require.NoError(t, r.UpsertProvider(ctx, &catalogdomain.Provider{Code: "marked-provider", DisplayName: "Marked", WireFormat: "openai", Source: "test"}))
			},
			want: func() []configsyncport.Marker {
				return []configsyncport.Marker{{Kind: configsyncport.MarkerCatalog}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := lastSeq(t, f)
			tc.write(t)
			if tc.want == nil {
				return
			}
			require.Equal(t, tc.want(), withoutSeq(markersAfter(t, f, before)))
		})
	}
}
