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

package grpc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

var _ snapshotpb.StoreInstallationsServer = (*InstallationsService)(nil)

// memInstallations is a tiny in-memory installation repository for the transport
// round-trip test, keyed by (gateway, principal, code).
type memInstallations struct {
	rows map[string]*installationdomain.Installation
}

func newMemInstallations() *memInstallations {
	return &memInstallations{rows: map[string]*installationdomain.Installation{}}
}

func key(g ids.GatewayID, sub, code string) string { return g.String() + "|" + sub + "|" + code }

func (m *memInstallations) Upsert(_ context.Context, in *installationdomain.Installation) error {
	m.rows[key(in.GatewayID, in.PrincipalSub, in.CatalogCode)] = in
	return nil
}

func (m *memInstallations) Find(
	_ context.Context, g ids.GatewayID, sub, code string,
) (*installationdomain.Installation, error) {
	if in, ok := m.rows[key(g, sub, code)]; ok {
		return in, nil
	}
	return nil, installationdomain.ErrNotFound
}

func (m *memInstallations) ListByPrincipal(
	_ context.Context, g ids.GatewayID, sub string,
) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, in := range m.rows {
		if in.GatewayID == g && in.PrincipalSub == sub {
			out = append(out, in)
		}
	}
	return out, nil
}

func (m *memInstallations) ListByCatalogCode(
	context.Context, ids.GatewayID, string,
) ([]*installationdomain.Installation, error) {
	return nil, nil
}

func (m *memInstallations) ListPendingByGateway(
	context.Context, ids.GatewayID,
) ([]*installationdomain.Installation, error) {
	return nil, nil
}

func (m *memInstallations) Delete(_ context.Context, g ids.GatewayID, sub, code string) error {
	k := key(g, sub, code)
	if _, ok := m.rows[k]; !ok {
		return installationdomain.ErrNotFound
	}
	delete(m.rows, k)
	return nil
}

func dialInstallations(t *testing.T, repo installationdomain.Repository) *InstallationsClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	snapshotpb.RegisterStoreInstallationsServer(gsrv, NewInstallationsService(repo, discardLogger()))
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return NewInstallationsClient(conn)
}

func TestInstallationsClient_RoundTrip(t *testing.T) {
	repo := newMemInstallations()
	client := dialInstallations(t, repo)
	ctx := context.Background()

	gatewayID, err := ids.NewV7[ids.GatewayKind]()
	if err != nil {
		t.Fatalf("gateway id: %v", err)
	}
	in, err := installationdomain.New(gatewayID, "user-sub", "github", "user-sub", map[string]string{"host": "acme"})
	if err != nil {
		t.Fatalf("new installation: %v", err)
	}

	if err := client.Upsert(ctx, in); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := client.Find(ctx, gatewayID, "user-sub", "github")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.ID != in.ID || got.CatalogCode != "github" || got.Status != installationdomain.StatusInstalled {
		t.Fatalf("Find returned %+v, want id=%s code=github installed", got, in.ID)
	}
	if got.Config["host"] != "acme" {
		t.Fatalf("Find lost config: %+v", got.Config)
	}

	list, err := client.ListByPrincipal(ctx, gatewayID, "user-sub")
	if err != nil {
		t.Fatalf("ListByPrincipal: %v", err)
	}
	if len(list) != 1 || list[0].CatalogCode != "github" {
		t.Fatalf("ListByPrincipal = %+v, want one github row", list)
	}

	if err := client.Delete(ctx, gatewayID, "user-sub", "github"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := client.Find(ctx, gatewayID, "user-sub", "github"); !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("Find after delete err = %v, want ErrNotFound", err)
	}
}

func TestInstallationsClient_FindMissingIsNotFound(t *testing.T) {
	client := dialInstallations(t, newMemInstallations())
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	if _, err := client.Find(context.Background(), gatewayID, "nobody", "ghost"); !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("Find err = %v, want ErrNotFound", err)
	}
}

func TestInstallationsClient_DeleteMissingIsNotFound(t *testing.T) {
	client := dialInstallations(t, newMemInstallations())
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	if err := client.Delete(context.Background(), gatewayID, "nobody", "ghost"); !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("Delete err = %v, want ErrNotFound", err)
	}
}

func TestInstallationsClient_AdminQueriesUnsupported(t *testing.T) {
	client := dialInstallations(t, newMemInstallations())
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	if _, err := client.ListByCatalogCode(context.Background(), gatewayID, "github"); !errors.Is(err, errDataPlaneAdminUnsupported) {
		t.Fatalf("ListByCatalogCode err = %v, want errDataPlaneAdminUnsupported", err)
	}
	if _, err := client.ListPendingByGateway(context.Background(), gatewayID); !errors.Is(err, errDataPlaneAdminUnsupported) {
		t.Fatalf("ListPendingByGateway err = %v, want errDataPlaneAdminUnsupported", err)
	}
}
