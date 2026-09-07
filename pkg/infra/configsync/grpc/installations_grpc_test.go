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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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
	_ context.Context, gatewayID ids.GatewayID, code string,
) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, in := range m.rows {
		if in.GatewayID == gatewayID && in.CatalogCode == code {
			out = append(out, in)
		}
	}
	return out, nil
}

func (m *memInstallations) ListPendingByGateway(
	_ context.Context, gatewayID ids.GatewayID,
) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, in := range m.rows {
		if in.GatewayID == gatewayID && in.Status == installationdomain.StatusPendingApproval {
			out = append(out, in)
		}
	}
	return out, nil
}

func (m *memInstallations) FindByID(
	_ context.Context, g ids.GatewayID, sub string, id ids.InstallationID,
) (*installationdomain.Installation, error) {
	for _, in := range m.rows {
		if in.GatewayID == g && in.PrincipalSub == sub && in.ID == id {
			return in, nil
		}
	}
	return nil, installationdomain.ErrNotFound
}

func (m *memInstallations) ListByPrincipalAndCode(
	_ context.Context, g ids.GatewayID, sub, code string,
) ([]*installationdomain.Installation, error) {
	if in, ok := m.rows[key(g, sub, code)]; ok {
		return []*installationdomain.Installation{in}, nil
	}
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

func (m *memInstallations) DeleteByID(
	_ context.Context, g ids.GatewayID, sub string, id ids.InstallationID,
) error {
	for k, in := range m.rows {
		if in.GatewayID == g && in.PrincipalSub == sub && in.ID == id {
			in.Status = installationdomain.StatusRevoked
			m.rows[k] = in
			return nil
		}
	}
	return installationdomain.ErrNotFound
}

// fakeRegistryEnsurer records the codes EnsureRegistry was asked to materialise.
type fakeRegistryEnsurer struct {
	ensured []string
	err     error
}

func (f *fakeRegistryEnsurer) Ensure(_ context.Context, _ ids.GatewayID, code string) error {
	if f.err != nil {
		return f.err
	}
	f.ensured = append(f.ensured, code)
	return nil
}

func dialInstallations(t *testing.T, repo installationdomain.Repository) *InstallationsClient {
	t.Helper()
	return dialInstallationsWithEnsurer(t, repo, nil)
}

func dialInstallationsWithEnsurer(t *testing.T, repo installationdomain.Repository, ensurer RegistryEnsurer) *InstallationsClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	service := NewInstallationsService(repo, ensurer, nil, discardLogger())
	snapshotpb.RegisterStoreInstallationsServer(gsrv, service)
	registerInstallationOperationsServer(gsrv, service)
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

func TestInstallationsClient_EnsureRegistryForwards(t *testing.T) {
	ensurer := &fakeRegistryEnsurer{}
	client := dialInstallationsWithEnsurer(t, newMemInstallations(), ensurer)
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	if err := client.Ensure(context.Background(), gatewayID, "app.linear/mcp"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(ensurer.ensured) != 1 || ensurer.ensured[0] != "app.linear/mcp" {
		t.Fatalf("EnsureRegistry did not reach the control-plane ensurer, got %+v", ensurer.ensured)
	}
}

func TestInstallationsClient_EnsureRegistryUnimplementedWithoutEnsurer(t *testing.T) {
	client := dialInstallations(t, newMemInstallations())
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	err := client.Ensure(context.Background(), gatewayID, "app.linear/mcp")
	if err == nil {
		t.Fatal("Ensure without a control-plane ensurer must error")
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Ensure err code = %v, want Unimplemented", status.Code(err))
	}
}

func TestInstallationsClient_CompleteRepositoryContract(t *testing.T) {
	repo := newMemInstallations()
	client := dialInstallations(t, repo)
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	in, err := installationdomain.New(gatewayID, "alice", "github", "alice", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Upsert(context.Background(), in); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	byID, err := client.FindByID(context.Background(), gatewayID, "alice", in.ID)
	if err != nil || byID.ID != in.ID {
		t.Fatalf("FindByID = (%+v, %v), want %s", byID, err, in.ID)
	}
	byPrincipalAndCode, err := client.ListByPrincipalAndCode(context.Background(), gatewayID, "alice", "github")
	if err != nil || len(byPrincipalAndCode) != 1 {
		t.Fatalf("ListByPrincipalAndCode = (%+v, %v), want one row", byPrincipalAndCode, err)
	}
	byCode, err := client.ListByCatalogCode(context.Background(), gatewayID, "github")
	if err != nil || len(byCode) != 1 {
		t.Fatalf("ListByCatalogCode = (%+v, %v), want one row", byCode, err)
	}
	in.Status = installationdomain.StatusPendingApproval
	if err := client.Upsert(context.Background(), in); err != nil {
		t.Fatalf("Upsert pending: %v", err)
	}
	pending, err := client.ListPendingByGateway(context.Background(), gatewayID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingByGateway = (%+v, %v), want one row", pending, err)
	}
	if err := client.DeleteByID(context.Background(), gatewayID, "alice", in.ID); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	revoked, err := client.FindByID(context.Background(), gatewayID, "alice", in.ID)
	if err != nil || revoked.Status != installationdomain.StatusRevoked {
		t.Fatalf("FindByID after delete = (%+v, %v), want revoked", revoked, err)
	}
}

func TestInstallationsOperationsAreRegisteredByServer(t *testing.T) {
	cfg := config.ConfigSyncConfig{
		GRPCListenAddr:       "127.0.0.1:0",
		Token:                "tok",
		GRPCKeepaliveTime:    30 * time.Second,
		GRPCKeepaliveTimeout: 10 * time.Second,
	}
	auth, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger())
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	source := &fakeSource{}
	source.set([]byte("payload"), "v1")
	installations := NewInstallationsService(newMemInstallations(), nil, nil, discardLogger())
	server, err := NewServer(cfg, NewService(NewHub(discardLogger(), nil), source, discardLogger()), installations, auth, discardLogger())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = server.Run() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	conn, err := grpc.NewClient(server.lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(bearerPerRPCCredentials{token: "tok"}),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := NewInstallationsClient(conn)
	gatewayID, _ := ids.NewV7[ids.GatewayKind]()
	items, err := client.ListPendingByGateway(context.Background(), gatewayID)
	if err != nil {
		t.Fatalf("ListPendingByGateway: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("ListPendingByGateway = %+v, want empty", items)
	}
}

// fakeGateways resolves gateways by id for the tenant check.
type fakeGateways struct {
	byID map[ids.GatewayID]*gatewaydomain.Gateway
}

func (f *fakeGateways) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if gw, ok := f.byID[id]; ok {
		return gw, nil
	}
	return nil, gatewaydomain.ErrNotFound
}

func tenantGateway(t *testing.T, tenant string) *gatewaydomain.Gateway {
	t.Helper()
	id, err := ids.NewV7[ids.GatewayKind]()
	if err != nil {
		t.Fatalf("gateway id: %v", err)
	}
	return &gatewaydomain.Gateway{ID: id, Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: tenant}}
}

func protoInstall(t *testing.T, gw ids.GatewayID, sub, code string) *snapshotpb.Installation {
	t.Helper()
	in, err := installationdomain.New(gw, sub, code, sub, nil)
	if err != nil {
		t.Fatalf("new installation: %v", err)
	}
	return installationToProto(in)
}

// A scoped data plane (per-instance token) must not read or write another
// tenant's installations, whatever gateway_id it puts on the wire — the same
// isolation the snapshot RPCs enforce through ScopeFromContext.
func TestInstallationsService_ScopedCallerCannotReachOtherTenant(t *testing.T) {
	acme := tenantGateway(t, "acme")
	globex := tenantGateway(t, "globex")
	repo := newMemInstallations()
	svc := NewInstallationsService(repo, &fakeRegistryEnsurer{}, &fakeGateways{
		byID: map[ids.GatewayID]*gatewaydomain.Gateway{acme.ID: acme, globex.ID: globex},
	}, discardLogger())

	// Seed a globex row directly so a refused Find is provably not "empty".
	seed, _ := installationdomain.New(globex.ID, "victim", "github", "victim", nil)
	_ = repo.Upsert(context.Background(), seed)

	scoped := WithScope(context.Background(), acme.ID.String())

	if _, err := svc.Upsert(scoped, &snapshotpb.UpsertInstallationRequest{Installation: protoInstall(t, globex.ID, "mallory", "github")}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Upsert for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.Find(scoped, &snapshotpb.FindInstallationRequest{GatewayId: globex.ID.String(), PrincipalSub: "victim", CatalogCode: "github"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Find for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.ListByPrincipal(scoped, &snapshotpb.ListByPrincipalRequest{GatewayId: globex.ID.String(), PrincipalSub: "victim"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListByPrincipal for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.FindByID(scoped, &snapshotpb.Installation{GatewayId: globex.ID.String(), PrincipalSub: "victim", Id: seed.ID.String()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("FindByID for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.ListByPrincipalAndCode(scoped, &snapshotpb.FindInstallationRequest{GatewayId: globex.ID.String(), PrincipalSub: "victim", CatalogCode: "github"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListByPrincipalAndCode for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.ListByCatalogCode(scoped, &snapshotpb.FindInstallationRequest{GatewayId: globex.ID.String(), CatalogCode: "github"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListByCatalogCode for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.ListPendingByGateway(scoped, &snapshotpb.ListByPrincipalRequest{GatewayId: globex.ID.String()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListPendingByGateway for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.Delete(scoped, &snapshotpb.DeleteInstallationRequest{GatewayId: globex.ID.String(), PrincipalSub: "victim", CatalogCode: "github"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Delete for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.DeleteByID(scoped, &snapshotpb.Installation{GatewayId: globex.ID.String(), PrincipalSub: "victim", Id: seed.ID.String()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DeleteByID for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.EnsureRegistry(scoped, &snapshotpb.EnsureRegistryRequest{GatewayId: globex.ID.String(), CatalogCode: "github"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("EnsureRegistry for another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, ok := repo.rows[key(globex.ID, "victim", "github")]; !ok {
		t.Fatal("the refused Delete must not have removed the other tenant's row")
	}

	unknown, _ := ids.NewV7[ids.GatewayKind]()
	if _, err := svc.Find(scoped, &snapshotpb.FindInstallationRequest{GatewayId: unknown.String(), PrincipalSub: "x", CatalogCode: "y"}); status.Code(err) != codes.NotFound {
		t.Fatalf("Find for an unknown gateway: code = %v, want NotFound", status.Code(err))
	}
}

func TestInstallationsService_ScopedCallerReachesOwnScope(t *testing.T) {
	acme := tenantGateway(t, "acme")
	acme2 := tenantGateway(t, "acme")
	repo := newMemInstallations()
	svc := NewInstallationsService(repo, &fakeRegistryEnsurer{}, &fakeGateways{
		byID: map[ids.GatewayID]*gatewaydomain.Gateway{acme.ID: acme, acme2.ID: acme2},
	}, discardLogger())

	// Instance scope: the scoped gateway itself.
	byGateway := WithScope(context.Background(), acme.ID.String())
	if _, err := svc.Upsert(byGateway, &snapshotpb.UpsertInstallationRequest{Installation: protoInstall(t, acme.ID, "alice", "github")}); err != nil {
		t.Fatalf("Upsert on the scoped gateway: %v", err)
	}
	found, err := svc.Find(byGateway, &snapshotpb.FindInstallationRequest{GatewayId: acme.ID.String(), PrincipalSub: "alice", CatalogCode: "github"})
	if err != nil || !found.GetFound() {
		t.Fatalf("Find on the scoped gateway = (%v, %v), want found", found, err)
	}

	// Tenant scope: another gateway of the same tenant.
	byTenant := WithScope(context.Background(), "acme")
	if _, err := svc.Upsert(byTenant, &snapshotpb.UpsertInstallationRequest{Installation: protoInstall(t, acme2.ID, "bob", "github")}); err != nil {
		t.Fatalf("Upsert on a same-tenant gateway: %v", err)
	}
	if _, err := svc.Delete(byTenant, &snapshotpb.DeleteInstallationRequest{GatewayId: acme2.ID.String(), PrincipalSub: "bob", CatalogCode: "github"}); err != nil {
		t.Fatalf("Delete on a same-tenant gateway: %v", err)
	}

	// Unscoped (shared token) sees everything, as its snapshot does.
	if _, err := svc.Find(context.Background(), &snapshotpb.FindInstallationRequest{GatewayId: acme.ID.String(), PrincipalSub: "alice", CatalogCode: "github"}); err != nil {
		t.Fatalf("unscoped Find: %v", err)
	}
}

func TestInstallationsService_UpsertValidatesWireRecord(t *testing.T) {
	gw := tenantGateway(t, "acme")
	svc := NewInstallationsService(newMemInstallations(), nil, &fakeGateways{
		byID: map[ids.GatewayID]*gatewaydomain.Gateway{gw.ID: gw},
	}, discardLogger())
	ctx := WithScope(context.Background(), gw.ID.String())

	bogus := protoInstall(t, gw.ID, "alice", "github")
	bogus.Status = "approved-by-me"
	if _, err := svc.Upsert(ctx, &snapshotpb.UpsertInstallationRequest{Installation: bogus}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Upsert with an unknown status: code = %v, want InvalidArgument", status.Code(err))
	}

	forged := protoInstall(t, gw.ID, "alice", "github")
	forged.InstalledBy = "admin"
	if _, err := svc.Upsert(ctx, &snapshotpb.UpsertInstallationRequest{Installation: forged}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Upsert with installed_by != principal_sub: code = %v, want PermissionDenied", status.Code(err))
	}

	anonymous := protoInstall(t, gw.ID, "alice", "github")
	anonymous.PrincipalSub = ""
	anonymous.InstalledBy = ""
	if _, err := svc.Upsert(ctx, &snapshotpb.UpsertInstallationRequest{Installation: anonymous}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Upsert without a principal: code = %v, want InvalidArgument", status.Code(err))
	}

	ok := protoInstall(t, gw.ID, "alice", "github")
	ok.Status = string(installationdomain.StatusPendingApproval)
	if _, err := svc.Upsert(ctx, &snapshotpb.UpsertInstallationRequest{Installation: ok}); err != nil {
		t.Fatalf("Upsert of a valid pending record: %v", err)
	}
}
