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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	oauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type fakeConfigCatalog struct {
	byCode map[string]catalogdomain.MCPServer
}

func (f fakeConfigCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	s, ok := f.byCode[code]
	return s, ok
}

// fakeInstalls is an in-memory installation repository keyed by instance id,
// with the same read semantics as the real one (Find prefers active rows).
type fakeInstalls struct {
	rows map[ids.InstallationID]*installationdomain.Installation
}

func (f *fakeInstalls) Upsert(_ context.Context, in *installationdomain.Installation) error {
	if f.rows == nil {
		f.rows = map[ids.InstallationID]*installationdomain.Installation{}
	}
	f.rows[in.ID] = in
	return nil
}

func (f *fakeInstalls) Find(ctx context.Context, gw ids.GatewayID, sub, code string) (*installationdomain.Installation, error) {
	rows, _ := f.ListByPrincipalAndCode(ctx, gw, sub, code)
	var pick *installationdomain.Installation
	for _, in := range rows {
		if pick == nil || (!pick.IsActive() && in.IsActive()) {
			pick = in
		}
	}
	if pick == nil {
		return nil, installationdomain.ErrNotFound
	}
	return pick, nil
}

func (f *fakeInstalls) ListByPrincipal(_ context.Context, gw ids.GatewayID, sub string) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, in := range f.rows {
		if in.GatewayID == gw && in.PrincipalSub == sub {
			out = append(out, in)
		}
	}
	return out, nil
}
func (f *fakeInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeInstalls) ListPendingByGateway(context.Context, ids.GatewayID) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeInstalls) Delete(context.Context, ids.GatewayID, string, string) error { return nil }

func (f *fakeInstalls) FindByID(_ context.Context, gw ids.GatewayID, sub string, id ids.InstallationID) (*installationdomain.Installation, error) {
	if in, ok := f.rows[id]; ok && in.GatewayID == gw && in.PrincipalSub == sub {
		return in, nil
	}
	return nil, installationdomain.ErrNotFound
}

func (f *fakeInstalls) ListByPrincipalAndCode(_ context.Context, gw ids.GatewayID, sub, code string) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, in := range f.rows {
		if in.GatewayID == gw && in.PrincipalSub == sub && in.CatalogCode == code {
			out = append(out, in)
		}
	}
	return out, nil
}

func (f *fakeInstalls) DeleteByID(_ context.Context, gw ids.GatewayID, sub string, id ids.InstallationID) error {
	in, ok := f.rows[id]
	if !ok || in.GatewayID != gw || in.PrincipalSub != sub {
		return installationdomain.ErrNotFound
	}
	in.Status = installationdomain.StatusRevoked
	return nil
}

// fakeShelf is the registry list the real installer reads the shelf from.
type fakeShelf struct{ items []*registrydomain.Registry }

func (f *fakeShelf) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return f.items, len(f.items), nil
}

func shelf(code string, store *registrydomain.MCPStoreConfig) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		MCPTarget: &registrydomain.MCPTarget{Code: code, Store: store},
	}
}

type configureFixtureT struct {
	svc      oauth.ConfigureService
	store    *memConnectStore
	vault    *memVaultRepo
	installs *fakeInstalls
	shelf    *fakeShelf
	gw       ids.GatewayID
}

func configureCatalog() fakeConfigCatalog {
	return fakeConfigCatalog{byCode: map[string]catalogdomain.MCPServer{
		"snowflake": {
			Code: "snowflake", DisplayName: "Snowflake",
			URLVariables: []catalogdomain.MCPURLVariable{
				{Name: "account_url", Required: true},
				{Name: "database", Required: true},
			},
		},
		"com.brightdata/mcp": {
			Code: "com.brightdata/mcp", DisplayName: "Bright Data",
			URLVariables: []catalogdomain.MCPURLVariable{{Name: "token", Required: true, Secret: true, In: "query"}},
		},
	}}
}

// configureFixture wires the configure service over the REAL store installer so
// a configure-before-install submission runs the same governance as the install
// tool. shelfItems is the gateway's registry shelf; open selects the Store mode.
func configureFixture(t *testing.T, open bool, shelfItems ...*registrydomain.Registry) configureFixtureT {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
	}})
	store := &memConnectStore{tickets: map[string]oauth.ConnectTicket{}, connects: map[string]oauth.ConnectState{}}
	vault := &memVaultRepo{}
	installs := &fakeInstalls{}
	sh := &fakeShelf{items: shelfItems}
	catalog := configureCatalog()
	installer, err := appstore.NewInstaller(catalog, sh, installs, nil)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	svc := oauth.NewConfigureService(store, &stubDataFinder{data: data}, catalog, installs, vault,
		oauth.WithConfigureInstaller(installer),
		oauth.WithConfigureOpenMode(func(context.Context, ids.GatewayID) bool { return open }),
	)
	return configureFixtureT{svc: svc, store: store, vault: vault, installs: installs, shelf: sh, gw: gw}
}

func (f configureFixtureT) ticket(t *testing.T, code, instanceID string, groups ...string) string {
	t.Helper()
	id, err := f.svc.CreateTicket(context.Background(), oauth.ConfigureTicketRequest{
		GatewayID: f.gw, PrincipalSub: "ana", ConsumerPath: appconsumer.MCPPath("dev"),
		Code: code, InstanceID: instanceID, Groups: groups,
	})
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	return id
}

// seed records an existing installation row directly (as the installer would).
func (f configureFixtureT) seed(t *testing.T, code string, status installationdomain.Status, config map[string]string) *installationdomain.Installation {
	t.Helper()
	in, err := installationdomain.New(f.gw, "ana", code, "ana", config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	in.Status = status
	if err := f.installs.Upsert(context.Background(), in); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	return in
}

func (f configureFixtureT) rows(t *testing.T, code string) []*installationdomain.Installation {
	t.Helper()
	rows, err := f.installs.ListByPrincipalAndCode(context.Background(), f.gw, "ana", code)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return rows
}

func TestConfigure_SubmitPlainStoresOnInstallation(t *testing.T) {
	// Available shelf server, no install yet: the form-driven first configuration
	// records the install through the governed installer, which admits it.
	f := configureFixture(t, false, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	id := f.ticket(t, "snowflake", "")

	page, err := f.svc.Submit(context.Background(), id, map[string]string{
		"account_url": "acme.snowflakecomputing.com",
		"database":    "ANALYTICS",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !page.Saved || page.Pending {
		t.Fatalf("submit must report saved and not pending, got %+v", page)
	}
	rows := f.rows(t, "snowflake")
	if len(rows) != 1 {
		t.Fatalf("expected one installation, got %d", len(rows))
	}
	inst := rows[0]
	if inst.Status != installationdomain.StatusInstalled {
		t.Fatalf("available server must install, got %q", inst.Status)
	}
	if inst.Config["account_url"] != "acme.snowflakecomputing.com" || inst.Config["database"] != "ANALYTICS" {
		t.Fatalf("plain values not persisted: %+v", inst.Config)
	}
}

// TestConfigure_FirstConfigureOfGovernedServerIsPending guards the governance
// bypass: configuring a requires-approval server before installing it must end
// as a pending request, never as an installed row.
func TestConfigure_FirstConfigureOfGovernedServerIsPending(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true, RequiresApproval: true}))
	id := f.ticket(t, "snowflake", "")

	page, err := f.svc.Submit(context.Background(), id, map[string]string{
		"account_url": "acme.snowflakecomputing.com",
		"database":    "ANALYTICS",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !page.Pending {
		t.Fatalf("page must report the install is pending approval, got %+v", page)
	}
	rows := f.rows(t, "snowflake")
	if len(rows) != 1 || rows[0].Status != installationdomain.StatusPendingApproval {
		t.Fatalf("governed server configured via the form must be pending_approval, got %+v", rows)
	}
}

// TestConfigure_FirstConfigureCuratedNotOnShelfIsPending: in curated mode a
// server not on the shelf is a request for the admin — the form cannot install it.
func TestConfigure_FirstConfigureCuratedNotOnShelfIsPending(t *testing.T) {
	f := configureFixture(t, false) // curated, empty shelf
	id := f.ticket(t, "snowflake", "")

	if _, err := f.svc.Submit(context.Background(), id, map[string]string{
		"account_url": "acme.snowflakecomputing.com",
		"database":    "ANALYTICS",
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	rows := f.rows(t, "snowflake")
	if len(rows) != 1 || rows[0].Status != installationdomain.StatusPendingApproval {
		t.Fatalf("curated not-on-shelf server must be pending, got %+v", rows)
	}
}

// TestConfigure_FirstConfigureGroupGatedRefused: the group gate applies to the
// form exactly as to the tool — the ticket carries the principal's groups.
func TestConfigure_FirstConfigureGroupGatedRefused(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true, Groups: []string{"data-eng"}}))
	values := map[string]string{"account_url": "acme.snowflakecomputing.com", "database": "ANALYTICS"}

	// Not in the group: refused, nothing recorded.
	excluded := f.ticket(t, "snowflake", "", "marketing")
	if _, err := f.svc.Submit(context.Background(), excluded, values); !errors.Is(err, appstore.ErrRoleNotAllowed) {
		t.Fatalf("group-excluded principal must be refused, got %v", err)
	}
	if rows := f.rows(t, "snowflake"); len(rows) != 0 {
		t.Fatalf("a refused configure must record nothing, got %+v", rows)
	}

	// In the group: installs.
	allowed := f.ticket(t, "snowflake", "", "data-eng")
	if _, err := f.svc.Submit(context.Background(), allowed, values); err != nil {
		t.Fatalf("group member Submit: %v", err)
	}
	if rows := f.rows(t, "snowflake"); len(rows) != 1 || rows[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("group member must install, got %+v", rows)
	}
}

// TestConfigure_FirstConfigureWithoutInstallerRefused: with no installer wired
// the form can only update an existing installation, never create one.
func TestConfigure_FirstConfigureWithoutInstallerRefused(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Type: consumerdomain.TypeMCP, Slug: "dev", Active: true},
	}})
	store := &memConnectStore{tickets: map[string]oauth.ConnectTicket{}, connects: map[string]oauth.ConnectState{}}
	installs := &fakeInstalls{}
	svc := oauth.NewConfigureService(store, &stubDataFinder{data: data}, configureCatalog(), installs, &memVaultRepo{})
	id, err := svc.CreateTicket(context.Background(), oauth.ConfigureTicketRequest{
		GatewayID: gw, PrincipalSub: "ana", ConsumerPath: appconsumer.MCPPath("dev"), Code: "snowflake",
	})
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	_, err = svc.Submit(context.Background(), id, map[string]string{"account_url": "acme.snowflakecomputing.com", "database": "ANALYTICS"})
	if !errors.Is(err, oauth.ErrConfigureInstallUnavailable) {
		t.Fatalf("configure-before-install without an installer must be refused, got %v", err)
	}
	if len(installs.rows) != 0 {
		t.Fatalf("the form must never create an installation on its own, got %+v", installs.rows)
	}
}

// TestConfigure_FirstConfigureIncompleteSavesNothing: a first-time submission
// missing a required plain value cannot be recorded half-configured.
func TestConfigure_FirstConfigureIncompleteSavesNothing(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	id := f.ticket(t, "snowflake", "")
	_, err := f.svc.Submit(context.Background(), id, map[string]string{"account_url": "acme.snowflakecomputing.com"})
	if !errors.Is(err, oauth.ErrConfigureIncomplete) || !errors.Is(err, oauth.ErrConfigureInvalid) {
		t.Fatalf("incomplete first configuration must be rejected as invalid/incomplete, got %v", err)
	}
	if rows := f.rows(t, "snowflake"); len(rows) != 0 {
		t.Fatalf("nothing may be recorded, got %+v", rows)
	}
}

// TestConfigure_ExistingInstanceMergesInPlace: configuring an installed instance
// merges the values into that row and keeps its status.
func TestConfigure_ExistingInstanceMergesInPlace(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true, RequiresApproval: true}))
	pending := f.seed(t, "snowflake", installationdomain.StatusPendingApproval, map[string]string{"account_url": "acme.snowflakecomputing.com"})
	id := f.ticket(t, "snowflake", pending.ID.String())

	page, err := f.svc.Submit(context.Background(), id, map[string]string{"database": "ANALYTICS"})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !page.Pending {
		t.Fatal("page must still report pending for a pending instance")
	}
	rows := f.rows(t, "snowflake")
	if len(rows) != 1 {
		t.Fatalf("merging must not create a second row, got %d", len(rows))
	}
	got := rows[0]
	if got.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("merging must not change the status, got %q", got.Status)
	}
	if got.Config["account_url"] != "acme.snowflakecomputing.com" || got.Config["database"] != "ANALYTICS" {
		t.Fatalf("values not merged: %+v", got.Config)
	}
}

// TestConfigure_TicketTargetsPinnedInstance: with two instances of one code the
// pinned ticket writes to the named instance, not to whichever Find returns.
func TestConfigure_TicketTargetsPinnedInstance(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	a := f.seed(t, "snowflake", installationdomain.StatusInstalled, map[string]string{"account_url": "acme.snowflakecomputing.com", "database": "A"})
	b := f.seed(t, "snowflake", installationdomain.StatusInstalled, map[string]string{"account_url": "acme.snowflakecomputing.com", "database": "B"})

	id := f.ticket(t, "snowflake", b.ID.String())
	if _, err := f.svc.Submit(context.Background(), id, map[string]string{"database": "B2"}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if a.Config["database"] != "A" {
		t.Fatalf("instance A must be untouched, got %+v", a.Config)
	}
	if b.Config["database"] != "B2" {
		t.Fatalf("instance B must carry the new value, got %+v", b.Config)
	}

	// An unpinned ticket cannot choose between the two.
	unpinned := f.ticket(t, "snowflake", "")
	if _, err := f.svc.Submit(context.Background(), unpinned, map[string]string{"database": "C"}); !errors.Is(err, oauth.ErrConfigureAmbiguous) {
		t.Fatalf("unpinned ticket over two instances must be ambiguous, got %v", err)
	}
}

// TestConfigure_PinnedTicketRejectsForeignInstance: a ticket pinned to an
// instance of another code (or another principal) is refused.
func TestConfigure_PinnedTicketRejectsForeignInstance(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	other := f.seed(t, "com.brightdata/mcp", installationdomain.StatusInstalled, nil)
	id := f.ticket(t, "snowflake", other.ID.String())
	_, err := f.svc.Submit(context.Background(), id, map[string]string{"database": "X"})
	if !errors.Is(err, oauth.ErrTicketNotFound) {
		t.Fatalf("instance of another code must be refused, got %v", err)
	}
}

func TestConfigure_SubmitSecretStoresInVault(t *testing.T) {
	f := configureFixture(t, true, shelf("com.brightdata/mcp", &registrydomain.MCPStoreConfig{Available: true}))
	id := f.ticket(t, "com.brightdata/mcp", "")

	if _, err := f.svc.Submit(context.Background(), id, map[string]string{"token": "s3cr3t"}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	provider := registrydomain.URLVariableVaultProvider("com.brightdata/mcp", "token")
	cred, err := f.vault.Find(context.Background(), f.gw, "ana", provider)
	if err != nil {
		t.Fatalf("secret not in vault under %q: %v", provider, err)
	}
	if cred.AccessToken != "s3cr3t" {
		t.Fatalf("wrong secret stored: %q", cred.AccessToken)
	}
}

func TestConfigure_SubmitRejectsUnsafeValue(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	id := f.ticket(t, "snowflake", "")
	_, err := f.svc.Submit(context.Background(), id, map[string]string{"account_url": "evil.com/../x"})
	if !errors.Is(err, oauth.ErrConfigureInvalid) {
		t.Fatalf("unsafe value must be rejected, got %v", err)
	}
}

func TestConfigure_SubmitRejectsUnknownVariable(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	id := f.ticket(t, "snowflake", "")
	_, err := f.svc.Submit(context.Background(), id, map[string]string{"bogus": "x"})
	if !errors.Is(err, oauth.ErrConfigureInvalid) {
		t.Fatalf("unknown variable must be rejected, got %v", err)
	}
}

func TestConfigure_PageReportsSetState(t *testing.T) {
	f := configureFixture(t, true, shelf("snowflake", &registrydomain.MCPStoreConfig{Available: true}))
	inst := f.seed(t, "snowflake", installationdomain.StatusInstalled, map[string]string{"account_url": "acme.snowflakecomputing.com"})
	id := f.ticket(t, "snowflake", inst.ID.String())
	page, err := f.svc.Page(context.Background(), id)
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	var accountSet, dbSet bool
	for _, v := range page.Variables {
		switch v.Name {
		case "account_url":
			accountSet = v.Set
		case "database":
			dbSet = v.Set
		}
	}
	if !accountSet || dbSet {
		t.Fatalf("expected account_url set and database unset, got %+v", page.Variables)
	}
}

func TestConfigure_UnknownTicketFails(t *testing.T) {
	f := configureFixture(t, true)
	if _, err := f.svc.Page(context.Background(), "nope"); !errors.Is(err, oauth.ErrTicketNotFound) {
		t.Fatalf("unknown ticket must fail, got %v", err)
	}
}
