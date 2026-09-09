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

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

type fakeCatalog struct {
	entries map[string]catalogdomain.MCPServer
}

func (f fakeCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	e, ok := f.entries[code]
	return e, ok
}

type fakeRegistries struct {
	items []*registrydomain.Registry
}

func (f *fakeRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return f.items, len(f.items), nil
}

// fakeGrants is the in-memory grant store: a Reader for the installer/scoper and
// a GrantStore for the approver (Upsert replaces by natural key).
type fakeGrants struct {
	items   []*storeaccessdomain.Grant
	upserts []*storeaccessdomain.Grant
	// err makes the grant store unreadable, to prove which paths consult it.
	err error
}

func (f *fakeGrants) ListByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

func (f *fakeGrants) Upsert(_ context.Context, g *storeaccessdomain.Grant) error {
	f.upserts = append(f.upserts, g)
	for i, existing := range f.items {
		if existing.CatalogCode == g.CatalogCode && existing.RegistryID == g.RegistryID {
			f.items[i] = g
			return nil
		}
	}
	f.items = append(f.items, g)
	return nil
}

// codeGrant grants a catalog code (every instance) to groups/users.
func codeGrant(gw ids.GatewayID, code string, groups, users []string) *storeaccessdomain.Grant {
	g, err := storeaccessdomain.New(gw, code, ids.RegistryID{}, groups, users)
	if err != nil {
		panic(err)
	}
	return g
}

// instanceGrant grants one configured instance (registry) of a code.
func instanceGrant(gw ids.GatewayID, code string, reg ids.RegistryID, groups, users []string) *storeaccessdomain.Grant {
	g, err := storeaccessdomain.New(gw, code, reg, groups, users)
	if err != nil {
		panic(err)
	}
	return g
}

// grantsOf builds the grant reader from a list.
func grantsOf(items ...*storeaccessdomain.Grant) *fakeGrants {
	return &fakeGrants{items: items}
}

type fakeInstalls struct {
	upserts     []*installationdomain.Installation
	deletes     int
	deleteByID  int
	findValue   *installationdomain.Installation
	byCode      []*installationdomain.Installation
	byPrincipal []*installationdomain.Installation
	pending     []*installationdomain.Installation
}

// installsForCode is the set a code-scoped read returns: an explicit byCode list
// when set, else the single findValue (the common one-instance fixture), else none.
func (f *fakeInstalls) installsForCode() []*installationdomain.Installation {
	if f.byCode != nil {
		return f.byCode
	}
	if f.findValue != nil {
		return []*installationdomain.Installation{f.findValue}
	}
	return nil
}

func (f *fakeInstalls) Upsert(_ context.Context, in *installationdomain.Installation) error {
	f.upserts = append(f.upserts, in)
	return nil
}

func (f *fakeInstalls) Find(_ context.Context, _ ids.GatewayID, _, _ string) (*installationdomain.Installation, error) {
	if f.findValue != nil {
		return f.findValue, nil
	}
	return nil, installationdomain.ErrNotFound
}

func (f *fakeInstalls) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return f.byPrincipal, nil
}

func (f *fakeInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}

func (f *fakeInstalls) ListPendingByGateway(context.Context, ids.GatewayID) ([]*installationdomain.Installation, error) {
	return f.pending, nil
}

func (f *fakeInstalls) FindByID(_ context.Context, _ ids.GatewayID, _ string, id ids.InstallationID) (*installationdomain.Installation, error) {
	for _, in := range f.installsForCode() {
		if in != nil && in.ID == id {
			return in, nil
		}
	}
	return nil, installationdomain.ErrNotFound
}

func (f *fakeInstalls) ListByPrincipalAndCode(context.Context, ids.GatewayID, string, string) ([]*installationdomain.Installation, error) {
	return f.installsForCode(), nil
}

func (f *fakeInstalls) Delete(context.Context, ids.GatewayID, string, string) error {
	f.deletes++
	return nil
}

// DeleteByID mirrors the real repositories: a soft revoke of the named row.
func (f *fakeInstalls) DeleteByID(_ context.Context, _ ids.GatewayID, _ string, id ids.InstallationID) error {
	f.deleteByID++
	for _, in := range f.installsForCode() {
		if in != nil && in.ID == id {
			in.Status = installationdomain.StatusRevoked
		}
	}
	return nil
}

// shelfRegistry builds a gateway registry (a configured instance) for a catalog
// code. Successive calls get later creation times so ordering is deterministic.
var shelfClock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func shelfRegistry(code string) *registrydomain.Registry {
	return namedRegistry(code, "")
}

func namedRegistry(code, name string) *registrydomain.Registry {
	shelfClock = shelfClock.Add(time.Second)
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Name:      name,
		CreatedAt: shelfClock,
		MCPTarget: &registrydomain.MCPTarget{Code: code},
	}
}

// fakeEnsurer records the codes it was asked to materialise and, when addTo is
// set, appends a freshly-shelved registry to it so a follow-up install sees an
// available registry.
type fakeEnsurer struct {
	ensured []string
	addTo   *fakeRegistries
	err     error
}

func (f *fakeEnsurer) Ensure(_ context.Context, _ ids.GatewayID, code string) error {
	if f.err != nil {
		return f.err
	}
	f.ensured = append(f.ensured, code)
	if f.addTo != nil {
		f.addTo.items = append(f.addTo.items, shelfRegistry(code))
	}
	return nil
}

func testCatalog() fakeCatalog {
	return fakeCatalog{entries: map[string]catalogdomain.MCPServer{
		// Each entry declares what the real catalog declares for its shape:
		// a fixed URL with nothing to configure holds one instance; a templated
		// one holds several; and all three are installable by a user alone.
		"github": {
			Code: "github", DisplayName: "GitHub", URL: "https://mcp.github.com", RequiresAuth: true,
			SelfService: true, MultiInstance: false,
		},
		"snowflake": {
			Code:        "snowflake",
			DisplayName: "Snowflake",
			URL:         "https://{account_url}/api/v2/databases/{database}/mcp",
			URLVariables: []catalogdomain.MCPURLVariable{
				{Name: "account_url", Required: true},
				{Name: "database", Required: true},
			},
			SelfService: true, MultiInstance: true,
		},
		"brightdata": {
			Code:        "brightdata",
			DisplayName: "Bright Data",
			URL:         "https://mcp.brightdata.com/mcp?token={token}",
			URLVariables: []catalogdomain.MCPURLVariable{
				{Name: "token", Required: true, Secret: true, In: "query"},
			},
			SelfService: true, MultiInstance: true,
		},
	}}
}

// newInstaller wires an installer with no grants (nothing granted under
// Selected) and no ensurer.
func newInstaller(t *testing.T, regs *fakeRegistries, installs *fakeInstalls) Installer {
	t.Helper()
	return newInstallerWith(t, regs, installs, nil, nil)
}

func newInstallerWithEnsurer(t *testing.T, regs *fakeRegistries, installs *fakeInstalls, ensurer RegistryEnsurer) Installer {
	t.Helper()
	return newInstallerWith(t, regs, installs, nil, ensurer)
}

func newInstallerWithGrants(t *testing.T, regs *fakeRegistries, installs *fakeInstalls, grants storeaccessdomain.Reader) Installer {
	t.Helper()
	return newInstallerWith(t, regs, installs, grants, nil)
}

func newInstallerWith(t *testing.T, regs *fakeRegistries, installs *fakeInstalls, grants storeaccessdomain.Reader, ensurer RegistryEnsurer) Installer {
	t.Helper()
	inst, err := NewInstaller(testCatalog(), regs, installs, grants, ensurer)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	return inst
}

func req(gw ids.GatewayID, code string, groups ...string) InstallRequest {
	return InstallRequest{GatewayID: gw, PrincipalSub: "ana", Code: code, InstalledBy: "ana", Groups: groups}
}

// openReq is a self-service (open Store) install request.
func openReq(gw ids.GatewayID, code string, groups ...string) InstallRequest {
	r := req(gw, code, groups...)
	r.OpenMode = true
	return r
}

func TestNewInstallerRejectsNilDeps(t *testing.T) {
	if _, err := NewInstaller(nil, &fakeRegistries{}, &fakeInstalls{}, nil, nil); err == nil {
		t.Fatal("nil catalog must error")
	}
}

// TestInstallGrantedServerInstallsImmediately: under Selected a code granted to
// the principal, with a configured instance, installs instantly.
func TestInstallGrantedServerInstallsImmediately(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	installs := &fakeInstalls{}
	grants := grantsOf(codeGrant(gw, "github", nil, []string{"ana"}))
	res, err := newInstallerWithGrants(t, regs, installs, grants).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || res.Pending {
		t.Fatalf("granted server must install immediately, got %+v", res)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("must record an installed row, got %+v", installs.upserts)
	}
	// The sole instance is the canonical one: the binding stays implicit.
	if !installs.upserts[0].RegistryID.IsNil() {
		t.Fatalf("a sole instance must not pin the install to a registry id, got %s", installs.upserts[0].RegistryID)
	}
}

func TestInstallNotOnShelfBecomesPendingRequest(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	// Curated mode (OpenMode false), no grant, no registry for the code — a
	// request the admin grants by approving.
	res, err := newInstaller(t, &fakeRegistries{}, &fakeInstalls{}).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("a server nobody granted must become a pending request, got %+v", res)
	}
}

// TestInstallSelectedCodeGrantMaterialisesLazily: the whole catalog is
// grantable before any registry exists. A principal holding the code-level
// grant installs a never-connected server: the registry is materialised from
// the catalog on this first install, exactly like self-service under All.
func TestInstallSelectedCodeGrantMaterialisesLazily(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	grants := grantsOf(codeGrant(gw, "github", []string{"eng"}, nil))
	res, err := newInstallerWith(t, regs, installs, grants, ensurer).Install(context.Background(), req(gw, "github", "eng"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Pending || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("a code-granted server must install, got %+v", res)
	}
	if len(ensurer.ensured) != 1 || ensurer.ensured[0] != "github" {
		t.Fatalf("the registry must be materialised on first install, got %+v", ensurer.ensured)
	}
}

// TestInstallSelectedCodeGrantWithoutEnsurerStaysPending: a code grant alone
// cannot conjure the registry on a plane without a materialiser.
func TestInstallSelectedCodeGrantWithoutEnsurerStaysPending(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	grants := grantsOf(codeGrant(gw, "github", nil, []string{"ana"}))
	res, err := newInstallerWithGrants(t, &fakeRegistries{}, &fakeInstalls{}, grants).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending {
		t.Fatalf("without an ensurer the install must fall back to a request, got %+v", res)
	}
}

// TestInstallSelfServiceMaterialisesAndInstalls guards the B2 self-service path:
// in open mode a catalog server that is not yet on the shelf is materialised
// through the ensurer and installed immediately, not queued.
func TestInstallSelfServiceMaterialisesAndInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	ensurer := &fakeEnsurer{addTo: regs}
	installs := &fakeInstalls{}
	res, err := newInstallerWithEnsurer(t, regs, installs, ensurer).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Pending || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("open-mode install of a catalog server must materialise and install, got %+v", res)
	}
	if len(ensurer.ensured) != 1 || ensurer.ensured[0] != "github" {
		t.Fatalf("expected the registry to be materialised once for github, got %+v", ensurer.ensured)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("must record an installed row, got %+v", installs.upserts)
	}
}

// TestInstallSelfServiceWithoutEnsurerStaysPending confirms open mode alone does
// not grant an install: without a materialiser wired, a not-yet-shelved server
// still becomes a pending request rather than being silently installed.
func TestInstallSelfServiceWithoutEnsurerStaysPending(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	res, err := newInstaller(t, &fakeRegistries{}, &fakeInstalls{}).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("open mode without an ensurer must fall back to a pending request, got %+v", res)
	}
}

// TestInstallSelfServiceEnsurerErrorFailsInstall confirms a materialisation
// failure surfaces as an error and records no installation row.
func TestInstallSelfServiceEnsurerErrorFailsInstall(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installs := &fakeInstalls{}
	ensurer := &fakeEnsurer{err: errors.New("boom")}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, installs, ensurer).
		Install(context.Background(), openReq(gw, "github"))
	if err == nil {
		t.Fatal("a materialisation failure must fail the install")
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a failed materialisation must not record an install, got %+v", installs.upserts)
	}
}

// TestInstallOpenModeInstallsExistingRegistryInstantly: under All every server
// installs instantly and the ensurer never runs when the registry exists.
func TestInstallOpenModeInstallsExistingRegistryInstantly(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	ensurer := &fakeEnsurer{addTo: regs}
	res, err := newInstallerWithEnsurer(t, regs, &fakeInstalls{}, ensurer).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Pending || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("All installs instantly, got %+v", res)
	}
	if len(ensurer.ensured) != 0 {
		t.Fatalf("the ensurer must not run when a registry already exists, got %+v", ensurer.ensured)
	}
}

// TestInstallOpenModeIgnoresGrants: a principal with All access is not held
// back by a grant that names other groups — All means all resources.
func TestInstallOpenModeIgnoresGrants(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	grants := grantsOf(codeGrant(gw, "github", []string{"sre"}, nil))
	res, err := newInstallerWithGrants(t, regs, &fakeInstalls{}, grants).Install(context.Background(), openReq(gw, "github", "eng"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled {
		t.Fatalf("All must install a group-restricted server instantly, got %+v", res)
	}
}

// TestInstallRoleGating: under Selected, a server granted to other groups is not
// refused — it becomes an approval request the admin can grant; a principal in
// the granted group installs instantly.
func TestInstallRoleGating(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	installs := &fakeInstalls{}
	inst := newInstallerWithGrants(t, regs, installs, grantsOf(codeGrant(gw, "github", []string{"sre"}, nil)))

	res, err := inst.Install(context.Background(), req(gw, "github", "eng"))
	if err != nil {
		t.Fatalf("excluded principal Install: %v", err)
	}
	if !res.Pending || res.Status != installationdomain.StatusPendingApproval {
		t.Fatalf("a server granted to other groups must become a request, got %+v", res)
	}
	if len(installs.upserts) != 1 || installs.upserts[0].Status != installationdomain.StatusPendingApproval {
		t.Fatalf("the request must be recorded pending, got %+v", installs.upserts)
	}
	// A request for a code with exactly one instance is bound to that instance,
	// so approving grants precisely it.
	if installs.upserts[0].RegistryID != regs.items[0].ID {
		t.Fatalf("the request must be bound to the sole instance, got %s", installs.upserts[0].RegistryID)
	}
	res, err = inst.Install(context.Background(), req(gw, "github", "sre"))
	if err != nil {
		t.Fatalf("allowed role Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled {
		t.Fatalf("allowed role must install, got %+v", res)
	}
}

// TestInstallUserGating mirrors TestInstallRoleGating for the Users axis.
func TestInstallUserGating(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	inst := newInstallerWithGrants(t, regs, &fakeInstalls{}, grantsOf(codeGrant(gw, "github", nil, []string{"ana"})))

	// "ana" is admitted by the Users allow-list even with no matching group.
	res, err := inst.Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("user-allowed Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled {
		t.Fatalf("user-allowed must install, got %+v", res)
	}

	// A different subject, matching neither Users nor Groups, files a request.
	other := InstallRequest{GatewayID: gw, PrincipalSub: "bob", Code: "github", InstalledBy: "bob"}
	res, err = inst.Install(context.Background(), other)
	if err != nil {
		t.Fatalf("other subject Install: %v", err)
	}
	if !res.Pending {
		t.Fatalf("a subject outside the grant must become a request, got %+v", res)
	}
}

// TestInstallNoGrantsMeansNobody: an existing registry with no grant at all is
// granted to nobody under Selected — it is a request, never an instant install.
func TestInstallNoGrantsMeansNobody(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), req(gw, "github", "eng"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending {
		t.Fatalf("an ungranted registry must file a request, got %+v", res)
	}
}

// TestInstallInstanceGrantBindsToThatInstance: an instance-level grant admits
// the principal to exactly that configured instance. With two instances of the
// code and one granted, the install binds to the granted one — no choice needed.
func TestInstallInstanceGrantBindsToThatInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("snowflake", "Snowflake (finance)")
	analytics := namedRegistry("snowflake", "Snowflake (analytics)")
	regs := &fakeRegistries{items: []*registrydomain.Registry{finance, analytics}}
	installs := &fakeInstalls{}
	grants := grantsOf(instanceGrant(gw, "snowflake", finance.ID, []string{"finance"}, nil))
	in := req(gw, "snowflake", "finance")
	in.Config = map[string]string{"account_url": "acme", "database": "ledger"}
	res, err := newInstallerWithGrants(t, regs, installs, grants).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || res.RequiresInstanceChoice {
		t.Fatalf("the sole granted instance must install without a choice, got %+v", res)
	}
	if installs.upserts[0].RegistryID != finance.ID {
		t.Fatalf("install must bind to the granted instance, got %s", installs.upserts[0].RegistryID)
	}
}

// TestInstallSeveralUsableInstancesRequiresChoice: with the code granted (or
// All) and several configured instances, the install must be told which one.
// Nothing is recorded until then.
func TestInstallSeveralUsableInstancesRequiresChoice(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("snowflake", "Snowflake (finance)")
	analytics := namedRegistry("snowflake", "Snowflake (analytics)")
	regs := &fakeRegistries{items: []*registrydomain.Registry{finance, analytics}}
	installs := &fakeInstalls{}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "ledger"}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresInstanceChoice || len(res.InstanceChoices) != 2 {
		t.Fatalf("expected a two-way instance choice, got %+v", res)
	}
	if res.InstanceChoices[0].RegistryID != finance.ID || res.InstanceChoices[0].Name != "Snowflake (finance)" {
		t.Fatalf("choices must carry id and name in creation order, got %+v", res.InstanceChoices)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a choice result must record nothing, got %+v", installs.upserts)
	}

	// Naming the instance installs and binds to it.
	in.RegistryID = analytics.ID
	res, err = newInstaller(t, regs, installs).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install with instance: %v", err)
	}
	if res.Status != installationdomain.StatusInstalled || installs.upserts[0].RegistryID != analytics.ID {
		t.Fatalf("named instance must install bound to it, got %+v / %s", res, installs.upserts[0].RegistryID)
	}
}

// TestInstallNamedInstanceMustBelongToCode: a registry id of another code (or
// an unknown one) is refused as a validation error.
func TestInstallNamedInstanceMustBelongToCode(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	other := shelfRegistry("github")
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("snowflake"), other}}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "ledger"}
	in.RegistryID = other.ID
	_, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in)
	if !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("expected ErrUnknownInstance, got %v", err)
	}
	in.RegistryID = ids.New[ids.RegistryKind]()
	if _, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("unknown id: expected ErrUnknownInstance, got %v", err)
	}
}

// TestInstallNamedUngrantedInstanceFilesBoundRequest: naming an instance the
// principal is not granted files a request bound to that instance.
func TestInstallNamedUngrantedInstanceFilesBoundRequest(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("snowflake", "finance")
	analytics := namedRegistry("snowflake", "analytics")
	regs := &fakeRegistries{items: []*registrydomain.Registry{finance, analytics}}
	installs := &fakeInstalls{}
	grants := grantsOf(instanceGrant(gw, "snowflake", finance.ID, nil, []string{"ana"}))
	in := req(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme", "database": "x"}
	in.RegistryID = analytics.ID
	res, err := newInstallerWithGrants(t, regs, installs, grants).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || installs.upserts[0].RegistryID != analytics.ID {
		t.Fatalf("expected a request bound to the named instance, got %+v / %s", res, installs.upserts[0].RegistryID)
	}
}

// TestInstallSeveralInstancesNoneGrantedFilesCodeRequest: with several
// instances and none usable, the request is code-level (unbound) for the admin
// to resolve by granting the code or one instance.
func TestInstallSeveralInstancesNoneGrantedFilesCodeRequest(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github"), shelfRegistry("github")}}
	installs := &fakeInstalls{}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), req(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending || !installs.upserts[0].RegistryID.IsNil() {
		t.Fatalf("expected an unbound code-level request, got %+v / %s", res, installs.upserts[0].RegistryID)
	}
}

// TestInstallSameInstanceDifferentRegistryIsNewInstance: identical config on a
// different configured instance is a different install (its own row).
func TestInstallSameConfigDifferentRegistryIsNewInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	finance := namedRegistry("snowflake", "finance")
	analytics := namedRegistry("snowflake", "analytics")
	regs := &fakeRegistries{items: []*registrydomain.Registry{finance, analytics}}
	config := map[string]string{"account_url": "acme", "database": "x"}
	existing := &installationdomain.Installation{
		ID: ids.New[ids.InstallationKind](), Status: installationdomain.StatusInstalled, Config: config, RegistryID: finance.ID,
	}
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{existing}}
	in := openReq(gw, "snowflake")
	in.Config = config
	in.RegistryID = analytics.ID
	res, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.AlreadyInstalled || installs.upserts[0].ID == existing.ID {
		t.Fatalf("a different instance must be a new row, got %+v", res)
	}
}

func TestInstallReportsAlreadyInstalled(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	installs := &fakeInstalls{findValue: &installationdomain.Installation{Status: installationdomain.StatusInstalled}}
	res, err := newInstaller(t, regs, installs).Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.AlreadyInstalled {
		t.Fatal("must report already installed when an active install exists")
	}
}

func TestInstallUnknownCatalogCode(t *testing.T) {
	inst := newInstaller(t, &fakeRegistries{}, &fakeInstalls{})
	_, err := inst.Install(context.Background(), req(ids.New[ids.GatewayKind](), "does-not-exist"))
	if !errors.Is(err, ErrCatalogEntryNotFound) {
		t.Fatalf("expected ErrCatalogEntryNotFound, got %v", err)
	}
}

func TestInstallRequiresConfigWhenVariablesMissing(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	installs := &fakeInstalls{}
	res, err := newInstallerWithEnsurer(t, regs, installs, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), openReq(gw, "snowflake"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresConfig || len(res.ConfigVariables) != 2 {
		t.Fatalf("must ask for the two required variables, got %+v", res)
	}
	if len(installs.upserts) != 0 {
		t.Fatalf("a requires-config result must not record an install, got %+v", installs.upserts)
	}
}

func TestInstallWithConfigStoresAndInstalls(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	installs := &fakeInstalls{}
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "acme.snowflakecomputing.com", "database": "ANALYTICS"}
	res, err := newInstallerWithEnsurer(t, regs, installs, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresConfig || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("a fully-configured install must proceed, got %+v", res)
	}
	if len(installs.upserts) != 1 {
		t.Fatalf("expected one install row, got %+v", installs.upserts)
	}
	cfg := installs.upserts[0].Config
	if cfg["account_url"] != "acme.snowflakecomputing.com" || cfg["database"] != "ANALYTICS" {
		t.Fatalf("config not persisted on the installation: %+v", cfg)
	}
}

func TestInstallRejectsUnsafeConfigValue(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := openReq(gw, "snowflake")
	in.Config = map[string]string{"account_url": "evil.com/../x", "database": "ANALYTICS"}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, &fakeInstalls{}, &fakeEnsurer{}).
		Install(context.Background(), in)
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("an unsafe host value must be rejected, got %v", err)
	}
}

func TestInstallRejectsSecretSuppliedInline(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in := openReq(gw, "brightdata")
	in.Config = map[string]string{"token": "sk-secret"}
	_, err := newInstallerWithEnsurer(t, &fakeRegistries{}, &fakeInstalls{}, &fakeEnsurer{}).
		Install(context.Background(), in)
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("a secret supplied inline must be rejected, got %v", err)
	}
}

func TestInstallSecretVariableRecordsAndRequiresConnect(t *testing.T) {
	// A server whose only required variable is a secret is recorded (the secret is
	// collected out-of-band through the hosted form, not inline) and reported as
	// requires-config so the caller surfaces the configure link. Its tools stay
	// dark until the secret is entered, but the install itself is durable.
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	installs := &fakeInstalls{}
	res, err := newInstallerWithEnsurer(t, regs, installs, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), openReq(gw, "brightdata"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresConfig || len(res.ConfigVariables) != 1 || !res.ConfigVariables[0].Secret {
		t.Fatalf("a required secret variable must be reported for connect-link setup, got %+v", res)
	}
	if res.Status != installationdomain.StatusInstalled {
		t.Fatalf("the install must be recorded so config can be attached, got %+v", res)
	}
	if len(installs.upserts) != 1 {
		t.Fatalf("the install must be recorded, got %+v", installs.upserts)
	}
}

func TestUninstallDeletesInstallationOnly(t *testing.T) {
	installs := &fakeInstalls{}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	// No active instance recorded: falls back to clearing any row for the code.
	if err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if installs.deletes != 1 {
		t.Fatalf("expected one delete, got %d", installs.deletes)
	}
}

func TestUninstallSingleInstanceDeletesByID(t *testing.T) {
	one := &installationdomain.Installation{
		ID:     ids.New[ids.InstallationKind](),
		Status: installationdomain.StatusInstalled,
	}
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{one}}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	if err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", ""); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if installs.deleteByID != 1 || installs.deletes != 0 {
		t.Fatalf("expected one delete-by-id, got byID=%d byCode=%d", installs.deleteByID, installs.deletes)
	}
}

func TestUninstallAmbiguousWithoutInstance(t *testing.T) {
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{
		{ID: ids.New[ids.InstallationKind](), Status: installationdomain.StatusInstalled, Config: map[string]string{"schema": "a"}},
		{ID: ids.New[ids.InstallationKind](), Status: installationdomain.StatusInstalled, Config: map[string]string{"schema": "b"}},
	}}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", "")
	if !errors.Is(err, ErrAmbiguousInstance) {
		t.Fatalf("expected ErrAmbiguousInstance, got %v", err)
	}
	if installs.deleteByID != 0 || installs.deletes != 0 {
		t.Fatal("must not delete anything when the instance is ambiguous")
	}
}

func TestUninstallByInstanceID(t *testing.T) {
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{
		{ID: ids.New[ids.InstallationKind](), CatalogCode: "github", Status: installationdomain.StatusInstalled, Config: map[string]string{"schema": "a"}},
		{ID: ids.New[ids.InstallationKind](), CatalogCode: "github", Status: installationdomain.StatusInstalled, Config: map[string]string{"schema": "b"}},
	}}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	target := installs.byCode[1].ID.String()
	if err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", target); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if installs.deleteByID != 1 {
		t.Fatalf("expected one delete-by-id, got %d", installs.deleteByID)
	}
	if installs.byCode[1].Status != installationdomain.StatusRevoked || installs.byCode[0].Status != installationdomain.StatusInstalled {
		t.Fatalf("only the named instance must be revoked, got %q / %q", installs.byCode[0].Status, installs.byCode[1].Status)
	}
}

// TestUninstallByInstanceIDRejectsForeignCode: an instance id names a row of
// another catalog code (or is unknown) — refused as not found, nothing revoked.
func TestUninstallByInstanceIDRejectsForeignCode(t *testing.T) {
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{
		{ID: ids.New[ids.InstallationKind](), CatalogCode: "snowflake", Status: installationdomain.StatusInstalled},
	}}
	inst := newInstaller(t, &fakeRegistries{}, installs)
	err := inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", installs.byCode[0].ID.String())
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("instance of another code must be ErrNotFound, got %v", err)
	}
	if installs.deleteByID != 0 {
		t.Fatal("nothing may be revoked when the instance does not belong to the code")
	}
	err = inst.Uninstall(context.Background(), ids.New[ids.GatewayKind](), "ana", "github", ids.New[ids.InstallationKind]().String())
	if !errors.Is(err, installationdomain.ErrNotFound) {
		t.Fatalf("unknown instance must be ErrNotFound, got %v", err)
	}
}

func TestInstallDifferentConfigCreatesNewInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("snowflake")}}
	// An existing instance (schema "a") must not be treated as the same install
	// when a different config (schema "b") arrives: it is a new instance — a fresh
	// id, reported not-already-installed.
	configA := map[string]string{"account_url": "acme", "database": "a"}
	configB := map[string]string{"account_url": "acme", "database": "b"}
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{
		{ID: ids.New[ids.InstallationKind](), Status: installationdomain.StatusInstalled, Config: configA},
	}}
	in := openReq(gw, "snowflake")
	in.Config = configB
	res, err := newInstaller(t, regs, installs).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.AlreadyInstalled {
		t.Fatal("a new config must be a new instance, not already-installed")
	}
	if len(installs.upserts) != 1 || !installs.upserts[0].SameConfig(configB) {
		t.Fatal("expected an upsert carrying the new config")
	}
}
