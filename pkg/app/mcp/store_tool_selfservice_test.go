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

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storegrantdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storegrant"
)

// e2eCatalog serves the search catalog, the installer's by-code lookup and the
// registry creator's auth canonicalisation over one fixture set.
type e2eCatalog struct {
	servers []catalogdomain.MCPServer
	shared  map[string][2]string
}

func (c e2eCatalog) ListMCPServers() []catalogdomain.MCPServer { return c.servers }

func (c e2eCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	for _, s := range c.servers {
		if s.Code == code {
			return s, true
		}
	}
	return catalogdomain.MCPServer{}, false
}

func (c e2eCatalog) SharedOAuthCredentials(code string) (string, string, bool) {
	creds, ok := c.shared[code]
	return creds[0], creds[1], ok
}

// e2eRegistries is the gateway's registry set: the installer/scoper read it and
// the creator appends to it, like the control plane's DB.
type e2eRegistries struct{ items []*registrydomain.Registry }

func (r *e2eRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return r.items, len(r.items), nil
}

// e2eCreator mirrors the real registry Creator's MCP path minus persistence:
// normalise, canonicalise auth from the catalog, and build (validate) the
// registry. A target the catalog cannot materialise fails here exactly as it
// would in production.
type e2eCreator struct {
	catalog appregistry.MCPAuthCatalog
	regs    *e2eRegistries
	created int
}

func (c *e2eCreator) Create(_ context.Context, in appregistry.CreateInput) (*registrydomain.Registry, error) {
	in.MCPTarget.Normalize()
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(in.MCPTarget, c.catalog); err != nil {
		return nil, err
	}
	reg, err := registrydomain.NewMCPRegistry(in.GatewayID, in.Name, in.Description, in.MCPTarget)
	if err != nil {
		return nil, err
	}
	if in.Enabled != nil {
		reg.Enabled = *in.Enabled
	}
	c.created++
	c.regs.items = append(c.regs.items, reg)
	return reg, nil
}

// e2eGrants is an in-memory Store grant store.
type e2eGrants struct{ items []*storegrantdomain.Grant }

func (g *e2eGrants) ListByGateway(context.Context, ids.GatewayID) ([]*storegrantdomain.Grant, error) {
	return g.items, nil
}

func (g *e2eGrants) Upsert(_ context.Context, grant *storegrantdomain.Grant) error {
	for i, existing := range g.items {
		if existing.CatalogCode == grant.CatalogCode && existing.RegistryID == grant.RegistryID {
			g.items[i] = grant
			return nil
		}
	}
	g.items = append(g.items, grant)
	return nil
}

// e2eInstalls is an in-memory installation repository keyed by instance id.
type e2eInstalls struct {
	rows []*installationdomain.Installation
}

func (f *e2eInstalls) Upsert(_ context.Context, in *installationdomain.Installation) error {
	for i, r := range f.rows {
		if r.ID == in.ID {
			f.rows[i] = in
			return nil
		}
	}
	f.rows = append(f.rows, in)
	return nil
}

func (f *e2eInstalls) Find(_ context.Context, gw ids.GatewayID, sub, code string) (*installationdomain.Installation, error) {
	for _, r := range f.rows {
		if r.GatewayID == gw && r.PrincipalSub == sub && r.CatalogCode == code {
			return r, nil
		}
	}
	return nil, installationdomain.ErrNotFound
}

func (f *e2eInstalls) FindByID(_ context.Context, gw ids.GatewayID, sub string, id ids.InstallationID) (*installationdomain.Installation, error) {
	for _, r := range f.rows {
		if r.GatewayID == gw && r.PrincipalSub == sub && r.ID == id {
			return r, nil
		}
	}
	return nil, installationdomain.ErrNotFound
}

func (f *e2eInstalls) ListByPrincipalAndCode(_ context.Context, gw ids.GatewayID, sub, code string) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, r := range f.rows {
		if r.GatewayID == gw && r.PrincipalSub == sub && r.CatalogCode == code {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *e2eInstalls) ListByPrincipal(_ context.Context, gw ids.GatewayID, sub string) ([]*installationdomain.Installation, error) {
	var out []*installationdomain.Installation
	for _, r := range f.rows {
		if r.GatewayID == gw && r.PrincipalSub == sub {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *e2eInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *e2eInstalls) ListPendingByGateway(context.Context, ids.GatewayID) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *e2eInstalls) Delete(context.Context, ids.GatewayID, string, string) error { return nil }
func (f *e2eInstalls) DeleteByID(context.Context, ids.GatewayID, string, ids.InstallationID) error {
	return nil
}

// e2eConnect records the connect ticket the install minted.
type e2eConnect struct {
	code, instanceID string
	calls            int
}

func (c *e2eConnect) CreateServerTicket(_ context.Context, _ ids.GatewayID, _, _, code, instanceID string) (string, error) {
	c.calls++
	c.code, c.instanceID = code, instanceID
	return "ticket-1", nil
}

// e2eConfigure records the configure ticket the install minted.
type e2eConfigure struct {
	last  appoauth.ConfigureTicketRequest
	calls int
}

func (c *e2eConfigure) CreateTicket(_ context.Context, in appoauth.ConfigureTicketRequest) (string, error) {
	c.calls++
	c.last = in
	return "cfg-1", nil
}

func notionLike() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code: "com.notion/mcp", DisplayName: "Notion", Vendor: "Notion", Category: "productivity",
		URL: "https://mcp.notion.com/mcp", Transport: "streamable-http",
		AuthHint: "oauth", AuthMethods: []string{"oauth"}, RequiresAuth: true,
		OAuth: &catalogdomain.MCPOAuth{
			Required: true, ResourceMetadata: true, Registration: "auto",
			AuthorizeURL: "https://mcp.notion.com/authorize", TokenURL: "https://mcp.notion.com/token",
		},
	}
}

// platformClientLike is a server whose OAuth client is pre-registered and held
// by the platform (registration manual, but no admin input is needed).
func platformClientLike() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code: "com.platform/mcp", DisplayName: "Platform", URL: "https://mcp.platform.example/mcp",
		Transport: "streamable-http", AuthHint: "oauth", AuthMethods: []string{"oauth"}, RequiresAuth: true,
		PlatformClient: true,
		OAuth: &catalogdomain.MCPOAuth{
			Required: true, Registration: "manual",
			AuthorizeURL: "https://mcp.platform.example/authorize", TokenURL: "https://mcp.platform.example/token",
		},
	}
}

func apiKeyOnlyLike() catalogdomain.MCPServer {
	return catalogdomain.MCPServer{
		Code: "com.semrush/mcp", DisplayName: "Semrush", URL: "https://mcp.semrush.com/mcp",
		Transport: "streamable-http", AuthHint: "static", AuthMethods: []string{"static"}, RequiresAuth: true,
		AuthHeaders: []catalogdomain.MCPAuthHeader{{Name: "Authorization", Required: true, Secret: true, Scheme: "Bearer"}},
	}
}

type e2eHarness struct {
	tool      StoreTool
	regs      *e2eRegistries
	creator   *e2eCreator
	installs  *e2eInstalls
	grants    *e2eGrants
	connect   *e2eConnect
	configure *e2eConfigure
	rc        *appconsumer.RoutableConsumer
}

// newE2EHarness wires the REAL store tool → REAL installer → REAL registry
// ensurer over in-memory ports, with the creator validating targets exactly as
// production does.
func newE2EHarness(t *testing.T, servers ...catalogdomain.MCPServer) *e2eHarness {
	t.Helper()
	catalog := e2eCatalog{servers: servers, shared: map[string][2]string{"com.platform/mcp": {"platform-client-id", "platform-secret"}}}
	regs := &e2eRegistries{}
	creator := &e2eCreator{catalog: catalog, regs: regs}
	ensurer, err := appstore.NewRegistryEnsurer(catalog, regs, creator)
	if err != nil {
		t.Fatalf("NewRegistryEnsurer: %v", err)
	}
	installs := &e2eInstalls{}
	grants := &e2eGrants{}
	installer, err := appstore.NewInstaller(catalog, regs, installs, grants, ensurer)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	connect := &e2eConnect{}
	configure := &e2eConfigure{}
	tool, err := NewStoreToolWithInstaller(catalog, installer, regs, grants, configure, connect)
	if err != nil {
		t.Fatalf("NewStoreToolWithInstaller: %v", err)
	}
	gw := ids.New[ids.GatewayKind]()
	return &e2eHarness{
		tool: tool, regs: regs, creator: creator, installs: installs, grants: grants, connect: connect, configure: configure,
		rc: &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)},
	}
}

// selfServiceDefaultCtx is the zero-friction self-service default: a free-tier
// gateway with nothing stamped and a token carrying no store_access claim. This
// is the state a fresh self-service org is in before its admin configures any
// governance, so the Store is open.
func selfServiceDefaultCtx(sub string) context.Context {
	gw := &gatewaydomain.Gateway{
		Entitlements: gatewaydomain.Entitlements{Tier: "free"},
	}
	principal := &identity.Principal{Subject: sub, Claims: map[string]any{
		identity.ClaimGroups: []string{"eng"},
	}}
	return appgateway.WithGateway(identity.WithPrincipal(context.Background(), principal), gw)
}

// TestStoreInstall_SelfServiceOAuthEndToEnd is the product guarantee: on a
// self-service gateway, trustgate_store_install {code} for an OAuth catalog
// server (DCR auto, or a platform-held client) with no required URL variables
// materialises the registry, records the install and returns requires_auth with
// a connect link pinned to the new instance — with no admin configuration at
// all, since an unstamped Store defaults to open.
func TestStoreInstall_SelfServiceOAuthEndToEnd(t *testing.T) {
	cases := []struct {
		name   string
		server catalogdomain.MCPServer
	}{
		{name: "dcr auto (Notion-like)", server: notionLike()},
		{name: "platform-held client", server: platformClientLike()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newE2EHarness(t, tc.server)
			ctx := selfServiceDefaultCtx("ana")

			raw, err := h.tool.Call(ctx, h.rc, "https://gw.example", StoreInstallToolName,
				json.RawMessage(`{"code":"`+tc.server.Code+`"}`))
			if err != nil {
				t.Fatalf("install: %v", err)
			}
			sc := decodeStructured(t, raw)

			// Materialised: exactly one registry, on the shelf, forwarded auth.
			if h.creator.created != 1 || len(h.regs.items) != 1 {
				t.Fatalf("expected exactly one materialised registry, got %d", len(h.regs.items))
			}
			reg := h.regs.items[0]
			if reg.MCPTarget.Code != tc.server.Code {
				t.Fatalf("materialised registry must carry the code: %+v", reg.MCPTarget)
			}
			if reg.MCPTarget.Auth == nil || reg.MCPTarget.Auth.Mode != registrydomain.MCPAuthModeForwarded {
				t.Fatalf("OAuth server must materialise with forwarded auth, got %+v", reg.MCPTarget.Auth)
			}
			if err := reg.MCPTarget.Validate(); err != nil {
				t.Fatalf("materialised target must validate: %v", err)
			}

			// Installed: one active row for the principal.
			if len(h.installs.rows) != 1 || h.installs.rows[0].Status != installationdomain.StatusInstalled {
				t.Fatalf("expected one installed row, got %+v", h.installs.rows)
			}
			inst := h.installs.rows[0]

			// Result: installed, requires_auth, connect link, instance id.
			if sc["status"] != string(installationdomain.StatusInstalled) || sc["pending"] != false {
				t.Fatalf("result must report installed, got %+v", sc)
			}
			if sc["requires_auth"] != true {
				t.Fatalf("result must carry requires_auth, got %+v", sc)
			}
			if sc["requires_admin_setup"] != false {
				t.Fatalf("an OAuth server must not need admin setup, got %+v", sc)
			}
			if sc["instance"] != inst.ID.String() {
				t.Fatalf("result must carry the instance id %s, got %v", inst.ID, sc["instance"])
			}
			connectURL, _ := sc["connect_url"].(string)
			if !strings.Contains(connectURL, "ticket=ticket-1") || !strings.Contains(connectURL, appconsumer.MCPPath(h.rc.Consumer.Slug)) {
				t.Fatalf("result must carry the connect link, got %q", connectURL)
			}
			if h.connect.calls != 1 || h.connect.code != tc.server.Code || h.connect.instanceID != inst.ID.String() {
				t.Fatalf("connect ticket must be scoped to the code and pinned to the instance, got %+v", h.connect)
			}
			if text := decodeText(t, raw); !strings.Contains(text, "Installed "+tc.server.DisplayName) || !strings.Contains(text, connectURL) {
				t.Fatalf("text must announce the install and present the connect link, got %q", text)
			}

			// Idempotent: a second install is the same instance, still with the link.
			raw2, err := h.tool.Call(ctx, h.rc, "https://gw.example", StoreInstallToolName,
				json.RawMessage(`{"code":"`+tc.server.Code+`"}`))
			if err != nil {
				t.Fatalf("second install: %v", err)
			}
			sc2 := decodeStructured(t, raw2)
			if sc2["already_installed"] != true || sc2["instance"] != inst.ID.String() || h.creator.created != 1 || len(h.installs.rows) != 1 {
				t.Fatalf("second install must be idempotent, got %+v (regs=%d rows=%d)", sc2, h.creator.created, len(h.installs.rows))
			}
			if _, ok := sc2["connect_url"]; !ok {
				t.Fatal("a re-install must still offer the connect link")
			}
		})
	}
}

// TestStoreInstall_SelfServiceHonoursGovernance guards the corrected product
// rule: governance is not a plan entitlement. Once a self-service admin narrows
// the Store (stamped none) or a principal's policy says none, the same
// enforcement applies as on enterprise — the install is refused and the search
// is closed.
func TestStoreInstall_SelfServiceHonoursGovernance(t *testing.T) {
	h := newE2EHarness(t, notionLike())
	gw := &gatewaydomain.Gateway{Entitlements: gatewaydomain.Entitlements{Tier: "standard"}, Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeNone)}
	ctx := appgateway.WithGateway(ctxWithStoreAccess(context.Background(), "ana", gatewaydomain.StoreModeNone), gw)
	if _, err := h.tool.Call(ctx, h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.notion/mcp"}`)); err == nil {
		t.Fatal("store_access=none on a self-service gateway must refuse the install")
	}
	if h.creator.created != 0 {
		t.Fatalf("a refused install must not materialise a registry, created=%d", h.creator.created)
	}
	raw, err := h.tool.Call(ctx, h.rc, "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if sc := decodeStructured(t, raw); sc["total"].(float64) != 0 || sc["mode"] != gatewaydomain.StoreModeNone {
		t.Fatalf("a closed self-service Store must browse nothing, got %+v", sc)
	}
	// A stamped curated mode on a free tier is enforced too: a non-shelf server
	// becomes a pending request instead of being materialised.
	curated := appgateway.WithGateway(identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana"}),
		&gatewaydomain.Gateway{Entitlements: gatewaydomain.Entitlements{Tier: "free"}, Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeCurated)})
	raw, err = h.tool.Call(curated, h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.notion/mcp"}`))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if sc := decodeStructured(t, raw); sc["pending"] != true || h.creator.created != 0 {
		t.Fatalf("curated self-service install of a non-shelf server must be a pending request, got %+v (created=%d)", sc, h.creator.created)
	}
}

// TestStoreInstall_EnterpriseHonoursClaimAndMode: the same claim/mode on an
// enterprise gateway is enforced.
func TestStoreInstall_EnterpriseHonoursClaimAndMode(t *testing.T) {
	h := newE2EHarness(t, notionLike())
	closed := appgateway.WithGateway(ctxWithStoreAccess(context.Background(), "ana", gatewaydomain.StoreModeNone), enterpriseGateway(gatewaydomain.StoreModeOpen))
	if _, err := h.tool.Call(closed, h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.notion/mcp"}`)); err == nil {
		t.Fatal("store_access=none on an enterprise gateway must refuse the install")
	}
	curated := appgateway.WithGateway(identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana"}), enterpriseGateway(gatewaydomain.StoreModeCurated))
	raw, err := h.tool.Call(curated, h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.notion/mcp"}`))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if sc := decodeStructured(t, raw); sc["pending"] != true || h.creator.created != 0 {
		t.Fatalf("curated enterprise install of a non-shelf server must be a pending request without materialisation, got %+v (created=%d)", sc, h.creator.created)
	}
}

// TestStoreInstall_NoGatewayInContextFailsClosed: without a resolved gateway the
// tier is unknown, so the Store is curated — a non-shelf server becomes a request
// rather than being materialised.
func TestStoreInstall_NoGatewayInContextFailsClosed(t *testing.T) {
	h := newE2EHarness(t, notionLike())
	raw, err := h.tool.Call(ctxWithPrincipal(), h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.notion/mcp"}`))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if sc := decodeStructured(t, raw); sc["pending"] != true || h.creator.created != 0 {
		t.Fatalf("missing gateway must fail closed to curated, got %+v (created=%d)", sc, h.creator.created)
	}
	// Search without a gateway reports curated: the catalog is browsable but a
	// non-shelf server is a request, never an instant install.
	raw, err = h.tool.Call(ctxWithPrincipal(), h.rc, "", StoreSearchToolName, nil)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["mode"] != gatewaydomain.StoreModeCurated {
		t.Fatalf("missing gateway must browse as curated, got %+v", sc)
	}
	for _, r := range sc["results"].([]any) {
		if r.(map[string]any)["store_state"] != storeStateRequest {
			t.Fatalf("under curated a non-shelf server must be a request, got %+v", r)
		}
	}
}

// TestStoreInstall_SelfServiceStaticOnlyReportsAdminSetup guards fix 6 end to
// end: an API-key-only server in open mode yields a clean result (no error), no
// registry, no row, no connect link, and a message pointing at the admin.
func TestStoreInstall_SelfServiceStaticOnlyReportsAdminSetup(t *testing.T) {
	h := newE2EHarness(t, apiKeyOnlyLike())
	raw, err := h.tool.Call(selfServiceDefaultCtx("ana"), h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.semrush/mcp"}`))
	if err != nil {
		t.Fatalf("install must not error, got %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["requires_admin_setup"] != true || sc["pending"] != false || sc["status"] != "" {
		t.Fatalf("expected a requires-admin-setup result, got %+v", sc)
	}
	if _, ok := sc["connect_url"]; ok {
		t.Fatal("no connect link when nothing was installed")
	}
	if h.creator.created != 0 || len(h.installs.rows) != 0 {
		t.Fatalf("nothing may be materialised or recorded, regs=%d rows=%d", h.creator.created, len(h.installs.rows))
	}
	if text := decodeText(t, raw); !strings.Contains(text, "administrator") {
		t.Fatalf("text must tell the user an admin has to add the credential, got %q", text)
	}
}

// TestStoreInstall_ConfigureLinkPinnedToInstanceAndGroups: a secret-only server
// records the install and the configure ticket carries the instance id and the
// principal's groups so the form is governed like the tool.
func TestStoreInstall_ConfigureLinkPinnedToInstanceAndGroups(t *testing.T) {
	bright := catalogdomain.MCPServer{
		Code: "com.brightdata/mcp", DisplayName: "Bright Data", URL: "https://mcp.brightdata.com/mcp?token={token}",
		Transport: "streamable-http", AuthHint: "static", AuthMethods: []string{"static"}, RequiresAuth: true,
		URLVariables: []catalogdomain.MCPURLVariable{{Name: "token", Required: true, Secret: true, In: "query"}},
	}
	h := newE2EHarness(t, bright)
	raw, err := h.tool.Call(selfServiceDefaultCtx("ana"), h.rc, "https://gw.example", StoreInstallToolName, json.RawMessage(`{"code":"com.brightdata/mcp"}`))
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	sc := decodeStructured(t, raw)
	if sc["requires_config"] != true || sc["status"] != string(installationdomain.StatusInstalled) {
		t.Fatalf("secret-only server must install and require config, got %+v", sc)
	}
	if len(h.installs.rows) != 1 || h.creator.created != 1 {
		t.Fatalf("expected one row and one registry, got rows=%d regs=%d", len(h.installs.rows), h.creator.created)
	}
	if h.configure.calls != 1 || h.configure.last.InstanceID != h.installs.rows[0].ID.String() {
		t.Fatalf("configure ticket must be pinned to the recorded instance, got %+v", h.configure.last)
	}
	if len(h.configure.last.Groups) != 1 || h.configure.last.Groups[0] != "eng" {
		t.Fatalf("configure ticket must snapshot the principal's groups, got %+v", h.configure.last.Groups)
	}
	if _, ok := sc["configure_url"]; !ok {
		t.Fatal("result must carry the configure link")
	}
}
