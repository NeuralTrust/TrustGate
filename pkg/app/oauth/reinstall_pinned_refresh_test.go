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
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

// A row written before host was pinned still stores it. The catalog server
// URL is filled from those stored values, so a reinstall that dropped host
// would stop applyCatalog: RefreshAuth would fall back to the scopes and
// resource persisted on the registry.
func TestReinstall_KeepsPinnedKeySoRefreshAuthStaysOnTheCatalog(t *testing.T) {
	const (
		code            = "kibana"
		catalogScope    = "catalog-scope"
		catalogResource = "https://acme.kb.example.com/audience"
		storedScope     = "stored-scope"
		storedResource  = "https://old.example/audience"
	)
	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "kibana", "", &registrydomain.MCPTarget{
		Code: code,
		URL:  "https://acme.kb.example.com/s/default/mcp",
		URLVariables: []registrydomain.MCPURLVariable{
			{Name: "host", Required: true},
			{Name: "space", Required: true},
		},
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     code,
			Registration: registrydomain.RegistrationAuto,
			Scopes:       []string{storedScope},
			Resource:     storedResource,
		},
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	catalog := stubScopeCatalog{
		code:     code,
		url:      "https://{host}/s/{space}/mcp",
		scopes:   []string{catalogScope},
		resource: catalogResource,
		urlVariables: []catalogdomain.MCPURLVariable{
			{Name: "host", Required: true},
			{Name: "space", Required: true},
		},
	}
	old, err := installationdomain.New(gw, "ana", code, "ana", map[string]string{
		"host":  "acme.kb.example.com",
		"space": "default",
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	installs := &fakeInstalls{}
	if err := installs.Upsert(context.Background(), old); err != nil {
		t.Fatalf("seed: %v", err)
	}
	data := appconsumer.NewData(gw, []appconsumer.RoutableConsumer{{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw,
			Type: consumerdomain.TypeMCP, Slug: "dev", Active: true,
		},
		Registries: []*registrydomain.Registry{reg},
	}})
	registrar := &fixedRegistrar{
		meta: &oauth.UpstreamAuthServer{
			AuthorizationEndpoint: "https://acme.kb.example.com/oauth/authorize",
			TokenEndpoint:         "https://acme.kb.example.com/oauth/token",
		},
		client: &oauth.RegisteredClient{ClientID: "dcr-kibana"},
	}
	svc := oauth.NewConnectService(
		newMemConnectStore(),
		&memVaultRepo{},
		&stubDataFinder{data: data},
		infraoauth.NewProviderClient(nil),
		registrar,
		discardConnectAuditor(),
		nil, nil,
		catalog,
		nil,
		oauth.WithConnectURLValues(appmcp.NewURLValueResolver(installs, nil)),
	)
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana"})

	before, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth before reinstall: %v", err)
	}
	if strings.Join(before.Scopes, " ") != catalogScope || before.Resource != catalogResource {
		t.Fatalf("before = scopes %q resource %q, want the catalog values", strings.Join(before.Scopes, " "), before.Resource)
	}

	installer, err := appstore.NewInstaller(catalog, &fakeShelf{items: []*registrydomain.Registry{reg}}, installs, nil, nil)
	if err != nil {
		t.Fatalf("NewInstaller: %v", err)
	}
	res, err := installer.Install(context.Background(), appstore.InstallRequest{
		GatewayID: gw, PrincipalSub: "ana", Code: code, InstalledBy: "ana", OpenMode: true,
		Config: map[string]string{},
	})
	if err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if !res.AlreadyInstalled || res.InstanceID != old.ID.String() {
		t.Fatalf("reinstall must refresh the existing row, got %+v", res)
	}

	after, err := svc.RefreshAuth(ctx, gw, reg)
	if err != nil {
		t.Fatalf("RefreshAuth after reinstall: %v", err)
	}
	if strings.Join(after.Scopes, " ") != strings.Join(before.Scopes, " ") || after.Resource != before.Resource {
		t.Fatalf("RefreshAuth changed from scopes %q resource %q to scopes %q resource %q",
			strings.Join(before.Scopes, " "), before.Resource, strings.Join(after.Scopes, " "), after.Resource)
	}
}
