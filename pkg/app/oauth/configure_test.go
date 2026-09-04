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

type fakeInstalls struct {
	rows map[string]*installationdomain.Installation
}

func (f *fakeInstalls) key(gw ids.GatewayID, sub, code string) string {
	return gw.String() + "|" + sub + "|" + code
}

func (f *fakeInstalls) Upsert(_ context.Context, in *installationdomain.Installation) error {
	if f.rows == nil {
		f.rows = map[string]*installationdomain.Installation{}
	}
	f.rows[f.key(in.GatewayID, in.PrincipalSub, in.CatalogCode)] = in
	return nil
}

func (f *fakeInstalls) Find(_ context.Context, gw ids.GatewayID, sub, code string) (*installationdomain.Installation, error) {
	if in, ok := f.rows[f.key(gw, sub, code)]; ok {
		return in, nil
	}
	return nil, installationdomain.ErrNotFound
}

func (f *fakeInstalls) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeInstalls) ListByCatalogCode(context.Context, ids.GatewayID, string) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeInstalls) ListPendingByGateway(context.Context, ids.GatewayID) ([]*installationdomain.Installation, error) {
	return nil, nil
}
func (f *fakeInstalls) Delete(context.Context, ids.GatewayID, string, string) error { return nil }

func configureFixture(t *testing.T) (oauth.ConfigureService, *memConnectStore, *memVaultRepo, *fakeInstalls, ids.GatewayID) {
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
	catalog := fakeConfigCatalog{byCode: map[string]catalogdomain.MCPServer{
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
	svc := oauth.NewConfigureService(store, &stubDataFinder{data: data}, catalog, installs, vault)
	return svc, store, vault, installs, gw
}

func configTicket(t *testing.T, store *memConnectStore, svc oauth.ConfigureService, gw ids.GatewayID, code string) string {
	t.Helper()
	id, err := svc.CreateTicket(context.Background(), gw, "ana", appconsumer.MCPPath("dev"), code)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	return id
}

func TestConfigure_SubmitPlainStoresOnInstallation(t *testing.T) {
	svc, store, _, installs, gw := configureFixture(t)
	id := configTicket(t, store, svc, gw, "snowflake")

	page, err := svc.Submit(context.Background(), id, map[string]string{
		"account_url": "acme.snowflakecomputing.com",
		"database":    "ANALYTICS",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !page.Saved {
		t.Fatal("submit must report saved")
	}
	inst, err := installs.Find(context.Background(), gw, "ana", "snowflake")
	if err != nil {
		t.Fatalf("installation not created: %v", err)
	}
	if inst.Config["account_url"] != "acme.snowflakecomputing.com" || inst.Config["database"] != "ANALYTICS" {
		t.Fatalf("plain values not persisted: %+v", inst.Config)
	}
}

func TestConfigure_SubmitSecretStoresInVault(t *testing.T) {
	svc, store, vault, _, gw := configureFixture(t)
	id := configTicket(t, store, svc, gw, "com.brightdata/mcp")

	if _, err := svc.Submit(context.Background(), id, map[string]string{"token": "s3cr3t"}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	provider := registrydomain.URLVariableVaultProvider("com.brightdata/mcp", "token")
	cred, err := vault.Find(context.Background(), gw, "ana", provider)
	if err != nil {
		t.Fatalf("secret not in vault under %q: %v", provider, err)
	}
	if cred.AccessToken != "s3cr3t" {
		t.Fatalf("wrong secret stored: %q", cred.AccessToken)
	}
}

func TestConfigure_SubmitRejectsUnsafeValue(t *testing.T) {
	svc, store, _, _, gw := configureFixture(t)
	id := configTicket(t, store, svc, gw, "snowflake")
	_, err := svc.Submit(context.Background(), id, map[string]string{"account_url": "evil.com/../x"})
	if !errors.Is(err, oauth.ErrConfigureInvalid) {
		t.Fatalf("unsafe value must be rejected, got %v", err)
	}
}

func TestConfigure_SubmitRejectsUnknownVariable(t *testing.T) {
	svc, store, _, _, gw := configureFixture(t)
	id := configTicket(t, store, svc, gw, "snowflake")
	_, err := svc.Submit(context.Background(), id, map[string]string{"bogus": "x"})
	if !errors.Is(err, oauth.ErrConfigureInvalid) {
		t.Fatalf("unknown variable must be rejected, got %v", err)
	}
}

func TestConfigure_PageReportsSetState(t *testing.T) {
	svc, store, _, _, gw := configureFixture(t)
	id := configTicket(t, store, svc, gw, "snowflake")
	if _, err := svc.Submit(context.Background(), id, map[string]string{"account_url": "acme.snowflakecomputing.com"}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	page, err := svc.Page(context.Background(), id)
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
	svc, _, _, _, _ := configureFixture(t)
	if _, err := svc.Page(context.Background(), "nope"); !errors.Is(err, oauth.ErrTicketNotFound) {
		t.Fatalf("unknown ticket must fail, got %v", err)
	}
}
