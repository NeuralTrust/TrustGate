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

package store_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	"github.com/gofiber/fiber/v2"
)

type fakePreview struct {
	state *appstore.PrincipalState
	err   error
	subs  []string
}

func (f *fakePreview) Preview(_ context.Context, _ ids.GatewayID, sub string) (*appstore.PrincipalState, error) {
	f.subs = append(f.subs, sub)
	return f.state, f.err
}

func newPrincipalApp(p appstore.PrincipalPreview) *fiber.App {
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/store/principal", storehttp.NewPrincipalHandler(p).Get)
	return app
}

func TestPrincipalHandler_RequiresSub(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	fake := &fakePreview{}
	resp, err := newPrincipalApp(fake).Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/principal", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422 without sub, got %d", resp.StatusCode)
	}
	if len(fake.subs) != 0 {
		t.Fatalf("service must not be called without a sub")
	}
}

func TestPrincipalHandler_ShapesStateWithoutSecrets(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	inst := ids.New[ids.InstallationKind]()
	exp := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	fake := &fakePreview{state: &appstore.PrincipalState{
		PrincipalSub: "ana",
		Installs: []appstore.PrincipalInstall{
			{InstanceID: inst, Code: "github", Name: "GitHub", Status: installationdomain.StatusInstalled, InstalledBy: "ana"},
			{InstanceID: ids.New[ids.InstallationKind](), Code: "snowflake", Name: "Snowflake", RegistryID: reg, Registry: "Snowflake (finance)", Status: installationdomain.StatusPendingApproval},
		},
		Connections: []appstore.PrincipalConnection{
			{Provider: "github", Code: "github", RegistryID: reg, Registry: "GitHub", Linked: true, AccountRef: "ana@corp", ExpiresAt: exp},
			{Provider: "notion", Code: "notion", RegistryID: reg, Registry: "Notion"},
		},
	}}
	resp, err := newPrincipalApp(fake).Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/principal?sub=%20ana%20", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if len(fake.subs) != 1 || fake.subs[0] != "ana" {
		t.Fatalf("sub should be trimmed before the service, got %v", fake.subs)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["principal_sub"] != "ana" {
		t.Fatalf("principal_sub: %v", body["principal_sub"])
	}
	installs := body["installs"].([]any)
	if len(installs) != 2 {
		t.Fatalf("installs: %v", installs)
	}
	first := installs[0].(map[string]any)
	if first["instance_id"] != inst.String() || first["status"] != "installed" || first["name"] != "GitHub" {
		t.Fatalf("first install: %v", first)
	}
	if _, has := first["registry_id"]; has {
		t.Fatalf("code-level install must omit registry_id: %v", first)
	}
	second := installs[1].(map[string]any)
	if second["registry_id"] != reg.String() || second["registry"] != "Snowflake (finance)" || second["status"] != "pending_approval" {
		t.Fatalf("bound install: %v", second)
	}
	conns := body["connections"].([]any)
	if len(conns) != 2 {
		t.Fatalf("connections: %v", conns)
	}
	linked := conns[0].(map[string]any)
	if linked["linked"] != true || linked["account_ref"] != "ana@corp" || linked["expires_at"] != "2026-09-07T12:00:00Z" || linked["needs_reconnect"] != false {
		t.Fatalf("linked connection: %v", linked)
	}
	for _, k := range []string{"access_token", "refresh_token", "scopes"} {
		if _, has := linked[k]; has {
			t.Fatalf("connection leaks %q", k)
		}
	}
	unlinked := conns[1].(map[string]any)
	if unlinked["linked"] != false {
		t.Fatalf("unlinked connection: %v", unlinked)
	}
	if _, has := unlinked["expires_at"]; has {
		t.Fatalf("unlinked connection must omit expires_at: %v", unlinked)
	}
}
