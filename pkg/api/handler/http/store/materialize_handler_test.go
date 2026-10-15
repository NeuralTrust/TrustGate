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
	"strings"
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type fakeMaterializer struct {
	codes []string
	reg   *registrydomain.Registry
	err   error
}

func (f *fakeMaterializer) Materialize(_ context.Context, gatewayID ids.GatewayID, code string) (*registrydomain.Registry, error) {
	f.codes = append(f.codes, code)
	if f.err != nil {
		return nil, f.err
	}
	f.reg.GatewayID = gatewayID
	return f.reg, nil
}

func newMaterializeApp(m appstore.CatalogMaterializer) *fiber.App {
	app := fiber.New()
	app.Post("/v1/gateways/:gateway_id/registries/from-catalog", storehttp.NewMaterializeHandler(m).Handle)
	return app
}

func TestMaterializeHandler_ReturnsRegistryWithOrigin(t *testing.T) {
	id, _ := ids.NewV7[ids.RegistryKind]()
	fake := &fakeMaterializer{reg: &registrydomain.Registry{
		ID:      id,
		Name:    "Notion",
		Type:    registrydomain.TypeMCP,
		Enabled: true,
		MCPTarget: &registrydomain.MCPTarget{
			Code:   "com.notion/mcp",
			Origin: registrydomain.MCPOriginStore,
			URL:    "https://mcp.notion.com/mcp",
			Auth:   &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeForwarded, Provider: "com.notion/mcp"},
		},
	}}
	app := newMaterializeApp(fake)
	gw, _ := ids.NewV7[ids.GatewayKind]()

	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gw.String()+"/registries/from-catalog",
		strings.NewReader(`{"code":"com.notion/mcp"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body struct {
		ID        string `json:"id"`
		MCPTarget struct {
			Code   string `json:"code"`
			Origin string `json:"origin"`
		} `json:"mcp_target"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ID != id.String() || body.MCPTarget.Code != "com.notion/mcp" || body.MCPTarget.Origin != "store" {
		t.Fatalf("unexpected body %+v", body)
	}
	if len(fake.codes) != 1 || fake.codes[0] != "com.notion/mcp" {
		t.Fatalf("materializer called with %v", fake.codes)
	}
}

func TestMaterializeHandler_NeedsAdminSetupIs409(t *testing.T) {
	app := newMaterializeApp(&fakeMaterializer{err: appstore.ErrNeedsAdminSetup})
	gw, _ := ids.NewV7[ids.GatewayKind]()
	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gw.String()+"/registries/from-catalog",
		strings.NewReader(`{"code":"com.acme/mcp"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

func TestMaterializeHandler_BadBodyIsUnprocessable(t *testing.T) {
	app := newMaterializeApp(&fakeMaterializer{})
	gw, _ := ids.NewV7[ids.GatewayKind]()
	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gw.String()+"/registries/from-catalog",
		strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	// Validation failures map to 422 across the admin API.
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
}
