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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/gofiber/fiber/v2"
)

type fakeGrantService struct {
	items []*storeaccessdomain.Grant
	sets  []appstore.SetGrantRequest
	err   error
}

func (f *fakeGrantService) ListByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	return f.items, f.err
}

func (f *fakeGrantService) Upsert(context.Context, *storeaccessdomain.Grant) error { return f.err }

func (f *fakeGrantService) Set(_ context.Context, in appstore.SetGrantRequest) (*storeaccessdomain.Grant, error) {
	f.sets = append(f.sets, in)
	if f.err != nil {
		return nil, f.err
	}
	return storeaccessdomain.New(in.GatewayID, in.CatalogCode, in.RegistryID, in.Groups, in.Users)
}

func newGrantsApp(svc appstore.GrantService) *fiber.App {
	app := fiber.New()
	h := storehttp.NewGrantsHandler(svc)
	app.Get("/v1/gateways/:gateway_id/store/grants", h.List)
	app.Put("/v1/gateways/:gateway_id/store/grants", h.Set)
	return app
}

func put(t *testing.T, app *fiber.App, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

func TestGrantsHandler_ListShapesCodeAndInstanceGrants(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	code, _ := storeaccessdomain.New(gw, "github", ids.RegistryID{}, []string{"eng"}, nil)
	inst, _ := storeaccessdomain.New(gw, "snowflake", reg, nil, []string{"ana"})
	app := newGrantsApp(&fakeGrantService{items: []*storeaccessdomain.Grant{code, inst}})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/grants", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != 2 || len(got.Items) != 2 {
		t.Fatalf("expected two grants, got %s", body)
	}
	if _, present := got.Items[0]["registry_id"]; present {
		t.Fatalf("code-level grant must omit registry_id, got %v", got.Items[0])
	}
	if got.Items[0]["users"] == nil {
		t.Fatalf("empty member lists must be [] not null, got %v", got.Items[0])
	}
	if got.Items[1]["registry_id"] != reg.String() {
		t.Fatalf("instance grant must carry registry_id, got %v", got.Items[1])
	}
}

func TestGrantsHandler_SetForwardsAndValidates(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	svc := &fakeGrantService{}
	app := newGrantsApp(svc)
	base := "/v1/gateways/" + gw.String() + "/store/grants"

	resp := put(t, app, base, `{"catalog_code":"snowflake","registry_id":"`+reg.String()+`","groups":["finance"],"users":[]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(svc.sets) != 1 || svc.sets[0].RegistryID != reg || svc.sets[0].GatewayID != gw || svc.sets[0].Groups[0] != "finance" {
		t.Fatalf("set must forward the parsed grant, got %+v", svc.sets)
	}

	if resp := put(t, app, base, `{"registry_id":"`+reg.String()+`"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("missing catalog_code must be 422, got %d", resp.StatusCode)
	}
	if resp := put(t, app, base, `{"catalog_code":"snowflake","registry_id":"nope"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("malformed registry_id must be 422, got %d", resp.StatusCode)
	}
	if resp := put(t, app, base, `{`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("malformed body must be 422, got %d", resp.StatusCode)
	}
	if resp := put(t, app, "/v1/gateways/not-a-uuid/store/grants", `{"catalog_code":"snowflake"}`); resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("malformed gateway id must be a client error, got %d", resp.StatusCode)
	}
}
