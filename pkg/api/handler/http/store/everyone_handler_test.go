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
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	"github.com/gofiber/fiber/v2"
)

type fakeEveryoneService struct {
	item *storeaccessdomain.Everyone
	sets []appstore.SetEveryoneRequest
}

func (f *fakeEveryoneService) GetEveryone(context.Context, ids.GatewayID) (*storeaccessdomain.Everyone, error) {
	return f.item, nil
}

func (f *fakeEveryoneService) Set(_ context.Context, in appstore.SetEveryoneRequest) (*storeaccessdomain.Everyone, error) {
	f.sets = append(f.sets, in)
	if in.Mode == "" {
		return nil, nil
	}
	return storeaccessdomain.NewEveryone(in.GatewayID, in.Mode, in.Grants, in.ExcludedGroups)
}

func newEveryoneApp(svc appstore.EveryoneService) *fiber.App {
	app := fiber.New()
	h := storehttp.NewEveryoneHandler(svc)
	app.Get("/v1/gateways/:gateway_id/store/everyone", h.Get)
	app.Put("/v1/gateways/:gateway_id/store/everyone", h.Set)
	return app
}

type everyoneBody struct {
	Mode   string `json:"mode"`
	Grants []struct {
		CatalogCode string `json:"catalog_code"`
		RegistryID  string `json:"registry_id"`
	} `json:"grants"`
	ExcludedGroups []string `json:"excluded_groups"`
}

func getEveryone(t *testing.T, app *fiber.App, url string) everyoneBody {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, url, nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var got everyoneBody
	if err := json.Unmarshal(body, &got); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get: %d %s (%v)", resp.StatusCode, body, err)
	}
	return got
}

func TestEveryoneHandler_GetEmptyAndSet(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	svc := &fakeEveryoneService{}
	app := newEveryoneApp(svc)
	base := "/v1/gateways/" + gw.String() + "/store/everyone"

	empty := getEveryone(t, app, base)
	if empty.Mode != "" || empty.Grants == nil || empty.ExcludedGroups == nil {
		t.Fatalf("no object must read as an empty mode with empty lists, got %+v", empty)
	}

	reg := ids.New[ids.RegistryKind]()
	body := `{"mode":"curated","grants":[{"catalog_code":"github"},{"catalog_code":"snowflake","registry_id":"` + reg.String() + `"}],"excluded_groups":["Contractors"]}`
	if resp := put(t, app, base, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("set status %d", resp.StatusCode)
	}
	if len(svc.sets) != 1 || len(svc.sets[0].Grants) != 2 || svc.sets[0].Grants[1].RegistryID != reg || svc.sets[0].ExcludedGroups[0] != "Contractors" {
		t.Fatalf("set must forward the parsed request, got %+v", svc.sets)
	}

	svc.item, _ = storeaccessdomain.NewEveryone(gw, "curated", svc.sets[0].Grants, svc.sets[0].ExcludedGroups)
	got := getEveryone(t, app, base)
	if got.Mode != "curated" || len(got.Grants) != 2 || got.Grants[0].RegistryID != "" || got.Grants[1].RegistryID != reg.String() {
		t.Fatalf("get must return the object, got %+v", got)
	}

	if resp := put(t, app, base, `{"mode":""}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("removal must be 204, got %d", resp.StatusCode)
	}
	if resp := put(t, app, base, `{"mode":"none"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("mode none must be 422, got %d", resp.StatusCode)
	}
	if resp := put(t, app, base, `{"mode":"curated"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("curated without grants must be 422, got %d", resp.StatusCode)
	}
	if resp := put(t, app, base, `{"mode":"curated","grants":[{"catalog_code":"github","registry_id":"nope"}]}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a bad registry id must be 422, got %d", resp.StatusCode)
	}
}
