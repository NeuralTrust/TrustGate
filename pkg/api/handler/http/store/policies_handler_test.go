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

type fakePolicyService struct {
	items []*storeaccessdomain.Policy
	sets  []appstore.SetPolicyRequest
}

func (f *fakePolicyService) ListPoliciesByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Policy, error) {
	return f.items, nil
}

func (f *fakePolicyService) Set(_ context.Context, in appstore.SetPolicyRequest) (*storeaccessdomain.Policy, error) {
	f.sets = append(f.sets, in)
	if in.Mode == "" {
		return nil, nil
	}
	return storeaccessdomain.NewPolicy(in.GatewayID, in.PrincipalType, in.PrincipalID, in.Mode)
}

func newPoliciesApp(svc appstore.PolicyService) *fiber.App {
	app := fiber.New()
	h := storehttp.NewPoliciesHandler(svc)
	app.Get("/v1/gateways/:gateway_id/store/access-policies", h.List)
	app.Put("/v1/gateways/:gateway_id/store/access-policies", h.Set)
	return app
}

func TestPoliciesHandler_ListAndSet(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	p, _ := storeaccessdomain.NewPolicy(gw, storeaccessdomain.PrincipalGroup, "eng", "curated")
	svc := &fakePolicyService{items: []*storeaccessdomain.Policy{p}}
	app := newPoliciesApp(svc)
	base := "/v1/gateways/" + gw.String() + "/store/access-policies"

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, base, nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var got struct {
		Items []map[string]string `json:"items"`
		Total int                 `json:"total"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Total != 1 {
		t.Fatalf("list: %s (%v)", body, err)
	}
	if got.Items[0]["principal_type"] != "group" || got.Items[0]["principal_id"] != "eng" || got.Items[0]["mode"] != "curated" {
		t.Fatalf("unexpected item %v", got.Items[0])
	}

	if resp := put(t, app, base, `{"principal_type":"User","principal_id":"ana","mode":"none"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("set status %d", resp.StatusCode)
	}
	if len(svc.sets) != 1 || svc.sets[0].PrincipalType != storeaccessdomain.PrincipalUser || svc.sets[0].Mode != "none" {
		t.Fatalf("set must forward the normalised request, got %+v", svc.sets)
	}
	if resp := put(t, app, base, `{"principal_type":"user","principal_id":"ana","mode":""}`); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("clearing must be 204, got %d", resp.StatusCode)
	}
	if resp := put(t, app, base, `{"principal_type":"user","mode":"open"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("missing principal_id must be 422, got %d", resp.StatusCode)
	}
}
