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
	"time"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type fakeApprover struct {
	pending  []appstore.PendingRequest
	approved []appstore.ApproveRequest
	denied   []appstore.DenyRequest
	err      error
}

func (f *fakeApprover) ListPending(context.Context, ids.GatewayID) ([]appstore.PendingRequest, error) {
	return f.pending, f.err
}

func (f *fakeApprover) Approve(_ context.Context, in appstore.ApproveRequest) error {
	f.approved = append(f.approved, in)
	return f.err
}

func (f *fakeApprover) Deny(_ context.Context, in appstore.DenyRequest) error {
	f.denied = append(f.denied, in)
	return f.err
}

func newApp(approver appstore.Approver) *fiber.App {
	app := fiber.New()
	h := storehttp.NewRequestsHandler(approver)
	app.Get("/v1/gateways/:gateway_id/store/requests", h.List)
	app.Post("/v1/gateways/:gateway_id/store/requests/approve", h.Approve)
	app.Post("/v1/gateways/:gateway_id/store/requests/deny", h.Deny)
	return app
}

func post(t *testing.T, app *fiber.App, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

func TestRequestsHandler_ListCarriesInstanceID(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	inst := ids.New[ids.InstallationKind]()
	approver := &fakeApprover{pending: []appstore.PendingRequest{{
		GatewayID: gw, InstanceID: inst.String(), PrincipalSub: "ana", Code: "github", Name: "GitHub", RequestedAt: time.Now(),
	}}}
	app := newApp(approver)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/requests", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		Items []struct {
			InstanceID string `json:"instance_id"`
			Code       string `json:"code"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].InstanceID != inst.String() || got.Items[0].Code != "github" {
		t.Fatalf("list must expose instance_id, got %s", body)
	}
}

func TestRequestsHandler_ApprovePassesInstanceID(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	inst := ids.New[ids.InstallationKind]().String()
	approver := &fakeApprover{}
	app := newApp(approver)
	resp := post(t, app, "/v1/gateways/"+gw.String()+"/store/requests/approve",
		`{"principal_sub":"ana","code":"github","instance_id":"`+inst+`"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(approver.approved) != 1 || approver.approved[0].InstanceID != inst || approver.approved[0].Code != "github" || approver.approved[0].GatewayID != gw {
		t.Fatalf("approve must pass instance_id through, got %+v", approver.approved)
	}
}

func TestRequestsHandler_DenyByInstanceIDOnly(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	inst := ids.New[ids.InstallationKind]().String()
	approver := &fakeApprover{}
	app := newApp(approver)
	// Backward compatible body shape: code omitted, instance_id alone identifies it.
	resp := post(t, app, "/v1/gateways/"+gw.String()+"/store/requests/deny",
		`{"principal_sub":"ana","instance_id":"`+inst+`"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(approver.denied) != 1 || approver.denied[0].InstanceID != inst {
		t.Fatalf("deny must pass instance_id through, got %+v", approver.denied)
	}
}

func TestRequestsHandler_DenyByCodeStillAccepted(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	approver := &fakeApprover{}
	app := newApp(approver)
	resp := post(t, app, "/v1/gateways/"+gw.String()+"/store/requests/deny", `{"principal_sub":"ana","code":"github"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(approver.denied) != 1 || approver.denied[0].Code != "github" || approver.denied[0].InstanceID != "" {
		t.Fatalf("code-only deny must still be accepted, got %+v", approver.denied)
	}
}

func TestRequestsHandler_RejectsBodyWithoutCodeOrInstance(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	approver := &fakeApprover{}
	app := newApp(approver)
	resp := post(t, app, "/v1/gateways/"+gw.String()+"/store/requests/approve", `{"principal_sub":"ana"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for a body naming neither code nor instance_id, got %d", resp.StatusCode)
	}
	if len(approver.approved) != 0 {
		t.Fatal("approver must not be called")
	}
}

func TestRequestsHandler_AmbiguousRequestIsConflict(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	approver := &fakeApprover{err: appstore.ErrAmbiguousRequest}
	app := newApp(approver)
	resp := post(t, app, "/v1/gateways/"+gw.String()+"/store/requests/deny", `{"principal_sub":"ana","code":"github"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("an ambiguous by-code decision must be 409, got %d", resp.StatusCode)
	}
}
