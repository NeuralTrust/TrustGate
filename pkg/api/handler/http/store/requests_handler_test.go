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
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	"github.com/gofiber/fiber/v2"
)

type fakeApprover struct {
	pending  []appstore.PendingRequest
	decided  []appstore.DecidedRequest
	approved []appstore.ApproveRequest
	denied   []appstore.DenyRequest
	err      error
}

func (f *fakeApprover) ListDecided(context.Context, ids.GatewayID) ([]appstore.DecidedRequest, error) {
	return f.decided, f.err
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

func TestRequestsHandler_ApprovePassesGrantToGroup(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	approver := &fakeApprover{}
	app := newApp(approver)
	resp := post(t, app, "/v1/gateways/"+gw.String()+"/store/requests/approve",
		`{"principal_sub":"ana","code":"github","grant_to_group":"sales"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(approver.approved) != 1 || approver.approved[0].GrantToGroup != "sales" {
		t.Fatalf("approve must pass grant_to_group through, got %+v", approver.approved)
	}
}

func TestRequestsHandler_HistoryShapesDecisions(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	at := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	approver := &fakeApprover{decided: []appstore.DecidedRequest{
		{InstanceID: "i1", PrincipalSub: "ana", Code: "github", Name: "GitHub", Decision: installationdomain.DecisionApproved, DecidedBy: "admin@corp", DecidedAt: at, RequestedAt: at.Add(-time.Hour)},
		{InstanceID: "i2", PrincipalSub: "bob", Code: "snowflake", Name: "Snowflake", RegistryID: reg, Decision: installationdomain.DecisionDenied, DecidedAt: at},
	}}
	app := newApp(approver)
	app.Get("/v1/gateways/:gateway_id/store/requests/history", storehttp.NewRequestsHandler(approver).History)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/requests/history", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 2 || len(body.Items) != 2 {
		t.Fatalf("body: %+v", body)
	}
	if body.Items[0]["decision"] != "approved" || body.Items[0]["decided_by"] != "admin@corp" || body.Items[0]["decided_at"] != "2026-09-07T12:00:00Z" || body.Items[0]["name"] != "GitHub" {
		t.Fatalf("approved row: %v", body.Items[0])
	}
	if _, has := body.Items[0]["registry_id"]; has {
		t.Fatalf("code-level request must omit registry_id: %v", body.Items[0])
	}
	if body.Items[1]["decision"] != "denied" || body.Items[1]["registry_id"] != reg.String() {
		t.Fatalf("denied row: %v", body.Items[1])
	}

	approver.err = appstore.ErrHistoryUnavailable
	resp2, _ := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/requests/history", nil))
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 without a history store, got %d", resp2.StatusCode)
	}
}

// The Approvals screen has had a Reason column with nothing to fill it. Both
// views carry the requester's words now: the pending queue, where the approver
// decides, and the history, where the decision is read back.
func TestRequestsHandler_CarriesTheRequestersReason(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	const reason = "I need to triage issues on the platform repo"
	approver := &fakeApprover{
		pending: []appstore.PendingRequest{{
			GatewayID: gw, InstanceID: ids.New[ids.InstallationKind]().String(),
			PrincipalSub: "ana", Code: "github", Name: "GitHub",
			Reason: reason, RequestedAt: time.Now(),
		}},
		decided: []appstore.DecidedRequest{{
			GatewayID: gw, InstanceID: ids.New[ids.InstallationKind]().String(),
			PrincipalSub: "ana", Code: "github", Name: "GitHub", Reason: reason,
			Decision: installationdomain.DecisionApproved, DecidedBy: "admin@corp.com",
			DecidedAt: time.Now(), RequestedAt: time.Now(),
		}},
	}
	app := fiber.New()
	h := storehttp.NewRequestsHandler(approver)
	app.Get("/v1/gateways/:gateway_id/store/requests", h.List)
	app.Get("/v1/gateways/:gateway_id/store/requests/history", h.History)

	for _, path := range []string{"/store/requests", "/store/requests/history"} {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+path, nil))
		if err != nil {
			t.Fatalf("app.Test %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var got struct {
			Items []struct {
				Reason string `json:"reason"`
			} `json:"items"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(got.Items) != 1 || got.Items[0].Reason != reason {
			t.Fatalf("%s must carry the reason, got %s", path, body)
		}
	}
}

// A request with no reason must not put an empty string in the column: the
// field is omitted and the console shows its own "none".
func TestRequestsHandler_OmitsAnAbsentReason(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	approver := &fakeApprover{pending: []appstore.PendingRequest{{
		GatewayID: gw, InstanceID: ids.New[ids.InstallationKind]().String(),
		PrincipalSub: "ana", Code: "github", Name: "GitHub", RequestedAt: time.Now(),
	}}}
	app := newApp(approver)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/gateways/"+gw.String()+"/store/requests", nil))
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "reason") {
		t.Fatalf("an absent reason must be omitted, got %s", body)
	}
}
