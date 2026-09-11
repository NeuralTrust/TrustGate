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
	"time"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
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

type fakePrincipalInstaller struct {
	got *appstore.OnBehalfInstallRequest
	res *appstore.InstallResult
	err error
}

func (f *fakePrincipalInstaller) InstallFor(_ context.Context, in appstore.OnBehalfInstallRequest) (*appstore.InstallResult, error) {
	f.got = &in
	return f.res, f.err
}

func newPrincipalApp(p appstore.PrincipalPreview) *fiber.App {
	return newPrincipalAppWith(p, nil)
}

func newPrincipalAppWith(p appstore.PrincipalPreview, installer appstore.PrincipalInstaller) *fiber.App {
	return newPrincipalAppFor(p, installer, nil, "")
}

// newPrincipalAppFor stands the handler up with a connect linker and stamps
// caller as the authenticated subject, the way the admin auth middleware does.
func newPrincipalAppFor(
	p appstore.PrincipalPreview,
	installer appstore.PrincipalInstaller,
	linker appstore.PrincipalConnectLinker,
	caller string,
) *fiber.App {
	app := fiber.New()
	if caller != "" {
		app.Use(func(c *fiber.Ctx) error {
			c.Locals(string(infracontext.UserIDContextKey), caller)
			return c.Next()
		})
	}
	h := storehttp.NewPrincipalHandler(p, installer, linker)
	app.Get("/v1/gateways/:gateway_id/store/principal", h.Get)
	app.Post("/v1/gateways/:gateway_id/store/principal/installs", h.Install)
	app.Post("/v1/gateways/:gateway_id/store/principal/connect-link", h.ConnectLink)
	return app
}

type fakeConnectLinker struct {
	got *appstore.PrincipalConnectRequest
	res *appstore.PrincipalConnectLink
	err error
}

func (f *fakeConnectLinker) LinkFor(
	_ context.Context,
	in appstore.PrincipalConnectRequest,
) (*appstore.PrincipalConnectLink, error) {
	f.got = &in
	return f.res, f.err
}

func postJSON(t *testing.T, app *fiber.App, path, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

func TestPrincipalHandler_Install_RunsAsThePrincipal(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	installer := &fakePrincipalInstaller{res: &appstore.InstallResult{
		Code: "github", Name: "GitHub", Status: installationdomain.StatusPendingApproval, InstanceID: "inst-1", Pending: true,
	}}
	app := newPrincipalAppWith(&fakePreview{}, installer)
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs",
		`{"principal_sub":"ana","code":"github","groups":["eng"],"instance_id":"`+reg.String()+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if installer.got == nil || installer.got.PrincipalSub != "ana" || installer.got.Code != "github" || installer.got.RegistryID != reg || len(installer.got.Groups) != 1 {
		t.Fatalf("request not forwarded: %+v", installer.got)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["pending"] != true || body["status"] != "pending_approval" || body["instance_id"] != "inst-1" || body["name"] != "GitHub" {
		t.Fatalf("body: %v", body)
	}
}

func TestPrincipalHandler_Install_ShapesInstanceChoicesAndErrors(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	installer := &fakePrincipalInstaller{res: &appstore.InstallResult{
		Code: "snowflake", Name: "Snowflake", RequiresInstanceChoice: true,
		InstanceChoices: []appstore.InstanceChoice{{RegistryID: reg, Name: "Snowflake (finance)"}},
	}}
	app := newPrincipalAppWith(&fakePreview{}, installer)
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs", `{"principal_sub":"ana","code":"snowflake"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	choices := body["instance_choices"].([]any)
	if body["requires_instance_choice"] != true || len(choices) != 1 || choices[0].(map[string]any)["registry_id"] != reg.String() {
		t.Fatalf("body: %v", body)
	}

	// Validation: missing code, bad instance id.
	if resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs", `{"principal_sub":"ana"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422 without code, got %d", resp.StatusCode)
	}
	if resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs", `{"principal_sub":"ana","code":"x","instance_id":"nope"}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422 for a bad instance id, got %d", resp.StatusCode)
	}
	// A closed Store (level None) is a conflict, not a server error.
	installer.err = appstore.ErrStoreClosed
	if resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs", `{"principal_sub":"ana","code":"x"}`); resp.StatusCode != http.StatusConflict {
		t.Fatalf("want 409 for a closed store, got %d", resp.StatusCode)
	}
	// No installer wired on this plane.
	if resp := postJSON(t, newPrincipalApp(&fakePreview{}), "/v1/gateways/"+gw.String()+"/store/principal/installs", `{"principal_sub":"ana","code":"x"}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 without an installer, got %d", resp.StatusCode)
	}
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

// The Portal collects the reason when the user asks for a server, so the
// endpoint carries it through to the installer, trimmed.
func TestPrincipalHandler_Install_ForwardsTheReason(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installer := &fakePrincipalInstaller{res: &appstore.InstallResult{
		Code: "github", Name: "GitHub", Status: installationdomain.StatusPendingApproval, Pending: true,
	}}
	app := newPrincipalAppWith(&fakePreview{}, installer)

	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs",
		`{"principal_sub":"ana","code":"github","reason":"  triaging platform issues  "}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if installer.got == nil || installer.got.Reason != "triaging platform issues" {
		t.Fatalf("reason not forwarded: %+v", installer.got)
	}
}

// Refused rather than truncated: a justification the approver reads must be
// what the requester wrote, so an over-long one is the caller's to shorten.
func TestPrincipalHandler_Install_RefusesAnOverlongReason(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installer := &fakePrincipalInstaller{res: &appstore.InstallResult{Code: "github"}}
	app := newPrincipalAppWith(&fakePreview{}, installer)

	long := strings.Repeat("x", installationdomain.MaxReasonLength+1)
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs",
		`{"principal_sub":"ana","code":"github","reason":"`+long+`"}`)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", resp.StatusCode)
	}
	if installer.got != nil {
		t.Fatal("the install must not run when the request is refused")
	}
}

func TestPrincipalHandler_ConnectLink_MintsForTheCaller(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	linker := &fakeConnectLinker{res: &appstore.PrincipalConnectLink{Ticket: "tkt-1", ConsumerPath: "/store/mcp"}}
	app := newPrincipalAppFor(&fakePreview{}, nil, linker, "ana")
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/connect-link",
		`{"principal_sub":"ana","code":"com.ahrefs/mcp","instance_id":"`+reg.String()+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if linker.got == nil || linker.got.PrincipalSub != "ana" || linker.got.Code != "com.ahrefs/mcp" ||
		linker.got.RegistryID != reg || linker.got.GatewayID != gw {
		t.Fatalf("request not forwarded: %+v", linker.got)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["ticket"] != "tkt-1" || body["consumer_path"] != "/store/mcp" || body["connect_path"] != "/store/mcp/connect" {
		t.Fatalf("body: %v", body)
	}
	expiry, ok := body["expires_at"].(string)
	if !ok || expiry == "" {
		t.Fatalf("expires_at missing: %v", body)
	}
	at, err := time.Parse(time.RFC3339, expiry)
	if err != nil {
		t.Fatalf("expires_at not a timestamp: %v", err)
	}
	if at.Before(time.Now().UTC()) {
		t.Fatalf("expires_at already past: %v", at)
	}
}

// A connect ticket completes OAuth as its principal, so it is the caller's own
// link or nothing — an admin previewing someone's Portal cannot ask for theirs.
func TestPrincipalHandler_ConnectLink_RefusesAnotherPrincipal(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	linker := &fakeConnectLinker{res: &appstore.PrincipalConnectLink{Ticket: "tkt-1", ConsumerPath: "/store/mcp"}}
	app := newPrincipalAppFor(&fakePreview{}, nil, linker, "admin")
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/connect-link",
		`{"principal_sub":"ana","code":"com.ahrefs/mcp"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if linker.got != nil {
		t.Fatalf("linker was called: %+v", linker.got)
	}
}

// No authenticated subject at all is the same refusal: nothing identifies the
// caller as the principal the ticket would speak for.
func TestPrincipalHandler_ConnectLink_RefusesAnUnidentifiedCaller(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	linker := &fakeConnectLinker{res: &appstore.PrincipalConnectLink{Ticket: "tkt-1", ConsumerPath: "/store/mcp"}}
	app := newPrincipalAppFor(&fakePreview{}, nil, linker, "")
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/connect-link",
		`{"principal_sub":"ana","code":"com.ahrefs/mcp"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	if linker.got != nil {
		t.Fatalf("linker was called: %+v", linker.got)
	}
}

func TestPrincipalHandler_ConnectLink_UnavailableWithoutALinker(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	app := newPrincipalAppFor(&fakePreview{}, nil, nil, "ana")
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/connect-link",
		`{"principal_sub":"ana","code":"com.ahrefs/mcp"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestPrincipalHandler_ConnectLink_ValidatesTheBody(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	linker := &fakeConnectLinker{res: &appstore.PrincipalConnectLink{Ticket: "tkt-1", ConsumerPath: "/store/mcp"}}
	app := newPrincipalAppFor(&fakePreview{}, nil, linker, "ana")
	for name, body := range map[string]string{
		"no principal": `{"code":"com.ahrefs/mcp"}`,
		"no code":      `{"principal_sub":"ana"}`,
		"bad instance": `{"principal_sub":"ana","code":"com.ahrefs/mcp","instance_id":"nope"}`,
	} {
		resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/connect-link", body)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s: want 422, got %d", name, resp.StatusCode)
		}
	}
	if linker.got != nil {
		t.Fatalf("linker was called: %+v", linker.got)
	}
}

// A Portal whose view of the access level was stale asks for an install of a
// server that is really a request. That is not an error it can only report: it
// comes back as the one thing missing, so the Portal can ask the user why.
func TestPrincipalHandler_Install_AsksForAReasonInsteadOfFailing(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	installer := &fakePrincipalInstaller{err: appstore.ErrReasonRequired}
	app := newPrincipalAppWith(&fakePreview{}, installer)
	resp := postJSON(t, app, "/v1/gateways/"+gw.String()+"/store/principal/installs",
		`{"principal_sub":"ana","code":"com.airbyte/mcp"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["requires_reason"] != true || body["code"] != "com.airbyte/mcp" || body["pending"] != false {
		t.Fatalf("body: %v", body)
	}
}
