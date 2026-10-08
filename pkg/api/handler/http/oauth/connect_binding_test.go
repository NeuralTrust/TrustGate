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

package oauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

func endUserPage() *appoauth.ConnectPage {
	return &appoauth.ConnectPage{
		ConsumerPath: "/support/mcp",
		Principal: appoauth.ConnectPrincipal{
			Subject:     "app:consumer-1:user-42",
			Application: "Support Assistant",
			EndUser:     "user-42",
		},
		Providers: []appoauth.ProviderStatus{
			{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-prod", Instance: "inst-prod"},
			{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-dev", Instance: "inst-dev"},
		},
	}
}

func connectFlowApp(h *ConnectHandler) *fiber.App {
	app := fiber.New()
	app.Get(ConnectFinishPath, h.Finish)
	app.Post(ConnectStartPath, h.Start)
	app.Get(ConnectStartPath, h.Confirm)
	app.Get(ConnectCallbackPath, h.Callback)
	app.Get("/+/connect", h.Page)
	return app
}

func send(t *testing.T, app *fiber.App, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(body)
}

func flowCookie(res *http.Response, name string) *http.Cookie {
	for _, cookie := range res.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func plainCookieName(state string) string {
	return connectCookiePlainPrefix + connectBinding(state)[:8]
}

func finishRequest(cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(fiber.MethodGet, ConnectFinishPath+"?f=fin", nil)
	req.Host = "localhost"
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return req
}

func TestConnectConfirm_NamesWhoTheAccountIsLinkedToAndAsksForAPost(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{page: endUserPage()}
	app := connectFlowApp(newTestConnectHandler(stub, nil, ""))

	res, body := send(t, app, httptest.NewRequest(fiber.MethodGet, "/oauth/connect/app.linear%2Fmcp?ticket=abc&instance=inst-dev", nil))
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200: %s", res.StatusCode, body)
	}
	for _, want := range []string{
		"user-42",
		"end-user id named by Support Assistant",
		"/support/mcp",
		"linear-dev",
		`method="post"`,
		`action="/oauth/connect/app.linear/mcp?instance=inst-dev&amp;ticket=abc"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("confirmation page is missing %q: %s", want, body)
		}
	}
	if stub.gotProvider != "" {
		t.Fatal("opening the link must not start the connection")
	}
	if len(res.Cookies()) != 0 {
		t.Fatal("the confirmation must not set a cookie")
	}
}

func TestConnectConfirm_ShowsTheAccountItReplaces(t *testing.T) {
	t.Parallel()
	page := endUserPage()
	page.Providers[0].Linked = true
	page.Providers[0].AccountRef = "someone@example.com"
	app := connectFlowApp(newTestConnectHandler(&stubConnectService{page: page}, nil, ""))

	_, body := send(t, app, httptest.NewRequest(fiber.MethodGet, "/oauth/connect/app.linear/mcp?ticket=abc&instance=inst-prod", nil))
	if !strings.Contains(body, "someone@example.com") || !strings.Contains(body, "Continuing replaces it") {
		t.Fatalf("confirmation does not say which account it replaces: %s", body)
	}
}

func TestConnectConfirm_RefusesWhatTheTicketCannotConnect(t *testing.T) {
	t.Parallel()
	shared := endUserPage()
	shared.Providers = []appoauth.ProviderStatus{{Provider: "app.linear/mcp", Instance: "inst-prod", Shared: true}}
	cases := []struct {
		name   string
		stub   *stubConnectService
		target string
		want   int
	}{
		{"missing ticket", &stubConnectService{page: endUserPage()}, "/oauth/connect/app.linear/mcp", fiber.StatusUnauthorized},
		{"expired ticket", &stubConnectService{err: appoauth.ErrTicketNotFound}, "/oauth/connect/app.linear/mcp?ticket=x", fiber.StatusUnauthorized},
		{"provider not on the page", &stubConnectService{page: endUserPage()}, "/oauth/connect/github?ticket=abc", fiber.StatusNotFound},
		{"one account for everyone", &stubConnectService{page: shared}, "/oauth/connect/app.linear/mcp?ticket=abc", fiber.StatusConflict},
	}
	for _, tc := range cases {
		app := connectFlowApp(newTestConnectHandler(tc.stub, nil, ""))
		res, _ := send(t, app, httptest.NewRequest(fiber.MethodGet, tc.target, nil))
		if res.StatusCode != tc.want {
			t.Fatalf("%s: status = %d, want %d", tc.name, res.StatusCode, tc.want)
		}
	}
}

func TestConnectConfirm_FallsBackToTheTicketInstanceThenTheFirstRow(t *testing.T) {
	t.Parallel()
	page := endUserPage()
	page.Instance = "inst-dev"
	if row, ok := confirmRow(page, "app.linear/mcp", ""); !ok || row.Instance != "inst-dev" {
		t.Fatalf("row = %+v, want the ticket's instance", row)
	}
	if row, ok := confirmRow(page, "app.linear/mcp", "gone"); !ok || row.Instance != "inst-dev" {
		t.Fatalf("row = %+v, want the ticket's instance for an unknown one", row)
	}
	page.Instance = ""
	if row, ok := confirmRow(page, "app.linear/mcp", ""); !ok || row.Instance != "inst-prod" {
		t.Fatalf("row = %+v, want the first row", row)
	}
}

func TestConnectPages_ShowWhoAccountsAreLinkedTo(t *testing.T) {
	t.Parallel()
	grid := endUserPage()
	single := endUserPage()
	single.Code = "app.linear/mcp"
	single.Instance = "inst-prod"
	for name, page := range map[string]*appoauth.ConnectPage{"grid": grid, "single server": single} {
		h := newTestConnectHandler(&stubConnectService{page: page}, nil, "")
		h.holdFor = 0
		_, body := send(t, connectFlowApp(h), httptest.NewRequest(fiber.MethodGet, "/support/mcp/connect?ticket=abc", nil))
		if !strings.Contains(body, "user-42") || !strings.Contains(body, "end-user id named by Support Assistant") {
			t.Fatalf("%s page does not say who accounts are linked to: %s", name, body)
		}
	}
}

func TestConnectStart_OnlyFromAPageOfThisGateway(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		site   string
		origin string
		want   int
	}{
		{"same-origin fetch metadata", "same-origin", "", fiber.StatusFound},
		{"same-origin fetch metadata, any Origin", "same-origin", "null", fiber.StatusFound},
		{"no fetch metadata, own Origin", "", "http://localhost", fiber.StatusFound},
		{"no fetch metadata, own Origin in other case", "", "HTTP://LOCALHOST", fiber.StatusFound},
		{"no fetch metadata, no Origin", "", "", fiber.StatusForbidden},
		{"no fetch metadata, opaque Origin", "", "null", fiber.StatusForbidden},
		{"no fetch metadata, other Origin", "", "https://elsewhere.example", fiber.StatusForbidden},
		{"same-site", "same-site", "http://localhost", fiber.StatusForbidden},
		{"cross-site", "cross-site", "", fiber.StatusForbidden},
		{"typed or opened from outside", "none", "", fiber.StatusForbidden},
	} {
		stub := &stubConnectService{}
		app := connectFlowApp(newTestConnectHandler(stub, nil, ""))
		req := httptest.NewRequest(fiber.MethodPost, "/oauth/connect/github?ticket=abc", nil)
		req.Host = "localhost"
		if tc.site != "" {
			req.Header.Set(headerSecFetchSite, tc.site)
		}
		if tc.origin != "" {
			req.Header.Set(fiber.HeaderOrigin, tc.origin)
		}
		res, _ := send(t, app, req)
		if res.StatusCode != tc.want {
			t.Fatalf("%s: status = %d, want %d", tc.name, res.StatusCode, tc.want)
		}
		if started := stub.gotProvider != ""; started != (tc.want == fiber.StatusFound) {
			t.Fatalf("%s: started = %v", tc.name, started)
		}
	}
}

func TestConnectStart_SetsTheFlowCookieOnTheStartHostAndGoesToTheProvider(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	app := connectFlowApp(newTestConnectHandler(stub, nil, "https://callback.mcp.example.com"))
	req := ownPagePost("/oauth/connect/github?ticket=abc")
	req.Host = "tenant.mcp.example.com"
	req.Header.Set(fiber.HeaderXForwardedProto, "https")

	res, _ := send(t, app, req)
	if res.StatusCode != fiber.StatusFound || res.Header.Get(fiber.HeaderLocation) != "https://github.com/login/oauth/authorize?x=1" {
		t.Fatalf("status = %d, Location = %q, want 302 to the provider", res.StatusCode, res.Header.Get(fiber.HeaderLocation))
	}
	if stub.gotOrigin != "https://tenant.mcp.example.com" || stub.gotBaseURL != "https://callback.mcp.example.com" {
		t.Fatalf("start origin = %q, callback base = %q", stub.gotOrigin, stub.gotBaseURL)
	}
	name := connectCookieSecurePrefix + connectBinding("the-state")[:8]
	cookie := flowCookie(res, name)
	if cookie == nil {
		t.Fatalf("start did not set %s: %v", name, res.Header.Values(fiber.HeaderSetCookie))
	}
	if cookie.Value != connectBinding("the-state") || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 600 {
		t.Fatalf("cookie = %+v", cookie)
	}
}

func TestConnectStart_UsesThePlainCookieOverHTTP(t *testing.T) {
	t.Parallel()
	app := connectFlowApp(newTestConnectHandler(&stubConnectService{}, nil, ""))
	res, _ := send(t, app, ownPagePost("/oauth/connect/github?ticket=abc"))
	cookie := flowCookie(res, plainCookieName("the-state"))
	if cookie == nil || cookie.Secure || cookie.Value != connectBinding("the-state") {
		t.Fatalf("cookie over http = %+v, want the plain, non-Secure one", cookie)
	}
}

func TestConnectStart_RefusesAnAddressTheGatewayIsNotServedOn(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{startErr: appoauth.ErrStartOriginNotServed}
	app := connectFlowApp(newTestConnectHandler(stub, nil, "https://callback.example.com"))
	req := ownPagePost("/oauth/connect/github?ticket=abc")
	req.Host = "elsewhere.example"
	req.Header.Set(fiber.HeaderXForwardedProto, "https")
	res, body := send(t, app, req)
	if res.StatusCode != fiber.StatusBadRequest || !strings.Contains(body, "cannot be started from this address") {
		t.Fatalf("status = %d body = %s, want 400", res.StatusCode, body)
	}
	if stub.gotOrigin != "https://elsewhere.example" {
		t.Fatalf("start origin passed to the service = %q", stub.gotOrigin)
	}
	if len(res.Cookies()) != 0 || res.Header.Get(fiber.HeaderLocation) != "" {
		t.Fatal("a refused start must neither set a cookie nor redirect")
	}
}

func TestConnectCallback_HandsTheResultToTheStartOriginWithoutCompletingIt(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	app := connectFlowApp(newTestConnectHandler(stub, nil, ""))

	res, _ := send(t, app, httptest.NewRequest(fiber.MethodGet, "/oauth/callback/github?state=the-state&code=c", nil))
	if res.StatusCode != fiber.StatusFound || res.Header.Get(fiber.HeaderLocation) != "https://start.example/oauth/connect/finish?f=fin" {
		t.Fatalf("status = %d, Location = %q, want 302 to finish", res.StatusCode, res.Header.Get(fiber.HeaderLocation))
	}
	if stub.callbacks != 0 {
		t.Fatal("the callback must not complete the connection")
	}
	if len(res.Cookies()) != 0 {
		t.Fatal("the callback must not touch cookies")
	}

	unknown, _ := send(t, app, httptest.NewRequest(fiber.MethodGet, "/oauth/callback/github?state=nope&code=c", nil))
	if unknown.StatusCode < 400 || unknown.Header.Get(fiber.HeaderLocation) != "" {
		t.Fatalf("unknown state: status = %d, want an error page", unknown.StatusCode)
	}
}

func TestConnectFinish_CompletesOnlyInTheBrowserThatStarted(t *testing.T) {
	t.Parallel()
	page := &appoauth.ConnectPage{
		ConsumerPath: "/tools/mcp",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "g", Linked: true}},
	}
	for name, cookies := range map[string][]*http.Cookie{
		"no cookie":              nil,
		"cookie of another flow": {{Name: plainCookieName("another-state"), Value: connectBinding("another-state")}},
		"wrong value":            {{Name: plainCookieName("the-state"), Value: connectBinding("another-state")}},
		"state as the value":     {{Name: plainCookieName("the-state"), Value: "the-state"}},
	} {
		stub := &stubConnectService{page: page}
		app := connectFlowApp(newTestConnectHandler(stub, nil, ""))
		if _, err := stub.ReceiveCallback(t.Context(), "github", "the-state", "c", "", ""); err != nil {
			t.Fatalf("ReceiveCallback: %v", err)
		}
		res, body := send(t, app, finishRequest(cookies...))
		if res.StatusCode != fiber.StatusBadRequest || !strings.Contains(body, "started in another browser") {
			t.Fatalf("%s: status = %d body = %s, want 400", name, res.StatusCode, body)
		}
		if stub.callbacks != 0 {
			t.Fatalf("%s: the authorization was used", name)
		}
		if len(res.Cookies()) != 0 {
			t.Fatalf("%s: a refused finish must not clear cookies", name)
		}
	}

	stub := &stubConnectService{page: page}
	app := connectFlowApp(newTestConnectHandler(stub, nil, ""))
	if _, err := stub.ReceiveCallback(t.Context(), "github", "the-state", "the-code", "", ""); err != nil {
		t.Fatalf("ReceiveCallback: %v", err)
	}
	other := &http.Cookie{Name: plainCookieName("another-state"), Value: connectBinding("another-state")}
	own := &http.Cookie{Name: plainCookieName("the-state"), Value: connectBinding("the-state")}
	res, body := send(t, app, finishRequest(other, own))
	if res.StatusCode != fiber.StatusOK || stub.callbacks != 1 {
		t.Fatalf("status = %d callbacks = %d, want the connection completed: %s", res.StatusCode, stub.callbacks, body)
	}
	if got := strings.Join(stub.callbackArg, ","); got != "github,the-state,the-code," {
		t.Fatalf("callback args = %q", got)
	}
	cleared := flowCookie(res, own.Name)
	if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("finish must clear its own cookie, got %+v", cleared)
	}
	if flowCookie(res, other.Name) != nil {
		t.Fatal("finish must leave another flow's cookie alone")
	}

	again, body := send(t, app, finishRequest(own))
	if again.StatusCode != fiber.StatusBadRequest || !strings.Contains(body, "already used or has expired") || stub.callbacks != 1 {
		t.Fatalf("second use: status = %d, want 400 and no second completion", again.StatusCode)
	}
}

func TestConnectFlow_SameHostEndToEnd(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/tools/mcp",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "g", Linked: true}},
	}}
	app := connectFlowApp(newTestConnectHandler(stub, nil, ""))

	started, _ := send(t, app, ownPagePost("/oauth/connect/github?ticket=abc"))
	cookie := flowCookie(started, plainCookieName("the-state"))
	if started.StatusCode != fiber.StatusFound || cookie == nil {
		t.Fatalf("start: status = %d cookie = %+v", started.StatusCode, cookie)
	}
	if stub.gotOrigin != "http://localhost" || stub.gotBaseURL != "http://localhost" {
		t.Fatalf("same host: start origin = %q, callback base = %q", stub.gotOrigin, stub.gotBaseURL)
	}
	callback, _ := send(t, app, httptest.NewRequest(fiber.MethodGet, "/oauth/callback/github?state=the-state&code=c", nil))
	if callback.StatusCode != fiber.StatusFound {
		t.Fatalf("callback: status = %d", callback.StatusCode)
	}
	finished, body := send(t, app, finishRequest(cookie))
	if finished.StatusCode != fiber.StatusOK || stub.callbacks != 1 {
		t.Fatalf("finish: status = %d callbacks = %d: %s", finished.StatusCode, stub.callbacks, body)
	}
}

func TestConnectCookie_FormFollowsTheSignInCookies(t *testing.T) {
	t.Parallel()
	secureName := connectCookieSecurePrefix + connectBinding("the-state")[:8]
	cases := []struct {
		name     string
		callback string
		host     string
		cookies  FlowCookies
		https    bool
		secure   bool
	}{
		{"https request", "https://callback.mcp.example", "tenant.mcp.example", FlowCookies{}, true, true},
		{"scheme lost at the proxy", "https://callback.mcp.example", "callback.mcp.example", FlowCookies{}, false, true},
		{"no callback origin set, non-loopback", "", "mcp.internal.corp:8083", FlowCookies{}, false, true},
		{"loopback", "", "localhost:8083", FlowCookies{}, false, false},
		{"plain cookies allowed", "", "mcp.internal.corp:8083", FlowCookies{AllowInsecure: true}, false, false},
		{"plane configured on plain http", "http://mcp.internal.corp:8083", "mcp.internal.corp:8083", FlowCookies{}, false, false},
	}
	for _, tc := range cases {
		stub := &stubConnectService{page: &appoauth.ConnectPage{ConsumerPath: "/tools/mcp"}}
		app := connectFlowApp(NewConnectHandler(stub, stub, nil, tc.callback, tc.cookies))
		start := ownPagePost("/oauth/connect/github?ticket=abc")
		start.Host = tc.host
		if tc.https {
			start.Header.Set(fiber.HeaderXForwardedProto, "https")
		}
		res, body := send(t, app, start)
		if res.StatusCode != fiber.StatusFound {
			t.Fatalf("%s: start status = %d body = %s", tc.name, res.StatusCode, body)
		}
		name := plainCookieName("the-state")
		if tc.secure {
			name = secureName
		}
		cookie := flowCookie(res, name)
		if cookie == nil || cookie.Secure != tc.secure {
			t.Fatalf("%s: cookie = %+v, want %s with Secure=%v", tc.name, cookie, name, tc.secure)
		}

		if _, err := stub.ReceiveCallback(t.Context(), "github", "the-state", "c", "", ""); err != nil {
			t.Fatalf("ReceiveCallback: %v", err)
		}
		finish := finishRequest(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		finish.Host = tc.host
		if tc.https {
			finish.Header.Set(fiber.HeaderXForwardedProto, "https")
		}
		res, body = send(t, app, finish)
		if res.StatusCode != fiber.StatusOK || stub.callbacks != 1 {
			t.Fatalf("%s: finish status = %d callbacks = %d body = %s", tc.name, res.StatusCode, stub.callbacks, body)
		}
	}
}

// Behind a proxy that ends TLS without forwarding the scheme, every request
// reads as http while the callback origin is https on the same host. The
// pages must render there rather than redirect to themselves, and the flow
// must start and finish.
func TestConnectFlow_BehindAProxyThatDropsTheScheme(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{page: endUserPage(), originErr: appoauth.ErrStartOriginNotServed}
	h := newTestConnectHandler(stub, nil, "https://gateway-mcp.example.com")
	h.holdFor = 0
	app := connectFlowApp(h)

	for _, target := range []string{"/support/mcp/connect?ticket=abc", "/oauth/connect/app.linear/mcp?ticket=abc"} {
		req := httptest.NewRequest(fiber.MethodGet, target, nil)
		req.Host = "gateway-mcp.example.com"
		res, body := send(t, app, req)
		if res.StatusCode != fiber.StatusOK || !strings.Contains(body, "user-42") {
			t.Fatalf("%s: status = %d Location = %q, want the page itself", target, res.StatusCode, res.Header.Get(fiber.HeaderLocation))
		}
	}

	start := httptest.NewRequest(fiber.MethodPost, "/oauth/connect/app.linear/mcp?ticket=abc", nil)
	start.Host = "gateway-mcp.example.com"
	start.Header.Set(fiber.HeaderOrigin, "https://gateway-mcp.example.com")
	res, body := send(t, app, start)
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("start: status = %d body = %s", res.StatusCode, body)
	}
	cookie := flowCookie(res, connectCookieSecurePrefix+connectBinding("the-state")[:8])
	if cookie == nil || !cookie.Secure {
		t.Fatalf("start: cookie = %+v, want the __Host- form", cookie)
	}

	if _, err := stub.ReceiveCallback(t.Context(), "app.linear/mcp", "the-state", "c", "", ""); err != nil {
		t.Fatalf("ReceiveCallback: %v", err)
	}
	finish := finishRequest(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	finish.Host = "gateway-mcp.example.com"
	res, body = send(t, app, finish)
	if res.StatusCode != fiber.StatusOK || stub.callbacks != 1 {
		t.Fatalf("finish: status = %d callbacks = %d body = %s", res.StatusCode, stub.callbacks, body)
	}
}

func TestConnectPages_UseASameOriginReferrerPolicy(t *testing.T) {
	t.Parallel()
	single := endUserPage()
	single.Code = "app.linear/mcp"
	for name, page := range map[string]*appoauth.ConnectPage{"grid": endUserPage(), "single server": single} {
		stub := &stubConnectService{page: page}
		h := newTestConnectHandler(stub, nil, "")
		h.holdFor = 0
		app := connectFlowApp(h)
		requests := map[string]*http.Request{
			"page":         httptest.NewRequest(fiber.MethodGet, "/support/mcp/connect?ticket=abc", nil),
			"confirmation": httptest.NewRequest(fiber.MethodGet, "/oauth/connect/app.linear/mcp?ticket=abc", nil),
		}
		if _, err := stub.ReceiveCallback(t.Context(), "app.linear/mcp", "the-state", "c", "", ""); err != nil {
			t.Fatalf("ReceiveCallback: %v", err)
		}
		requests["finish"] = finishRequest(&http.Cookie{Name: plainCookieName("the-state"), Value: connectBinding("the-state")})
		for kind, req := range requests {
			res, _ := send(t, app, req)
			if res.StatusCode != fiber.StatusOK || res.Header.Get(fiber.HeaderReferrerPolicy) != "same-origin" {
				t.Fatalf("%s %s: status = %d Referrer-Policy = %q, want same-origin",
					name, kind, res.StatusCode, res.Header.Get(fiber.HeaderReferrerPolicy))
			}
		}
	}
}

// An authorization started by the previous version carries no start origin;
// its callback completes on the callback itself, as it did then.
func TestConnectCallback_CompletesAnAuthorizationWithoutAStartOrigin(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{direct: true, page: &appoauth.ConnectPage{
		ConsumerPath: "/tools/mcp",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "g", Linked: true}},
	}}
	app := connectFlowApp(newTestConnectHandler(stub, nil, ""))
	res, body := send(t, app, httptest.NewRequest(fiber.MethodGet, "/oauth/callback/github?state=the-state&code=c", nil))
	if res.StatusCode != fiber.StatusOK || stub.callbacks != 1 {
		t.Fatalf("status = %d callbacks = %d body = %s, want the connection completed", res.StatusCode, stub.callbacks, body)
	}
	if got := strings.Join(stub.callbackArg, ","); got != "github,the-state,c," {
		t.Fatalf("callback args = %q", got)
	}
}

func TestConnectPages_OnAHostConnectionsAreNotStartedFromMoveToTheCallbackOrigin(t *testing.T) {
	t.Parallel()
	for _, target := range []string{
		"/support/mcp/connect?ticket=abc",
		"/oauth/connect/app.linear/mcp?ticket=abc&instance=inst-dev",
	} {
		stub := &stubConnectService{page: endUserPage(), originErr: appoauth.ErrStartOriginNotServed}
		h := newTestConnectHandler(stub, nil, "https://callback.mcp.example.com")
		h.holdFor = 0
		req := httptest.NewRequest(fiber.MethodGet, target, nil)
		req.Host = "mcp.acme-corp.com"
		req.Header.Set(fiber.HeaderXForwardedProto, "https")
		res, _ := send(t, connectFlowApp(h), req)
		if res.StatusCode != fiber.StatusFound || res.Header.Get(fiber.HeaderLocation) != "https://callback.mcp.example.com"+target {
			t.Fatalf("%s: status = %d, Location = %q, want the same page on the callback origin",
				target, res.StatusCode, res.Header.Get(fiber.HeaderLocation))
		}

		served := &stubConnectService{page: endUserPage()}
		h = newTestConnectHandler(served, nil, "https://callback.mcp.example.com")
		h.holdFor = 0
		for _, host := range []string{"acme.mcp.example.com", "callback.mcp.example.com"} {
			req = httptest.NewRequest(fiber.MethodGet, target, nil)
			req.Host = host
			req.Header.Set(fiber.HeaderXForwardedProto, "https")
			res, body := send(t, connectFlowApp(h), req)
			if res.StatusCode != fiber.StatusOK || !strings.Contains(body, "user-42") {
				t.Fatalf("%s on %s: status = %d, want the page itself", target, host, res.StatusCode)
			}
		}
	}

	expired := &stubConnectService{originErr: appoauth.ErrTicketNotFound}
	req := httptest.NewRequest(fiber.MethodGet, "/support/mcp/connect?ticket=abc", nil)
	req.Host = "mcp.acme-corp.com"
	req.Header.Set(fiber.HeaderXForwardedProto, "https")
	res, _ := send(t, connectFlowApp(newTestConnectHandler(expired, nil, "https://callback.mcp.example.com")), req)
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("expired ticket on another host: status = %d, want 401", res.StatusCode)
	}
}
