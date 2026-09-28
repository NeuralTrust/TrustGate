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
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/gofiber/fiber/v2"
)

type stubConnectService struct {
	page        *appoauth.ConnectPage
	err         error
	gotProvider string
	gotInstance string
	gotBaseURL  string
	startErr    error
	callbackErr error
}

func (s *stubConnectService) CreateTicket(context.Context, ids.GatewayID, string, string) (string, error) {
	return "t", nil
}

func (s *stubConnectService) CreateServerTicket(context.Context, ids.GatewayID, string, string, string, string) (string, error) {
	return "t", nil
}

func (s *stubConnectService) CreateAppTicket(
	context.Context,
	ids.GatewayID,
	string,
	string,
	ids.ConsumerID,
	ids.AuthID,
	[]string,
	string,
) (string, error) {
	return "t", nil
}

func (s *stubConnectService) Page(context.Context, string) (*appoauth.ConnectPage, error) {
	return s.page, s.err
}

func (s *stubConnectService) Statuses(context.Context, ids.GatewayID, string, string) ([]appoauth.ProviderStatus, error) {
	return nil, nil
}

func (s *stubConnectService) Start(_ context.Context, baseURL, _, provider, instanceID string) (string, error) {
	s.gotBaseURL = baseURL
	s.gotProvider = provider
	s.gotInstance = instanceID
	if s.startErr != nil {
		return "", s.startErr
	}
	return "https://github.com/login/oauth/authorize?x=1", nil
}

func (s *stubConnectService) Callback(_ context.Context, baseURL, _, _, _, _, _ string) (string, error) {
	s.gotBaseURL = baseURL
	return "t", s.callbackErr
}

func (s *stubConnectService) Disconnect(context.Context, string, string, string) error { return nil }

func (s *stubConnectService) RefreshAuth(context.Context, ids.GatewayID, *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	return nil, nil
}

func (s *stubConnectService) ChainURL(context.Context, string, ids.GatewayID, string, string, string) (string, error) {
	return "", nil
}

func TestConnectPage_RouteMatchesNestedConsumerPaths(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/v1/mcp/dev",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "github-mcp"}},
	}}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)

	res, err := app.Test(httptest.NewRequest("GET", "/v1/mcp/dev/connect?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "github") || !strings.Contains(string(body), "/oauth/connect/github?ticket=abc") {
		t.Fatalf("page body missing provider button: %s", body)
	}
}

func TestConnectPage_ScopedToOneServerRendersSingleCard(t *testing.T) {
	t.Parallel()
	// A ticket scoped to a catalog code (Code set) renders the focused
	// single-server connect page, not the full provider grid.
	h := NewConnectHandler(&stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/dev",
		Code:         "com.notion/mcp",
		Providers: []appoauth.ProviderStatus{
			{Provider: "com.notion/mcp", Code: "com.notion/mcp", Registry: "Notion"},
			{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "Linear"},
		},
	}}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)

	res, err := app.Test(httptest.NewRequest("GET", "/dev/connect?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	s := string(body)
	// Focused on Notion, with its connect button, and NOT showing Linear.
	if !strings.Contains(s, "Connect your") || !strings.Contains(s, "/oauth/connect/com.notion/mcp?ticket=abc") {
		t.Fatalf("single-server page missing focused connect button: %s", s)
	}
	if strings.Contains(s, "Linear") {
		t.Fatalf("single-server page must not list other providers: %s", s)
	}
}

func TestConnectPage_MissingTicketIs401(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)
	res, err := app.Test(httptest.NewRequest("GET", "/v1/mcp/dev/connect", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}

func TestConnectPage_ExpiredTicketIs401(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{err: appoauth.ErrTicketNotFound}, nil, "")
	app := fiber.New()
	app.Get("/+/connect", h.Page)
	res, err := app.Test(httptest.NewRequest("GET", "/x/connect?ticket=stale", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
}

func TestConnectStart_RedirectsToProvider(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&stubConnectService{}, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/connect/github?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "https://github.com/") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestConnectStart_ProviderWithSlash(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/connect/app.linear/mcp?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotProvider != "app.linear/mcp" {
		t.Fatalf("provider = %q, want app.linear/mcp", stub.gotProvider)
	}
}

// The connect page links a provider raw, but a client that builds the URL
// properly escapes the slash - and the SDK's connect link does. Read as written
// it names a provider no consumer has, and the link 404s on a server that is
// configured perfectly well.
func TestConnectStart_ProviderWithEscapedSlash(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/connect/app.linear%2Fmcp?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotProvider != "app.linear/mcp" {
		t.Fatalf("provider = %q, want app.linear/mcp", stub.gotProvider)
	}
}

func TestConnectStart_UsesConfiguredPublicBaseURL(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "https://oauth.mcp.example.com/")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	req := httptest.NewRequest("GET", "/oauth/connect/com.google.workspace/calendar?ticket=abc", nil)
	req.Host = "gw-tenant.mcp.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotBaseURL != "https://oauth.mcp.example.com" {
		t.Fatalf("baseURL = %q, want fixed public base", stub.gotBaseURL)
	}
	if stub.gotProvider != "com.google.workspace/calendar" {
		t.Fatalf("provider = %q", stub.gotProvider)
	}
}

func TestConnectCallback_UsesConfiguredPublicBaseURL(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{page: &appoauth.ConnectPage{
		ConsumerPath: "/tools/mcp",
		Providers:    []appoauth.ProviderStatus{{Provider: "github", Registry: "g", Linked: true}},
	}}
	h := NewConnectHandler(stub, nil, "https://oauth.mcp.example.com")
	app := fiber.New()
	app.Get(ConnectCallbackPath, h.Callback)
	req := httptest.NewRequest("GET", "/oauth/callback/github?state=s&code=c", nil)
	req.Host = "gw-tenant.mcp.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if stub.gotBaseURL != "https://oauth.mcp.example.com" {
		t.Fatalf("baseURL = %q, want fixed public base", stub.gotBaseURL)
	}
}

func TestConnectStart_FallsBackToRequestBaseURL(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	req := httptest.NewRequest("GET", "/oauth/connect/github?ticket=abc", nil)
	req.Host = "gw-tenant.mcp.example.com"
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if stub.gotBaseURL != "http://gw-tenant.mcp.example.com" {
		t.Fatalf("baseURL = %q, want request origin", stub.gotBaseURL)
	}
}

// sequencedConnectFlow answers Page with each page in turn, then keeps
// answering the last: a server that reaches the plane on the Nth look.
type sequencedConnectFlow struct {
	stubConnectService
	pages []*appoauth.ConnectPage
	calls int
}

func (s *sequencedConnectFlow) Page(context.Context, string) (*appoauth.ConnectPage, error) {
	page := s.pages[min(s.calls, len(s.pages)-1)]
	s.calls++
	return page, nil
}

func connectPageBody(t *testing.T, h *ConnectHandler, target string) string {
	t.Helper()
	app := fiber.New()
	app.Get("/+/connect", h.Page)
	res, err := app.Test(httptest.NewRequest("GET", target, nil), -1)
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	return string(body)
}

var (
	linearNotHereYet = &appoauth.ConnectPage{ConsumerPath: "/store/mcp", Code: "app.linear/mcp"}
	linearArrived    = &appoauth.ConnectPage{
		ConsumerPath: "/store/mcp",
		Code:         "app.linear/mcp",
		Providers:    []appoauth.ProviderStatus{{Provider: "app.linear/mcp", Code: "app.linear/mcp", Registry: "linear-mcp"}},
	}
)

// Right after a connect, config-sync brings the server within moments. The
// page waits for it instead of showing "getting ready" and reloading into the
// real page, which read as an error first.
func TestConnectPage_HoldsForAServerThatIsArriving(t *testing.T) {
	t.Parallel()
	flow := &sequencedConnectFlow{pages: []*appoauth.ConnectPage{linearNotHereYet, linearNotHereYet, linearArrived}}
	h := NewConnectHandler(flow, nil, "")
	h.holdFor, h.holdEvery = time.Second, time.Millisecond

	body := connectPageBody(t, h, "/store/mcp/connect?ticket=tk")
	if strings.Contains(body, "ready</h1>") || strings.Contains(body, `http-equiv="refresh"`) {
		t.Fatalf("page said it was getting ready although the server arrived while it waited: %s", body)
	}
	if !strings.Contains(body, "/oauth/connect/app.linear/mcp?ticket=tk") {
		t.Fatalf("page is not the server's connect card: %s", body)
	}
	if flow.calls != 3 {
		t.Fatalf("Page was read %d times, want 3", flow.calls)
	}
}

// A server that does not arrive within the hold still gets the "getting ready"
// page, with its own logo rather than the generic MCP mark.
func TestConnectPage_FallsBackToGettingReadyAfterTheHold(t *testing.T) {
	t.Parallel()
	h := NewConnectHandler(&sequencedConnectFlow{pages: []*appoauth.ConnectPage{linearNotHereYet}}, nil, "")
	h.holdFor, h.holdEvery = 20*time.Millisecond, time.Millisecond

	body := connectPageBody(t, h, "/store/mcp/connect?ticket=tk")
	if !strings.Contains(body, `http-equiv="refresh"`) {
		t.Fatalf("page did not fall back to reloading: %s", body)
	}
	if !strings.Contains(body, `src="/oauth/brands/mcp/linear.svg"`) {
		t.Fatalf("page does not show the server's own logo: %s", body)
	}
}

// A page whose server is already here, and one past the last attempt, answer
// at once.
func TestConnectPage_DoesNotHoldWhenThereIsNothingToWaitFor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		page   *appoauth.ConnectPage
		target string
	}{
		{"server already here", linearArrived, "/store/mcp/connect?ticket=tk"},
		{"last attempt spent", linearNotHereYet, "/store/mcp/connect?ticket=tk&wait=4"},
	} {
		flow := &sequencedConnectFlow{pages: []*appoauth.ConnectPage{tc.page}}
		h := NewConnectHandler(flow, nil, "")
		h.holdFor, h.holdEvery = time.Minute, time.Millisecond
		_ = connectPageBody(t, h, tc.target)
		if flow.calls != 1 {
			t.Fatalf("%s: Page was read %d times, want 1", tc.name, flow.calls)
		}
	}
}

// Calendly refusing the gateway's client registration is the upstream's answer,
// not a gateway fault: it must not surface as a 500, and the page has to keep
// the upstream's reason for whoever fixes the configuration.
func TestConnectStart_RejectedRegistrationIsBadGateway(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{startErr: fmt.Errorf("%w (status 400): %s",
		appoauth.ErrUpstreamRegistrationRejected, `{"error":"invalid_client_metadata"}`)}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectStartPath, h.Start)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/connect/com.calendly/mcp?ticket=abc", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusBadGateway {
		t.Fatalf("status = %d, want 502", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "The provider refused to register this gateway") {
		t.Fatalf("body does not explain the failure: %s", body)
	}
	if !strings.Contains(string(body), "invalid_client_metadata") {
		t.Fatalf("body must keep the upstream reason: %s", body)
	}
}

// An upstream that refuses the sign-in redirects back with a bare RFC 6749 code
// (Axiom sends error=invalid_target and nothing else). The page has to say what
// happened and what to do, not echo the code on its own.
func TestConnectCallback_UpstreamErrorRendersActionableFlash(t *testing.T) {
	t.Parallel()
	stub := &stubConnectService{
		page: &appoauth.ConnectPage{
			ConsumerPath: "/tools/mcp",
			Providers:    []appoauth.ProviderStatus{{Provider: "co.axiom/mcp", Registry: "axiom"}},
		},
		callbackErr: &appoauth.OAuthError{Code: "invalid_target"},
	}
	h := NewConnectHandler(stub, nil, "")
	app := fiber.New()
	app.Get(ConnectCallbackPath, h.Callback)
	res, err := app.Test(httptest.NewRequest("GET", "/oauth/callback/co.axiom/mcp?state=s&error=invalid_target", nil))
	if err != nil {
		t.Fatalf("route test: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	html := string(body)
	if !strings.Contains(html, "The provider rejected the sign-in request") {
		t.Fatalf("flash does not explain the failure: %s", html)
	}
	if !strings.Contains(html, "(invalid_target)") {
		t.Fatalf("flash must keep the upstream code for operators: %s", html)
	}
}

func TestCallbackFlash(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"denied", &appoauth.OAuthError{Code: "access_denied"}, "Sign-in was cancelled or access was not granted. Try again to connect your account. (access_denied)"},
		{"with description", &appoauth.OAuthError{Code: "invalid_scope", Description: "unknown scope foo"}, "(invalid_scope: unknown scope foo)"},
		{"unavailable", &appoauth.OAuthError{Code: "temporarily_unavailable"}, "Wait a moment and try again. (temporarily_unavailable)"},
		{"unknown code", &appoauth.OAuthError{Code: "weird"}, "Sign-in with the provider failed."},
		{"not an oauth error", io.ErrUnexpectedEOF, io.ErrUnexpectedEOF.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := callbackFlash(tc.err); !strings.Contains(got, tc.want) {
				t.Fatalf("callbackFlash = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
