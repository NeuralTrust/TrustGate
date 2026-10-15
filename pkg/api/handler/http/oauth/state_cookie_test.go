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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// stubAuthProxy plays the brokered flow: Authorize parks an IdP leg (or
// returns a client redirect), Approve and Deny release it, Callback records
// what it was asked to redeem.
type stubAuthProxy struct {
	authorizeResult appoauth.AuthorizeResult
	authorizeErr    error
	approved        []string
	denied          []string
	denyLocation    string
	callbackState   string
	callbackCalls   int
}

func (s *stubAuthProxy) Authorize(context.Context, string, appoauth.AuthorizeRequest) (appoauth.AuthorizeResult, error) {
	return s.authorizeResult, s.authorizeErr
}

func (s *stubAuthProxy) Approve(_ context.Context, state string) (string, error) {
	s.approved = append(s.approved, state)
	if state != gatewayState {
		return "", &appoauth.OAuthError{Code: "invalid_request", Description: "unknown or expired authorization request"}
	}
	return idpLocation, nil
}

func (s *stubAuthProxy) Deny(_ context.Context, state string) (string, error) {
	s.denied = append(s.denied, state)
	if s.denyLocation != "" {
		return s.denyLocation, nil
	}
	return "https://client.example.com/cb?error=access_denied&state=client-state", nil
}

func (s *stubAuthProxy) Callback(_ context.Context, _, state, _, _, _ string) (string, error) {
	s.callbackCalls++
	s.callbackState = state
	return "https://client.example.com/cb?code=gw-code&state=client-state", nil
}

func (s *stubAuthProxy) Exchange(context.Context, string, appoauth.TokenRequest) (map[string]any, error) {
	return nil, nil
}

type stubClientFinder map[string]string

func (s stubClientFinder) GetGatewayClient(_ context.Context, clientID string) (*appoauth.RegisteredGatewayClient, error) {
	name, ok := s[clientID]
	if !ok {
		return nil, nil
	}
	return &appoauth.RegisteredGatewayClient{ClientID: clientID, ClientName: name}, nil
}

func newFlowApp(proxy appoauth.AuthProxy) *fiber.App {
	app := fiber.New()
	authorize := NewAuthorizeHandler(proxy, nil, stubClientFinder{"agw-1": "Claude"}, FlowCookies{})
	app.Get(AuthorizePath, authorize.Handle)
	app.Post(AuthorizePath, authorize.Decide)
	app.Get(appoauth.CallbackPath, NewCallbackHandler(proxy, FlowCookies{}).Handle)
	return app
}

func setCookies(t *testing.T, res *http.Response) map[string]*http.Cookie {
	t.Helper()
	out := map[string]*http.Cookie{}
	for _, c := range res.Cookies() {
		out[c.Name] = c
	}
	return out
}

const gatewayState = "3f2a9c0e1b4d5e6f7a8b9c0d1e2f3a4b"

func authorizeReq(scheme string) *http.Request {
	req := httptest.NewRequest(fiber.MethodGet,
		AuthorizePath+"?response_type=code&client_id=agw-1&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&state=client-state&code_challenge=x&code_challenge_method=S256",
		nil)
	req.Host = "gw.example.com"
	if scheme == "https" {
		req.Header.Set(fiber.HeaderXForwardedProto, "https")
	}
	return req
}

const idpLocation = "https://idp.example.com/authorize?client_id=trustgate&state=" + gatewayState

func consentReq(host, state, decision string, cookie *http.Cookie) *http.Request {
	form := url.Values{"state": {state}, consentDecisionField: {decision}}
	req := httptest.NewRequest(fiber.MethodPost, AuthorizePath, strings.NewReader(form.Encode()))
	req.Host = host
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)
	if host == "gw.example.com" {
		req.Header.Set(fiber.HeaderXForwardedProto, "https")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

func parkedConsent(name string) *http.Cookie {
	return &http.Cookie{Name: name, Value: gatewayState}
}

func consentCookieFor(prefix string) string {
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(ctx)
	name := FlowCookies{}.consentCookieName(ctx, gatewayState)
	return prefix + strings.TrimPrefix(strings.TrimPrefix(name, consentCookieSecureName), consentCookiePlainName)
}

func TestAuthorizeShowsConsentBeforeIdP(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{authorizeResult: appoauth.AuthorizeResult{Location: idpLocation, ConsentState: gatewayState}}
	res, err := newFlowApp(proxy).Test(authorizeReq("https"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("expected the consent page (200), got %d", res.StatusCode)
	}
	if loc := res.Header.Get(fiber.HeaderLocation); loc != "" {
		t.Fatalf("the IdP leg must wait for consent, got redirect to %q", loc)
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("consent page must refuse framing, got CSP %q", res.Header.Get("Content-Security-Policy"))
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	for _, want := range []string{"Claude", "client.example.com", `value="` + gatewayState + `"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("consent page must show %q", want)
		}
	}
	if strings.Contains(string(body), "idp.example.com") {
		t.Fatal("the IdP redirect must stay on the server until approval")
	}
	cookies := setCookies(t, res)
	if cookies[stateCookieSecureName] != nil {
		t.Fatal("the callback binding must only be issued after approval")
	}
	ck := cookies[consentCookieFor(consentCookieSecureName)]
	if ck == nil {
		t.Fatalf("expected a per-flow consent cookie, got %v", res.Header.Values(fiber.HeaderSetCookie))
	}
	if ck.Value != gatewayState || !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode || ck.Domain != "" {
		t.Fatalf("consent cookie must hold the state and be HttpOnly, Secure, Path=/, SameSite=Lax, host-only, got %+v", ck)
	}
}

func TestAuthorizeClientRedirectSkipsConsent(t *testing.T) {
	t.Parallel()
	location := "https://client.example.com/cb?error=invalid_target&state=client-state"
	res, err := newFlowApp(&stubAuthProxy{authorizeResult: appoauth.AuthorizeResult{Location: location}}).Test(authorizeReq("https"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusFound || res.Header.Get(fiber.HeaderLocation) != location {
		t.Fatalf("expected 302 back to the client, got %d %q", res.StatusCode, res.Header.Get(fiber.HeaderLocation))
	}
	if len(res.Cookies()) != 0 {
		t.Fatalf("a client redirect must set no flow cookie, got %v", res.Header.Values(fiber.HeaderSetCookie))
	}
}

func TestConsentApprovalBindsStateAndResumesIdP(t *testing.T) {
	t.Parallel()

	t.Run("https uses __Host- cookies", func(t *testing.T) {
		t.Parallel()
		proxy := &stubAuthProxy{}
		res, err := newFlowApp(proxy).Test(consentReq("gw.example.com", gatewayState, consentApprove, parkedConsent(consentCookieFor(consentCookieSecureName))))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if res.StatusCode != fiber.StatusSeeOther || res.Header.Get(fiber.HeaderLocation) != idpLocation {
			t.Fatalf("expected 303 to the IdP, got %d %q", res.StatusCode, res.Header.Get(fiber.HeaderLocation))
		}
		if len(proxy.approved) != 1 || proxy.approved[0] != gatewayState {
			t.Fatalf("the parked authorization must be approved once, got %v", proxy.approved)
		}
		cookies := setCookies(t, res)
		ck := cookies[stateCookieSecureName]
		if ck == nil || ck.Value != gatewayState {
			t.Fatalf("approval must bind the gateway state, got %v", res.Header.Values(fiber.HeaderSetCookie))
		}
		if !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode || ck.Domain != "" {
			t.Fatalf("state cookie must be HttpOnly, Secure, Path=/, SameSite=Lax, host-only, got %+v", ck)
		}
		if ck.MaxAge != int(stateCookieMaxAge.Seconds()) {
			t.Fatalf("cookie Max-Age = %d, want %d", ck.MaxAge, int(stateCookieMaxAge.Seconds()))
		}
		if cleared := cookies[consentCookieFor(consentCookieSecureName)]; cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
			t.Fatal("the consent cookie must be cleared once used")
		}
	})

	t.Run("plain http stays usable on loopback", func(t *testing.T) {
		t.Parallel()
		res, err := newFlowApp(&stubAuthProxy{}).Test(consentReq("localhost:8080", gatewayState, consentApprove, parkedConsent(consentCookieFor(consentCookiePlainName))))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		ck := setCookies(t, res)[stateCookiePlainName]
		if res.StatusCode != fiber.StatusSeeOther || ck == nil || ck.Secure || ck.Value != gatewayState {
			t.Fatalf("loopback approval must bind over plain http, got status=%d cookie=%+v", res.StatusCode, ck)
		}
	})
}

func TestFlowCookiesUseHostPrefixOnNonLoopbackHosts(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{authorizeResult: appoauth.AuthorizeResult{Location: idpLocation, ConsentState: gatewayState}}
	res, err := newFlowApp(proxy).Test(authorizeReq("http"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	ck := setCookies(t, res)[consentCookieFor(consentCookieSecureName)]
	if ck == nil || !ck.Secure {
		t.Fatalf("expected the __Host- consent cookie, got %v", res.Header.Values(fiber.HeaderSetCookie))
	}
}

func TestFlowCookiesAllowInsecureKeepsPlainHTTPHostsUsable(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{authorizeResult: appoauth.AuthorizeResult{Location: idpLocation, ConsentState: gatewayState}}
	app := fiber.New()
	authorize := NewAuthorizeHandler(proxy, nil, nil, FlowCookies{AllowInsecure: true})
	app.Get(AuthorizePath, authorize.Handle)
	app.Post(AuthorizePath, authorize.Decide)

	res, err := app.Test(authorizeReq("http"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	consent := setCookies(t, res)[consentCookieFor(consentCookiePlainName)]
	if consent == nil || consent.Secure {
		t.Fatalf("expected a plain consent cookie, got %v", res.Header.Values(fiber.HeaderSetCookie))
	}

	req := consentReq("gw.example.com", gatewayState, consentApprove, consent)
	req.Header.Del(fiber.HeaderXForwardedProto)
	res, err = app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if ck := setCookies(t, res)[stateCookiePlainName]; res.StatusCode != fiber.StatusSeeOther || ck == nil || ck.Secure {
		t.Fatalf("expected a plain state binding and a 303, got %d %v", res.StatusCode, res.Header.Values(fiber.HeaderSetCookie))
	}
}

func TestConsentRejectsSubmissionsNotBoundToThisBrowser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		state   string
		cookie  *http.Cookie
		headers map[string]string
	}{
		{name: "no consent cookie", state: gatewayState},
		{name: "state from another flow", state: "other-state", cookie: parkedConsent(consentCookieFor(consentCookieSecureName))},
		{name: "cookie for another state", state: gatewayState, cookie: &http.Cookie{Name: consentCookieFor(consentCookieSecureName), Value: "other-state"}},
		{name: "plain cookie on a public host", state: gatewayState, cookie: parkedConsent(consentCookieFor(consentCookiePlainName))},
		{name: "cross-site submission", state: gatewayState, cookie: parkedConsent(consentCookieFor(consentCookieSecureName)), headers: map[string]string{"Sec-Fetch-Site": "cross-site"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			proxy := &stubAuthProxy{}
			req := consentReq("gw.example.com", tt.state, consentApprove, tt.cookie)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			res, err := newFlowApp(proxy).Test(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			if res.StatusCode != fiber.StatusBadRequest {
				t.Fatalf("expected 400, got %d", res.StatusCode)
			}
			if len(proxy.approved) != 0 || setCookies(t, res)[stateCookieSecureName] != nil {
				t.Fatal("nothing may be approved or bound for an unbound submission")
			}
		})
	}
}

func TestConsentDeclinedReportsToTheClient(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{}
	res, err := newFlowApp(proxy).Test(consentReq("gw.example.com", gatewayState, "deny", parkedConsent(consentCookieFor(consentCookieSecureName))))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusSeeOther || !strings.Contains(res.Header.Get(fiber.HeaderLocation), "error=access_denied") {
		t.Fatalf("a declined request must go back to the client with access_denied, got %d %q", res.StatusCode, res.Header.Get(fiber.HeaderLocation))
	}
	if len(proxy.denied) != 1 || len(proxy.approved) != 0 {
		t.Fatalf("expected one deny and no approval, got denied=%v approved=%v", proxy.denied, proxy.approved)
	}
	if setCookies(t, res)[stateCookieSecureName] != nil {
		t.Fatal("a declined request must not be bound for the callback")
	}
}

func TestConsentDeclinedHandsAppCallbacksADeepLinkPage(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{denyLocation: "cursor://anysphere.cursor-mcp/oauth/callback?error=access_denied&state=client-state"}
	res, err := newFlowApp(proxy).Test(consentReq("gw.example.com", gatewayState, "deny", parkedConsent(consentCookieFor(consentCookieSecureName))))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != fiber.StatusOK || !strings.Contains(string(body), "cursor://anysphere.cursor-mcp/oauth/callback") {
		t.Fatalf("an app callback must get the deep-link page, got %d", res.StatusCode)
	}
}

func callbackReq(scheme, state string, cookie *http.Cookie) *http.Request {
	req := httptest.NewRequest(fiber.MethodGet, appoauth.CallbackPath+"?code=platform-code&state="+state, nil)
	req.Host = "gw.example.com"
	if scheme == "https" {
		req.Header.Set(fiber.HeaderXForwardedProto, "https")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

func TestCallbackWithMatchingStateCookieProceedsAndClearsIt(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{}
	app := newFlowApp(proxy)

	res, err := app.Test(callbackReq("https", gatewayState, &http.Cookie{Name: stateCookieSecureName, Value: gatewayState}))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusFound {
		t.Fatalf("expected 302 to the client, got %d", res.StatusCode)
	}
	if proxy.callbackCalls != 1 || proxy.callbackState != gatewayState {
		t.Fatalf("callback must be redeemed once with the query state, got calls=%d state=%q", proxy.callbackCalls, proxy.callbackState)
	}
	if !strings.HasPrefix(res.Header.Get(fiber.HeaderLocation), "https://client.example.com/cb?") {
		t.Fatalf("expected redirect to the client, got %q", res.Header.Get(fiber.HeaderLocation))
	}
	cleared := setCookies(t, res)[stateCookieSecureName]
	if cleared == nil {
		t.Fatalf("callback must clear the binding cookie, got %v", res.Header.Values(fiber.HeaderSetCookie))
	}
	// net/http reports Max-Age=0 (fasthttp's rendering of a negative MaxAge,
	// an immediate delete for browsers) as MaxAge -1.
	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("clearing cookie must be empty and expire immediately, got %+v", cleared)
	}
	if !cleared.Secure || cleared.Path != "/" {
		t.Fatalf("clearing cookie must mirror the __Host- attributes to be honoured, got %+v", cleared)
	}
}

func TestCallbackWithoutStateCookieIsRejected(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{}
	res, err := newFlowApp(proxy).Test(callbackReq("https", gatewayState, nil))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("a callback with no browser binding must be rejected with 400, got %d", res.StatusCode)
	}
	if proxy.callbackCalls != 0 {
		t.Fatal("no code may be redeemed without the browser binding")
	}
}

func TestCallbackWithMismatchedStateCookieIsRejected(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{}
	app := newFlowApp(proxy)

	// The attacker completed their own IdP leg and lures the victim's browser
	// (which holds the state of the flow it started) into the callback carrying
	// the attacker's state and code.
	res, err := app.Test(callbackReq("https", "attacker-state", &http.Cookie{Name: stateCookieSecureName, Value: gatewayState}))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("mismatched state must be rejected with 400, got %d", res.StatusCode)
	}
	if proxy.callbackCalls != 0 {
		t.Fatal("no code may be redeemed for a state this browser did not start")
	}
	if cleared := setCookies(t, res)[stateCookieSecureName]; cleared == nil || cleared.Value != "" {
		t.Fatal("the binding must be cleared even on rejection so the browser starts over")
	}
}

func TestCallbackPlainHTTPUsesPlainCookieName(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{}
	req := callbackReq("http", gatewayState, &http.Cookie{Name: stateCookiePlainName, Value: gatewayState})
	req.Host = "localhost:8080"
	res, err := newFlowApp(proxy).Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusFound || proxy.callbackCalls != 1 {
		t.Fatalf("loopback http flow must keep working, got status=%d calls=%d", res.StatusCode, proxy.callbackCalls)
	}
}

func TestRedirectTargetShowsAnASCIIHost(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://claude.ai/api/mcp/auth_callback":        "claude.ai",
		"https://user@claude.ai.example.com/cb":          "claude.ai.example.com",
		"https://сlaude.ai/cb":                           "xn--laude-0ye.ai",
		"https://x-.аpple.com/cb":                        "x-.xn--pple-43d.com",
		"http://127.0.0.1:33418/callback":                "127.0.0.1:33418",
		"cursor://anysphere.cursor-mcp/oauth/callback?x": "cursor://anysphere.cursor-mcp/oauth/callback",
	}
	for in, want := range cases {
		if got := redirectTarget(in); got != want {
			t.Errorf("redirectTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientNameDropsControlCharactersAndIsCapped(t *testing.T) {
	t.Parallel()
	h := NewAuthorizeHandler(nil, nil, stubClientFinder{
		"bidi": "Cla\u202eedu\u200b",
		"long": strings.Repeat("a", 80),
	}, FlowCookies{})
	if got := h.clientName(context.Background(), "bidi"); got != "Claedu" {
		t.Errorf("clientName = %q, want control characters removed", got)
	}
	if got := []rune(h.clientName(context.Background(), "long")); len(got) != maxClientNameRunes+1 {
		t.Errorf("clientName length = %d, want %d", len(got), maxClientNameRunes+1)
	}
}
