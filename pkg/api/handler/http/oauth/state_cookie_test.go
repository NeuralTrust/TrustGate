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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// stubAuthProxy plays the brokered flow: Authorize redirects to the IdP with
// the gateway state, Callback records what it was asked to redeem.
type stubAuthProxy struct {
	authorizeLocation string
	authorizeErr      error
	callbackState     string
	callbackCalls     int
}

func (s *stubAuthProxy) Authorize(context.Context, string, appoauth.AuthorizeRequest) (string, error) {
	return s.authorizeLocation, s.authorizeErr
}

func (s *stubAuthProxy) Callback(_ context.Context, _, state, _, _, _ string) (string, error) {
	s.callbackCalls++
	s.callbackState = state
	return "https://client.example.com/cb?code=gw-code&state=client-state", nil
}

func (s *stubAuthProxy) Exchange(context.Context, string, appoauth.TokenRequest) (map[string]any, error) {
	return nil, nil
}

func newFlowApp(proxy appoauth.AuthProxy) *fiber.App {
	app := fiber.New()
	app.Get(AuthorizePath, NewAuthorizeHandler(proxy, nil).Handle)
	app.Get(appoauth.CallbackPath, NewCallbackHandler(proxy).Handle)
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

func TestAuthorizeSetsBrowserBoundStateCookie(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{authorizeLocation: "https://idp.example.com/authorize?client_id=trustgate&state=" + gatewayState}
	app := newFlowApp(proxy)

	t.Run("https uses a __Host- cookie", func(t *testing.T) {
		t.Parallel()
		res, err := app.Test(authorizeReq("https"))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if res.StatusCode != fiber.StatusFound {
			t.Fatalf("expected 302, got %d", res.StatusCode)
		}
		ck := setCookies(t, res)[stateCookieSecureName]
		if ck == nil {
			t.Fatalf("expected %s cookie, got %v", stateCookieSecureName, res.Header.Values(fiber.HeaderSetCookie))
		}
		if ck.Value != gatewayState {
			t.Fatalf("cookie must hold the gateway state, got %q", ck.Value)
		}
		if !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie attributes must be HttpOnly, Secure, Path=/, SameSite=Lax, got %+v", ck)
		}
		if ck.MaxAge != int(stateCookieMaxAge.Seconds()) {
			t.Fatalf("cookie Max-Age = %d, want %d", ck.MaxAge, int(stateCookieMaxAge.Seconds()))
		}
		if ck.Domain != "" {
			t.Fatalf("a __Host- cookie must carry no Domain, got %q", ck.Domain)
		}
	})

	t.Run("plain http loopback stays usable without Secure", func(t *testing.T) {
		t.Parallel()
		res, err := app.Test(authorizeReq("http"))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		ck := setCookies(t, res)[stateCookiePlainName]
		if ck == nil {
			t.Fatalf("expected %s cookie over http, got %v", stateCookiePlainName, res.Header.Values(fiber.HeaderSetCookie))
		}
		if ck.Secure {
			t.Fatal("a browser would drop a Secure cookie set over plain http")
		}
		if ck.Value != gatewayState || !ck.HttpOnly {
			t.Fatalf("unexpected cookie %+v", ck)
		}
	})
}

// A protocol error is redirected back to the client with the client's own
// state; that never comes back through the callback, so no binding is set.
func TestAuthorizeErrorRedirectSetsNoStateCookie(t *testing.T) {
	t.Parallel()
	proxy := &stubAuthProxy{authorizeLocation: "https://client.example.com/cb?error=invalid_target&state=client-state"}
	res, err := newFlowApp(proxy).Test(authorizeReq("https"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if len(res.Cookies()) != 0 {
		t.Fatalf("no state cookie must be set on a client error redirect, got %v", res.Header.Values(fiber.HeaderSetCookie))
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
	res, err := newFlowApp(proxy).Test(callbackReq("http", gatewayState, &http.Cookie{Name: stateCookiePlainName, Value: gatewayState}))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.StatusCode != fiber.StatusFound || proxy.callbackCalls != 1 {
		t.Fatalf("loopback http flow must keep working, got status=%d calls=%d", res.StatusCode, proxy.callbackCalls)
	}
}
