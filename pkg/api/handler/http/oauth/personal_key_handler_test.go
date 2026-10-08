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
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type pkMemStore struct {
	tickets  map[string]appoauth.PersonalKeyTicket
	sessions map[string]appoauth.PersonalKeySession
}

func (m *pkMemStore) SaveTicket(_ context.Context, id string, t appoauth.PersonalKeyTicket) error {
	m.tickets[id] = t
	return nil
}

func (m *pkMemStore) GetTicket(_ context.Context, id string) (*appoauth.PersonalKeyTicket, error) {
	if t, ok := m.tickets[id]; ok {
		return &t, nil
	}
	return nil, nil
}

func (m *pkMemStore) DeleteTicket(_ context.Context, id string) error {
	delete(m.tickets, id)
	return nil
}

func (m *pkMemStore) SaveSession(_ context.Context, id string, s appoauth.PersonalKeySession) error {
	m.sessions[id] = s
	return nil
}

func (m *pkMemStore) GetSession(_ context.Context, id string) (*appoauth.PersonalKeySession, error) {
	if s, ok := m.sessions[id]; ok {
		return &s, nil
	}
	return nil, nil
}

func (m *pkMemStore) DeleteSession(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

type pkSignIn struct {
	proofs map[string]appoauth.BrowserIdentity
}

func (s *pkSignIn) BeginBrowserSignIn(context.Context, string, string) (string, error) {
	return "https://idp.example/authorize?state=s-1", nil
}

func (s *pkSignIn) TakeBrowserSignIn(_ context.Context, proof string) (*appoauth.BrowserIdentity, error) {
	who, ok := s.proofs[proof]
	if !ok {
		return nil, appoauth.ErrBrowserProof
	}
	delete(s.proofs, proof)
	return &who, nil
}

type pkIssuer struct{ key *appauth.PersonalKey }

func (i *pkIssuer) Get(context.Context, ids.GatewayID, string) (*appauth.PersonalKey, error) {
	if i.key == nil {
		return nil, authdomain.ErrNotFound
	}
	return i.key, nil
}

func (i *pkIssuer) Create(_ context.Context, gw ids.GatewayID, owner string, _ []string) (*appauth.PersonalKey, error) {
	expires := time.Now().Add(90 * 24 * time.Hour)
	i.key = &appauth.PersonalKey{Auth: &authdomain.Auth{GatewayID: gw, OwnerID: owner, KeyPrefix: "ag_ab", KeySuffix: "yz", ExpiresAt: &expires, RawKey: "ag_the_secret"}}
	return i.key, nil
}

func (i *pkIssuer) Rotate(context.Context, ids.GatewayID, string) (*appauth.PersonalKey, error) {
	return i.key, nil
}

func (i *pkIssuer) Revoke(context.Context, ids.GatewayID, string) error {
	i.key = nil
	return nil
}

type pkGateways struct{ gw *gatewaydomain.Gateway }

func (g pkGateways) Resolve(*fiber.Ctx) (*gatewaydomain.Gateway, error) { return g.gw, nil }

type pkFixture struct {
	app    *fiber.App
	signIn *pkSignIn
	issuer *pkIssuer
	ticket string
	gw     string
}

func newPKFixture(t *testing.T) *pkFixture {
	t.Helper()
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	store := &pkMemStore{tickets: map[string]appoauth.PersonalKeyTicket{}, sessions: map[string]appoauth.PersonalKeySession{}}
	signIn := &pkSignIn{proofs: map[string]appoauth.BrowserIdentity{}}
	issuer := &pkIssuer{}
	pages, err := appoauth.NewPersonalKeyPages(store, signIn, issuer, nil, nil)
	require.NoError(t, err)
	ticket, err := pages.CreateTicket(context.Background(), appoauth.PersonalKeyTicket{
		GatewayID: gw.ID.String(), PrincipalSub: "alice", MCPURL: "https://acme.mcp.example/store/mcp",
	})
	require.NoError(t, err)
	h := NewPersonalKeyHandler(pages, pkGateways{gw: gw}, FlowCookies{AllowInsecure: true})
	app := fiber.New()
	app.Get(appoauth.PersonalKeyReturnPath, h.Return)
	app.Get(appoauth.PersonalKeyPagePath, h.Page)
	app.Post(appoauth.PersonalKeyPagePath, h.Act)
	return &pkFixture{app: app, signIn: signIn, issuer: issuer, ticket: ticket, gw: gw.ID.String()}
}

func (f *pkFixture) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := f.app.Test(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	return res, string(body)
}

func (f *pkFixture) pageURL() string {
	return appoauth.PersonalKeyPagePath + "?" + url.Values{"ticket": {f.ticket}}.Encode()
}

// signIn walks the browser through the page's sign-in and returns its cookie.
func (f *pkFixture) signInAs(t *testing.T, who appoauth.BrowserIdentity) (*http.Response, string, *http.Cookie) {
	t.Helper()
	f.signIn.proofs["p-1"] = who
	res, body := f.do(t, httptest.NewRequest(http.MethodGet,
		appoauth.PersonalKeyReturnPath+"?"+url.Values{"ticket": {f.ticket}, "proof": {"p-1"}}.Encode(), nil))
	for _, c := range res.Cookies() {
		if strings.HasPrefix(c.Name, personalKeyCookiePlainName) {
			return res, body, c
		}
	}
	return res, body, nil
}

// The whole page from the browser's side: sent to sign in, back with a cookie
// bound to the link, the key created with the page's own form, its secret
// shown once, and the link spent.
func TestPersonalKeyHandler_SignInCreateAndSpend(t *testing.T) {
	fx := newPKFixture(t)

	res, _ := fx.do(t, httptest.NewRequest(http.MethodGet, fx.pageURL(), nil))
	require.Equal(t, fiber.StatusFound, res.StatusCode)
	require.Equal(t, "https://idp.example/authorize?state=s-1", res.Header.Get("Location"))
	var state *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == stateCookiePlainName {
			state = c
		}
	}
	require.NotNil(t, state, "the gateway's callback only redeems a sign-in started in this browser")
	require.Equal(t, "s-1", state.Value)
	require.Equal(t, "frame-ancestors 'none'", res.Header.Get("Content-Security-Policy"))

	res, _, cookie := fx.signInAs(t, appoauth.BrowserIdentity{Subject: "alice", Email: "alice@acme.test", GatewayID: fx.gw})
	require.Equal(t, fiber.StatusSeeOther, res.StatusCode)
	require.Equal(t, fx.pageURL(), res.Header.Get("Location"))
	require.NotNil(t, cookie)
	require.True(t, cookie.HttpOnly)

	page := httptest.NewRequest(http.MethodGet, fx.pageURL(), nil)
	page.AddCookie(cookie)
	res, body := fx.do(t, page)
	require.Equal(t, fiber.StatusOK, res.StatusCode)
	require.Contains(t, body, "Create personal key")
	require.Contains(t, body, "alice@acme.test")
	require.Contains(t, body, "TrustGateUser(&#34;https://acme.mcp.example/store/mcp&#34;")
	csrf := between(body, `name="csrf" value="`, `"`)
	require.NotEmpty(t, csrf)

	cross := httptest.NewRequest(http.MethodPost, fx.pageURL(), strings.NewReader(url.Values{"csrf": {csrf}, "action": {"create"}}.Encode()))
	cross.Header.Set(fiber.HeaderContentType, "application/x-www-form-urlencoded")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	cross.AddCookie(cookie)
	res, _ = fx.do(t, cross)
	require.Equal(t, fiber.StatusForbidden, res.StatusCode, "a post from another site is not the person pressing the button")
	require.Nil(t, fx.issuer.key)

	create := httptest.NewRequest(http.MethodPost, fx.pageURL(), strings.NewReader(url.Values{"csrf": {csrf}, "action": {"create"}}.Encode()))
	create.Header.Set(fiber.HeaderContentType, "application/x-www-form-urlencoded")
	create.Header.Set("Sec-Fetch-Site", "same-origin")
	create.AddCookie(cookie)
	res, body = fx.do(t, create)
	require.Equal(t, fiber.StatusOK, res.StatusCode)
	require.Contains(t, body, "ag_the_secret")
	require.Contains(t, body, "shown once")
	require.Equal(t, "no-store", res.Header.Get(fiber.HeaderCacheControl)[:8])

	again := httptest.NewRequest(http.MethodGet, fx.pageURL(), nil)
	again.AddCookie(cookie)
	res, body = fx.do(t, again)
	require.Equal(t, fiber.StatusGone, res.StatusCode)
	require.NotContains(t, body, "ag_the_secret")
}

func TestPersonalKeyHandler_SaysWhoTheBrowserIsSignedInAs(t *testing.T) {
	fx := newPKFixture(t)

	res, body, cookie := fx.signInAs(t, appoauth.BrowserIdentity{Subject: "mallory", Email: "mallory@evil.test", GatewayID: fx.gw})

	require.Equal(t, fiber.StatusForbidden, res.StatusCode)
	require.Nil(t, cookie)
	require.Contains(t, body, "This link is for another account")
	require.Contains(t, body, "mallory@evil.test")
}

func TestPersonalKeyHandler_AFormWithoutTheBrowsersSignInIsRefused(t *testing.T) {
	fx := newPKFixture(t)
	post := httptest.NewRequest(http.MethodPost, fx.pageURL(), strings.NewReader(url.Values{"csrf": {"x"}, "action": {"create"}}.Encode()))
	post.Header.Set(fiber.HeaderContentType, "application/x-www-form-urlencoded")

	res, body := fx.do(t, post)

	require.Equal(t, fiber.StatusForbidden, res.StatusCode)
	require.Contains(t, body, "Sign in again")
	require.Nil(t, fx.issuer.key)
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
