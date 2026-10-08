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
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

type memPersonalKeyStore struct {
	tickets  map[string]PersonalKeyTicket
	sessions map[string]PersonalKeySession
}

func newMemPersonalKeyStore() *memPersonalKeyStore {
	return &memPersonalKeyStore{tickets: map[string]PersonalKeyTicket{}, sessions: map[string]PersonalKeySession{}}
}

func (m *memPersonalKeyStore) SaveTicket(_ context.Context, id string, t PersonalKeyTicket) error {
	m.tickets[id] = t
	return nil
}

func (m *memPersonalKeyStore) GetTicket(_ context.Context, id string) (*PersonalKeyTicket, error) {
	t, ok := m.tickets[id]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (m *memPersonalKeyStore) DeleteTicket(_ context.Context, id string) error {
	delete(m.tickets, id)
	return nil
}

func (m *memPersonalKeyStore) SaveSession(_ context.Context, id string, s PersonalKeySession) error {
	m.sessions[id] = s
	return nil
}

func (m *memPersonalKeyStore) GetSession(_ context.Context, id string) (*PersonalKeySession, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, nil
	}
	return &s, nil
}

func (m *memPersonalKeyStore) DeleteSession(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

// fakeSignIn hands out a proof for whoever the test says signed in.
type fakeSignIn struct {
	returnTo string
	proofs   map[string]BrowserIdentity
}

func (f *fakeSignIn) BeginBrowserSignIn(_ context.Context, _, returnTo string) (string, error) {
	f.returnTo = returnTo
	return "https://idp.example/authorize?state=s", nil
}

func (f *fakeSignIn) TakeBrowserSignIn(_ context.Context, proof string) (*BrowserIdentity, error) {
	who, ok := f.proofs[proof]
	if !ok {
		return nil, ErrBrowserProof
	}
	delete(f.proofs, proof)
	return &who, nil
}

type fakeIssuer struct {
	key     *appauth.PersonalKey
	groups  []string
	err     error
	rotated int
}

func (f *fakeIssuer) Get(context.Context, ids.GatewayID, string) (*appauth.PersonalKey, error) {
	if f.key == nil {
		return nil, authdomain.ErrNotFound
	}
	return f.key, nil
}

func (f *fakeIssuer) Create(_ context.Context, gw ids.GatewayID, owner string, groups []string) (*appauth.PersonalKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.key != nil {
		return nil, authdomain.ErrOwnedKeyExists
	}
	f.groups = groups
	expires := time.Now().Add(time.Hour)
	f.key = &appauth.PersonalKey{Auth: &authdomain.Auth{GatewayID: gw, OwnerID: owner, KeyPrefix: "ag_ab", KeySuffix: "yz", ExpiresAt: &expires}}
	issued := *f.key.Auth
	issued.RawKey = "ag_secret"
	return &appauth.PersonalKey{Auth: &issued}, nil
}

func (f *fakeIssuer) Rotate(context.Context, ids.GatewayID, string) (*appauth.PersonalKey, error) {
	if f.key == nil {
		return nil, authdomain.ErrNotFound
	}
	f.rotated++
	issued := *f.key.Auth
	issued.RawKey = "ag_rotated"
	return &appauth.PersonalKey{Auth: &issued}, nil
}

func (f *fakeIssuer) Revoke(context.Context, ids.GatewayID, string) error {
	if f.key == nil {
		return authdomain.ErrNotFound
	}
	f.key = nil
	return nil
}

type refusingLimiter struct{}

func (refusingLimiter) Check(context.Context, ConnectAttemptScope, string) error {
	return &ConnectRateLimitExceeded{RetryAfter: time.Hour}
}

type personalKeyFixture struct {
	pages  PersonalKeyPages
	store  *memPersonalKeyStore
	signIn *fakeSignIn
	issuer *fakeIssuer
	ticket string
	gw     string
}

func newPersonalKeyFixture(t *testing.T, limiter PersonalKeyLimiter) *personalKeyFixture {
	t.Helper()
	store := newMemPersonalKeyStore()
	signIn := &fakeSignIn{proofs: map[string]BrowserIdentity{}}
	issuer := &fakeIssuer{}
	pages, err := NewPersonalKeyPages(store, signIn, issuer, limiter, nil)
	require.NoError(t, err)
	gw := ids.New[ids.GatewayKind]().String()
	ticket, err := pages.CreateTicket(context.Background(), PersonalKeyTicket{
		GatewayID: gw, PrincipalSub: "alice", MCPURL: "https://gw.example/store/mcp", LLMURL: "https://gw.llm.example/store/v1",
	})
	require.NoError(t, err)
	return &personalKeyFixture{pages: pages, store: store, signIn: signIn, issuer: issuer, ticket: ticket, gw: gw}
}

// signIn brings the browser back as who, and returns its session.
func (f *personalKeyFixture) signInAs(t *testing.T, who BrowserIdentity) (string, error) {
	t.Helper()
	f.signIn.proofs["proof-1"] = who
	return f.pages.Return(context.Background(), f.ticket, "proof-1")
}

func (f *personalKeyFixture) alice() BrowserIdentity {
	return BrowserIdentity{Subject: "alice", Email: "alice@acme.test", GatewayID: f.gw, Groups: []string{"eng"}}
}

// The link alone shows nothing: the browser is sent to sign in, and comes back
// to this ticket.
func TestPersonalKeyPage_SendsAnUnknownBrowserToSignIn(t *testing.T) {
	fx := newPersonalKeyFixture(t, nil)

	view, location, err := fx.pages.Open(context.Background(), "https://gw.example", fx.ticket, "")

	require.NoError(t, err)
	require.Nil(t, view)
	require.Equal(t, "https://idp.example/authorize?state=s", location)
	back, err := url.Parse(fx.signIn.returnTo)
	require.NoError(t, err)
	require.Equal(t, "https://gw.example"+PersonalKeyReturnPath, back.Scheme+"://"+back.Host+back.Path)
	require.Equal(t, fx.ticket, back.Query().Get("ticket"))
}

// A leaked link is useless to anyone else: they sign in as themselves, and the
// page says the link is not theirs.
func TestPersonalKeyPage_RefusesABrowserSignedInAsSomeoneElse(t *testing.T) {
	fx := newPersonalKeyFixture(t, nil)

	_, err := fx.signInAs(t, BrowserIdentity{Subject: "mallory", Email: "mallory@evil.test", GatewayID: fx.gw})

	var wrong *PersonalKeyWrongAccountError
	require.ErrorAs(t, err, &wrong)
	require.Equal(t, "mallory@evil.test", wrong.Email)
	require.Empty(t, fx.store.sessions)

	_, err = fx.signInAs(t, BrowserIdentity{Subject: "alice", GatewayID: ids.New[ids.GatewayKind]().String()})
	require.ErrorAs(t, err, &wrong, "the same person on another gateway is not this link's")
}

// Signed in as its owner, the page creates the key with the groups the
// sign-in carried, shows the secret once, and spends the link.
func TestPersonalKeyPage_CreatesTheKeyOnceAndSpendsTheLink(t *testing.T) {
	fx := newPersonalKeyFixture(t, nil)
	ctx := context.Background()
	session, err := fx.signInAs(t, fx.alice())
	require.NoError(t, err)

	view, location, err := fx.pages.Open(ctx, "https://gw.example", fx.ticket, session)
	require.NoError(t, err)
	require.Empty(t, location)
	require.Nil(t, view.Key)
	require.Equal(t, "alice@acme.test", view.Email)
	require.Equal(t, "https://gw.example/store/mcp", view.MCPURL)
	require.NotEmpty(t, view.CSRF)

	_, err = fx.pages.Act(ctx, fx.ticket, session, "forged", PersonalKeyActionCreate)
	require.ErrorIs(t, err, ErrPersonalKeyNotSignedIn, "a form that did not come from the page is refused")
	require.Nil(t, fx.issuer.key)

	done, err := fx.pages.Act(ctx, fx.ticket, session, view.CSRF, PersonalKeyActionCreate)
	require.NoError(t, err)
	require.Equal(t, "ag_secret", done.Secret)
	require.True(t, done.Done)
	require.Equal(t, "ag_ab", done.Key.Prefix)
	require.Equal(t, []string{"eng"}, fx.issuer.groups)

	_, _, err = fx.pages.Open(ctx, "https://gw.example", fx.ticket, session)
	require.ErrorIs(t, err, ErrPersonalKeyLinkGone, "the secret is shown once: the link does not open again")
}

func TestPersonalKeyPage_ShowsAKeyThatAlreadyExistsInsteadOfFailing(t *testing.T) {
	fx := newPersonalKeyFixture(t, nil)
	expires := time.Now().Add(time.Hour)
	fx.issuer.key = &appauth.PersonalKey{Auth: &authdomain.Auth{KeyPrefix: "ag_ol", KeySuffix: "dd", ExpiresAt: &expires}}
	session, err := fx.signInAs(t, fx.alice())
	require.NoError(t, err)
	view, _, err := fx.pages.Open(context.Background(), "https://gw.example", fx.ticket, session)
	require.NoError(t, err)

	got, err := fx.pages.Act(context.Background(), fx.ticket, session, view.CSRF, PersonalKeyActionCreate)

	require.NoError(t, err)
	require.False(t, got.Done)
	require.Empty(t, got.Secret)
	require.Equal(t, "ag_ol", got.Key.Prefix)
	require.Contains(t, got.Notice, "already have a personal key")
}

func TestPersonalKeyPage_RotatesAndRevokes(t *testing.T) {
	for _, tc := range []struct {
		action string
		check  func(t *testing.T, v *PersonalKeyView, issuer *fakeIssuer)
	}{
		{PersonalKeyActionRotate, func(t *testing.T, v *PersonalKeyView, issuer *fakeIssuer) {
			require.Equal(t, "ag_rotated", v.Secret)
			require.Equal(t, 1, issuer.rotated)
		}},
		{PersonalKeyActionRevoke, func(t *testing.T, v *PersonalKeyView, issuer *fakeIssuer) {
			require.True(t, v.Revoked)
			require.Empty(t, v.Secret)
			require.Nil(t, issuer.key)
		}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			fx := newPersonalKeyFixture(t, nil)
			expires := time.Now().Add(time.Hour)
			fx.issuer.key = &appauth.PersonalKey{Auth: &authdomain.Auth{KeyPrefix: "ag_ol", ExpiresAt: &expires}}
			session, err := fx.signInAs(t, fx.alice())
			require.NoError(t, err)
			view, _, err := fx.pages.Open(context.Background(), "https://gw.example", fx.ticket, session)
			require.NoError(t, err)

			got, err := fx.pages.Act(context.Background(), fx.ticket, session, view.CSRF, tc.action)

			require.NoError(t, err)
			require.True(t, got.Done)
			tc.check(t, got, fx.issuer)
		})
	}
}

func TestPersonalKeyPage_SaysWhyAKeyCannotBeIssuedHere(t *testing.T) {
	fx := newPersonalKeyFixture(t, nil)
	fx.issuer.err = consumerdomain.ErrHybridPersonal
	session, err := fx.signInAs(t, fx.alice())
	require.NoError(t, err)
	view, _, _ := fx.pages.Open(context.Background(), "https://gw.example", fx.ticket, session)

	got, err := fx.pages.Act(context.Background(), fx.ticket, session, view.CSRF, PersonalKeyActionCreate)

	require.NoError(t, err)
	require.True(t, strings.Contains(got.Unavailable, "not available"))
	require.False(t, got.Done)
}

// The Portal's budget: changes stop once one person has made too many.
func TestPersonalKeyPage_HonoursTheChangeBudget(t *testing.T) {
	fx := newPersonalKeyFixture(t, refusingLimiter{})
	session, err := fx.signInAs(t, fx.alice())
	require.NoError(t, err)
	view, _, _ := fx.pages.Open(context.Background(), "https://gw.example", fx.ticket, session)

	_, err = fx.pages.Act(context.Background(), fx.ticket, session, view.CSRF, PersonalKeyActionCreate)

	var exceeded *ConnectRateLimitExceeded
	require.True(t, errors.As(err, &exceeded))
	require.Nil(t, fx.issuer.key)
}
