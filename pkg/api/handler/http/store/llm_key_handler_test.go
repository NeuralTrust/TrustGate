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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const validLLMKeyBody = `{"expires_at":"2099-01-01T00:00:00Z"}`

var alice = middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "t1", Subject: "alice", Email: "alice@acme.test"}

func newLLMKeyApp(keys appauth.PersonalKeys, identity middleware.AdminIdentity) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		middleware.StoreAdminIdentity(c, identity)
		return c.Next()
	})
	h := storehttp.NewLLMKeyHandler(keys)
	const path = "/v1/gateways/:gateway_id/store/principal/llm-key"
	app.Get(path, h.Get)
	app.Post(path, h.Create)
	app.Post(path+"/rotate", h.Rotate)
	app.Delete(path, h.Revoke)
	app.Post("/v1/gateways/:gateway_id/store/users/:user_id/llm-key", h.CreateForUser)
	return app
}

func callUserLLMKey(t *testing.T, app *fiber.App, gw ids.GatewayID, userID, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/gateways/"+gw.String()+"/store/users/"+userID+"/llm-key", strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func callLLMKey(t *testing.T, app *fiber.App, method string, gw ids.GatewayID, suffix, body, contentType string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, "/v1/gateways/"+gw.String()+"/store/principal/llm-key"+suffix, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set(fiber.HeaderContentType, contentType)
	}
	res, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func TestLLMKeyHandler_RefusesCallersWithoutATenantUser(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	for name, identity := range map[string]middleware.AdminIdentity{
		"service credential": {Kind: middleware.AdminIdentityService, TenantID: "t1", GatewayID: gw.String(), Subject: "svc", Scopes: []string{"registries:read", "registries:write"}},
		"platform token":     {Kind: middleware.AdminIdentityPlatform, Subject: "alice"},
		"no subject":         {Kind: middleware.AdminIdentityHuman, TenantID: "t1"},
	} {
		app := newLLMKeyApp(appauthmocks.NewPersonalKeys(t), identity)
		for _, route := range [][2]string{{http.MethodGet, ""}, {http.MethodPost, ""}, {http.MethodPost, "/rotate"}, {http.MethodDelete, ""}} {
			status, raw := callLLMKey(t, app, route[0], gw, route[1], validLLMKeyBody, fiber.MIMEApplicationJSON)
			require.Equal(t, http.StatusForbidden, status, "%s on %s %s: %s", name, route[0], route[1], raw)
		}
		status, raw := callUserLLMKey(t, app, gw, "bob", validLLMKeyBody)
		require.Equal(t, http.StatusForbidden, status, "%s creating another user's key: %s", name, raw)
	}
}

// A token whose email is not an address still gets its key, without one.
func TestLLMKeyHandler_CreatesWithoutAnEmailThatIsNotOne(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	a, err := domain.NewOwnedAPIKeyAuth(gw, "alice", domain.KeyGroup{}, ptr(time.Now().Add(time.Hour)), time.Now())
	require.NoError(t, err)
	keys := appauthmocks.NewPersonalKeys(t)
	keys.EXPECT().Create(mock.Anything, gw, appauth.PersonalKeyOwner{ID: "alice"}, domain.KeyGroup{}, mock.Anything).Return(&appauth.PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}, nil).Once()
	caller := alice
	caller.Email = "alice at acme"

	status, raw := callLLMKey(t, newLLMKeyApp(keys, caller), http.MethodPost, gw, "", validLLMKeyBody, fiber.MIMEApplicationJSON)

	require.Equal(t, http.StatusCreated, status, raw)
}

func TestLLMKeyHandler_ActsOnTheCallerAndShowsTheSecretOnlyWhenIssued(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	expiry := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := domain.NewOwnedAPIKeyAuth(gw, "alice", domain.KeyGroup{}, ptr(time.Now().Add(time.Hour)), time.Now())
	require.NoError(t, err)
	key := &appauth.PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}
	keys := appauthmocks.NewPersonalKeys(t)
	keys.EXPECT().Create(mock.Anything, gw, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, mock.MatchedBy(expiresAt(expiry))).Return(key, nil).Once()
	keys.EXPECT().Get(mock.Anything, gw, "alice").Return(key, nil).Once()
	keys.EXPECT().Rotate(mock.Anything, gw, "alice", mock.MatchedBy(func(e *appauth.ExpiryChange) bool { return e != nil && e.At != nil && e.At.Equal(expiry) })).Return(key, nil).Once()
	app := newLLMKeyApp(keys, alice)

	status, raw := callLLMKey(t, app, http.MethodPost, gw, "",
		`{"expires_at":"2099-01-01T00:00:00Z","owner_id":"bob","principal_sub":"bob","consumer_id":"`+ids.New[ids.ConsumerKind]().String()+`"}`, fiber.MIMEApplicationJSON)
	require.Equal(t, http.StatusCreated, status, raw)
	require.Contains(t, raw, `"api_key":"`+a.RawKey+`"`)
	require.Contains(t, raw, `"consumer_ids":[]`)
	require.NotContains(t, raw, "bob")

	status, raw = callLLMKey(t, app, http.MethodGet, gw, "", "", "")
	require.Equal(t, http.StatusOK, status, raw)
	require.NotContains(t, raw, `"api_key":`)
	require.NotContains(t, raw, a.RawKey)
	require.NotContains(t, raw, a.KeyHash)

	status, raw = callLLMKey(t, app, http.MethodPost, gw, "/rotate", validLLMKeyBody, fiber.MIMEApplicationJSON)
	require.Equal(t, http.StatusOK, status, raw)
	require.Contains(t, raw, `"api_key":"`+a.RawKey+`"`)
}

func TestLLMKeyHandler_StatusCodes(t *testing.T) {
	t.Parallel()
	noExpiry := (*time.Time)(nil)
	keepExpiry := (*appauth.ExpiryChange)(nil)
	cases := map[string]struct {
		method, suffix, body string
		plain                bool
		expect               func(m *appauthmocks.PersonalKeys)
		want                 int
		says, hides          string
	}{
		"create without expires_at never expires": {method: http.MethodPost, body: `{}`, want: http.StatusConflict, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, noExpiry).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"create with a null expires_at never expires": {method: http.MethodPost, body: `{"expires_at":null}`, want: http.StatusConflict, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, noExpiry).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"create with an empty body never expires": {method: http.MethodPost, plain: true, want: http.StatusConflict, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, noExpiry).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"create with a malformed expires_at":            {method: http.MethodPost, body: `{"expires_at":"soon"}`, want: http.StatusUnprocessableEntity, says: "expires_at must be an RFC 3339 instant"},
		"create without a content type":                 {method: http.MethodPost, body: validLLMKeyBody, plain: true, want: http.StatusUnprocessableEntity},
		"rotate with a malformed body":                  {method: http.MethodPost, suffix: "/rotate", body: `{"expires_at":1}`, want: http.StatusUnprocessableEntity},
		"rotate with both expires_at and never_expires": {method: http.MethodPost, suffix: "/rotate", body: `{"expires_at":"2099-01-01T00:00:00Z","never_expires":true}`, want: http.StatusUnprocessableEntity, says: "cannot be combined"},
		"rotate to never expire": {method: http.MethodPost, suffix: "/rotate", body: `{"never_expires":true}`, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", &appauth.ExpiryChange{}).Return(nil, domain.ErrNotFound).Once()
		}},
		"rotate with never_expires false keeps the expiry": {method: http.MethodPost, suffix: "/rotate", body: `{"never_expires":false}`, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", keepExpiry).Return(nil, domain.ErrNotFound).Once()
		}},
		"create a second key": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusConflict, says: "Rotate or revoke it instead", expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, mock.Anything).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"create out of range": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, mock.Anything).Return(nil, domain.ErrOwnedExpiry).Once()
		}},
		"create on a hybrid gateway": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, mock.Anything).Return(nil, consumerdomain.ErrHybridPersonal).Once()
		}},
		"create failing unexpectedly": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusInternalServerError, hides: "10.0.0.7", expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, domain.KeyGroup{}, mock.Anything).Return(nil, errors.New("dial tcp 10.0.0.7:5432: refused")).Once()
		}},
		"get without a key": {method: http.MethodGet, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Get(mock.Anything, mock.Anything, "alice").Return(nil, domain.ErrNotFound).Once()
		}},
		"rotate without a body or a key": {method: http.MethodPost, suffix: "/rotate", plain: true, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", keepExpiry).Return(nil, domain.ErrNotFound).Once()
		}},
		"rotate an expired key with an empty body": {method: http.MethodPost, suffix: "/rotate", body: `{}`, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", keepExpiry).Return(nil, domain.ErrOwnedExpiry).Once()
		}},
		"rotate with a null expires_at": {method: http.MethodPost, suffix: "/rotate", body: `{"expires_at":null}`, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", keepExpiry).Return(nil, domain.ErrNotFound).Once()
		}},
		"revoke": {method: http.MethodDelete, want: http.StatusNoContent, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Revoke(mock.Anything, mock.Anything, "alice").Return(nil).Once()
		}},
		"revoke without a key": {method: http.MethodDelete, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Revoke(mock.Anything, mock.Anything, "alice").Return(domain.ErrNotFound).Once()
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys := appauthmocks.NewPersonalKeys(t)
			if tc.expect != nil {
				tc.expect(keys)
			}
			contentType := fiber.MIMEApplicationJSON
			if tc.plain {
				contentType = ""
			}
			status, raw := callLLMKey(t, newLLMKeyApp(keys, alice), tc.method, ids.New[ids.GatewayKind](), tc.suffix, tc.body, contentType)
			require.Equal(t, tc.want, status, raw)
			require.Contains(t, raw, tc.says)
			if tc.hides != "" {
				require.NotContains(t, raw, tc.hides)
			}
		})
	}
}

// An admin issues bob's key: it is bob's, under bob's email, whoever asked.
func TestLLMKeyHandler_CreatesAnotherUsersKeyForTheAdmin(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	expiry := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := domain.NewOwnedAPIKeyAuth(gw, "bob", domain.KeyGroup{}, ptr(time.Now().Add(time.Hour)), time.Now())
	require.NoError(t, err)
	keys := appauthmocks.NewPersonalKeys(t)
	keys.EXPECT().Create(mock.Anything, gw, appauth.PersonalKeyOwner{ID: "bob", Email: "bob@acme.test"}, domain.KeyGroup{}, mock.MatchedBy(expiresAt(expiry))).
		Return(&appauth.PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}, nil).Once()

	status, raw := callUserLLMKey(t, newLLMKeyApp(keys, alice), gw, "bob", `{"expires_at":"2099-01-01T00:00:00Z","owner_email":"bob@acme.test","owner_id":"carol"}`)

	require.Equal(t, http.StatusCreated, status, raw)
	require.Contains(t, raw, `"api_key":"`+a.RawKey+`"`)
	require.Contains(t, raw, `"consumer_ids":[]`)
	require.NotContains(t, raw, "carol")
}

func TestLLMKeyHandler_CreateForUserStatusCodes(t *testing.T) {
	t.Parallel()
	bob := appauth.PersonalKeyOwner{ID: "bob"}
	cases := map[string]struct {
		body   string
		expect func(m *appauthmocks.PersonalKeys)
		want   int
		says   string
	}{
		"without expires_at never expires": {body: `{"owner_email":"bob@acme.test"}`, want: http.StatusConflict, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "bob", Email: "bob@acme.test"}, domain.KeyGroup{}, (*time.Time)(nil)).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"with a malformed expires_at": {body: `{"expires_at":"soon"}`, want: http.StatusUnprocessableEntity, says: "expires_at must be an RFC 3339 instant"},
		"with a malformed body":       {body: `{"owner_email":1}`, want: http.StatusUnprocessableEntity},
		"for a user who has a key": {body: validLLMKeyBody, want: http.StatusConflict, says: "already exists", expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, bob, domain.KeyGroup{}, mock.Anything).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"with an email that is not one": {body: `{"expires_at":"2099-01-01T00:00:00Z","owner_email":"bob at acme"}`, want: http.StatusUnprocessableEntity, says: "not an email address", expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, appauth.PersonalKeyOwner{ID: "bob", Email: "bob at acme"}, domain.KeyGroup{}, mock.Anything).
				Return(nil, fmt.Errorf("%w: %q is not an email address", domain.ErrInvalidOwnerEmail, "bob at acme")).Once()
		}},
		"on a hybrid gateway": {body: validLLMKeyBody, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, bob, domain.KeyGroup{}, mock.Anything).Return(nil, consumerdomain.ErrHybridPersonal).Once()
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keys := appauthmocks.NewPersonalKeys(t)
			if tc.expect != nil {
				tc.expect(keys)
			}
			status, raw := callUserLLMKey(t, newLLMKeyApp(keys, alice), ids.New[ids.GatewayKind](), "bob", tc.body)
			require.Equal(t, tc.want, status, raw)
			require.Contains(t, raw, tc.says)
		})
	}
}

func ptr[T any](v T) *T { return &v }

// expiresAt matches an expiry argument that is want.
func expiresAt(want time.Time) func(*time.Time) bool {
	return func(at *time.Time) bool { return at != nil && at.Equal(want) }
}
