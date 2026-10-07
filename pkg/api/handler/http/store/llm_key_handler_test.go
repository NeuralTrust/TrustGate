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

var alice = middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "t1", Subject: "alice"}

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
	return app
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
	}
}

func TestLLMKeyHandler_ActsOnTheCallerAndShowsTheSecretOnlyWhenIssued(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	expiry := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	a, err := domain.NewOwnedAPIKeyAuth(gw, "alice", time.Now().Add(time.Hour), time.Now())
	require.NoError(t, err)
	key := &appauth.PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}
	keys := appauthmocks.NewPersonalKeys(t)
	keys.EXPECT().Create(mock.Anything, gw, "alice", mock.MatchedBy(expiry.Equal)).Return(key, nil).Once()
	keys.EXPECT().Get(mock.Anything, gw, "alice").Return(key, nil).Once()
	keys.EXPECT().Rotate(mock.Anything, gw, "alice", mock.MatchedBy(func(at *time.Time) bool { return at != nil && at.Equal(expiry) })).Return(key, nil).Once()
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
	cases := map[string]struct {
		method, suffix, body string
		plain                bool
		expect               func(m *appauthmocks.PersonalKeys)
		want                 int
		says, hides          string
	}{
		"create without expires_at":          {method: http.MethodPost, body: `{}`, want: http.StatusUnprocessableEntity, says: "expires_at is required"},
		"create with a malformed expires_at": {method: http.MethodPost, body: `{"expires_at":"soon"}`, want: http.StatusUnprocessableEntity, says: "expires_at must be an RFC 3339 instant"},
		"create with an empty body":          {method: http.MethodPost, plain: true, want: http.StatusUnprocessableEntity},
		"create without a content type":      {method: http.MethodPost, body: validLLMKeyBody, plain: true, want: http.StatusUnprocessableEntity},
		"rotate with a malformed body":       {method: http.MethodPost, suffix: "/rotate", body: `{"expires_at":1}`, want: http.StatusUnprocessableEntity},
		"create a second key": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusConflict, says: "Rotate or revoke it instead", expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, "alice", mock.Anything).Return(nil, domain.ErrOwnedKeyExists).Once()
		}},
		"create out of range": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, "alice", mock.Anything).Return(nil, domain.ErrOwnedExpiry).Once()
		}},
		"create on a hybrid gateway": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, "alice", mock.Anything).Return(nil, consumerdomain.ErrHybridPersonal).Once()
		}},
		"create failing unexpectedly": {method: http.MethodPost, body: validLLMKeyBody, want: http.StatusInternalServerError, hides: "10.0.0.7", expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Create(mock.Anything, mock.Anything, "alice", mock.Anything).Return(nil, errors.New("dial tcp 10.0.0.7:5432: refused")).Once()
		}},
		"get without a key": {method: http.MethodGet, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Get(mock.Anything, mock.Anything, "alice").Return(nil, domain.ErrNotFound).Once()
		}},
		"rotate without a body or a key": {method: http.MethodPost, suffix: "/rotate", plain: true, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", noExpiry).Return(nil, domain.ErrNotFound).Once()
		}},
		"rotate an expired key with an empty body": {method: http.MethodPost, suffix: "/rotate", body: `{}`, want: http.StatusUnprocessableEntity, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", noExpiry).Return(nil, domain.ErrOwnedExpiry).Once()
		}},
		"rotate with a null expires_at": {method: http.MethodPost, suffix: "/rotate", body: `{"expires_at":null}`, want: http.StatusNotFound, expect: func(m *appauthmocks.PersonalKeys) {
			m.EXPECT().Rotate(mock.Anything, mock.Anything, "alice", noExpiry).Return(nil, domain.ErrNotFound).Once()
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
