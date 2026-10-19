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

package auth_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	sessionrevocation "github.com/NeuralTrust/TrustGate/pkg/domain/sessionrevocation"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type fakeSubjectSessions struct {
	revoked int
	err     error
	calls   int
	org     string
	gateway string
	subject string
}

func (f *fakeSubjectSessions) RevokeSubjectSessions(_ context.Context, org, gatewayID, subject string) (int, error) {
	f.calls++
	f.org, f.gateway, f.subject = org, gatewayID, subject
	if f.err != nil {
		return 0, f.err
	}
	return f.revoked, nil
}

type fakeDurableRevocations struct {
	err   error
	calls int
}

func (f *fakeDurableRevocations) Upsert(context.Context, string, string, string, time.Time) error {
	f.calls++
	return f.err
}

func (f *fakeDurableRevocations) ListActive(context.Context, time.Time) ([]sessionrevocation.Record, error) {
	return nil, nil
}

func subjectSessionsApp(sessions appoauth.SubjectSessions, identity middleware.AdminIdentity) *fiber.App {
	return subjectSessionsAppFull(sessions, &fakeDurableRevocations{}, &configsynctest.FakeSignaler{}, identity)
}

func subjectSessionsAppFull(sessions appoauth.SubjectSessions, revocations sessionrevocation.Store, signaler *configsynctest.FakeSignaler, identity middleware.AdminIdentity) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		middleware.StoreAdminIdentity(c, identity)
		return c.Next()
	})
	h := authhttp.NewDeleteSubjectSessionsHandler(sessions, revocations, signaler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.Delete("/v1/gateways/:gateway_id/subjects/:user_id/sessions", h.Handle)
	return app
}

func deleteSubjectSessions(t *testing.T, app *fiber.App, gatewayID, userID string) (int, string) {
	t.Helper()
	return deleteSubjectSessionsRaw(t, app, gatewayID, userID, false)
}

// deleteSubjectSessionsRaw sends the delete. rawUser leaves userID unescaped so
// a whitespace character reaches the handler: Fiber does not unescape path
// params, and a percent-encoded space is a different identifier.
func deleteSubjectSessionsRaw(t *testing.T, app *fiber.App, gatewayID, userID string, rawUser bool) (int, string) {
	t.Helper()
	segment := url.PathEscape(userID)
	if rawUser {
		segment = userID
	}
	path := "/v1/gateways/" + url.PathEscape(gatewayID) + "/subjects/" + segment + "/sessions"
	req := httptest.NewRequest(http.MethodDelete, "http://example.com/v1/gateways/"+url.PathEscape(gatewayID)+"/subjects/placeholder/sessions", nil)
	req.RequestURI = path
	res, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func TestDeleteSubjectSessions_RevokesAndRepeatsAsZero(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	sessions := &fakeSubjectSessions{revoked: 2}
	revocations := &fakeDurableRevocations{}
	signaler := &configsynctest.FakeSignaler{}
	app := subjectSessionsAppFull(sessions, revocations, signaler, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "org-1"})

	status, raw := deleteSubjectSessions(t, app, gw.String(), "user-1")
	require.Equal(t, http.StatusOK, status, raw)
	require.JSONEq(t, `{"revoked":2,"recorded":true}`, raw)
	require.Equal(t, 1, sessions.calls)
	require.Equal(t, "org-1", sessions.org)
	require.Equal(t, gw.String(), sessions.gateway)
	require.Equal(t, "user-1", sessions.subject)
	require.Equal(t, 1, revocations.calls)
	require.Equal(t, 1, signaler.Count())

	sessions.revoked = 0
	status, raw = deleteSubjectSessions(t, app, gw.String(), "user-1")
	require.Equal(t, http.StatusOK, status, raw)
	require.JSONEq(t, `{"revoked":0,"recorded":true}`, raw)
	require.Equal(t, 2, revocations.calls)
	require.Equal(t, 2, signaler.Count())
}

func TestDeleteSubjectSessions_DurableWriteFailureIs500(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	sessions := &fakeSubjectSessions{revoked: 1}
	revocations := &fakeDurableRevocations{err: errors.New("db down")}
	signaler := &configsynctest.FakeSignaler{}
	app := subjectSessionsAppFull(sessions, revocations, signaler, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "org-1"})

	status, raw := deleteSubjectSessions(t, app, gw.String(), "user-1")
	require.Equal(t, http.StatusInternalServerError, status, raw)
	require.Contains(t, raw, `"error":"internal_error"`)
	require.NotContains(t, raw, `"recorded"`)
	require.Equal(t, 1, revocations.calls)
	require.Equal(t, 0, sessions.calls, "redis is not touched when the durable write fails")
	require.Equal(t, 0, signaler.Count())
}

func TestDeleteSubjectSessions_ErrorStatuses(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	human := middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "org-1"}
	for name, tc := range map[string]struct {
		identity   middleware.AdminIdentity
		gatewayID  string
		userID     string
		sessions   *fakeSubjectSessions
		rawUser    bool
		wantStatus int
		wantCode   string
		wantCalls  int
	}{
		"empty tenant": {
			identity:   middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman},
			gatewayID:  gw.String(),
			userID:     "user-1",
			sessions:   &fakeSubjectSessions{revoked: 1},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		"platform token without a tenant": {
			identity:   middleware.AdminIdentity{Kind: middleware.AdminIdentityPlatform},
			gatewayID:  gw.String(),
			userID:     "user-1",
			sessions:   &fakeSubjectSessions{revoked: 1},
			wantStatus: http.StatusForbidden,
			wantCode:   "forbidden",
		},
		"invalid gateway": {
			identity:   human,
			gatewayID:  "not-a-uuid",
			userID:     "user-1",
			sessions:   &fakeSubjectSessions{revoked: 1},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_uuid",
		},
		"whitespace user id": {
			identity:   human,
			gatewayID:  gw.String(),
			userID:     "\u00a0",
			rawUser:    true,
			sessions:   &fakeSubjectSessions{revoked: 1},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "validation_failed",
		},
		"user id too long": {
			identity:   human,
			gatewayID:  gw.String(),
			userID:     strings.Repeat("a", 257),
			sessions:   &fakeSubjectSessions{revoked: 1},
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "validation_failed",
		},
		"store error": {
			identity:   human,
			gatewayID:  gw.String(),
			userID:     "user-1",
			sessions:   &fakeSubjectSessions{err: errors.New("redis down")},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "internal_error",
			wantCalls:  1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			status, raw := deleteSubjectSessionsRaw(t, subjectSessionsApp(tc.sessions, tc.identity), tc.gatewayID, tc.userID, tc.rawUser)
			require.Equal(t, tc.wantStatus, status, raw)
			require.Contains(t, raw, `"error":"`+tc.wantCode+`"`)
			require.Equal(t, tc.wantCalls, tc.sessions.calls)
		})
	}
}
