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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func testAPIKeyAuth(t *testing.T, gwID ids.GatewayID, name, owner string) *domain.Auth {
	t.Helper()
	a, err := domain.NewAPIKeyAuth(gwID, name, true, nil)
	require.NoError(t, err)
	a.OwnerID, a.RawKey = owner, ""
	return a
}

func doJSON(t *testing.T, app *fiber.App, method, url, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	res, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func TestListAuths_HidesOwnedKeysUnlessAskedByOwner(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	application, owned := testAPIKeyAuth(t, gwID, "ci", ""), testAPIKeyAuth(t, gwID, "personal-alice", "alice")
	for name, tc := range map[string]struct{ query, ownerID string }{
		"default excludes owned keys":    {query: ""},
		"empty owner_id is the default":  {query: "?owner_id="},
		"owner_id lists the owner's key": {query: "?owner_id=alice", ownerID: "alice"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			listed := application
			if tc.ownerID != "" {
				listed = owned
			}
			finder := appauthmocks.NewFinder(t)
			finder.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
				return f.GatewayID == gwID && f.ExcludeOwned == (tc.ownerID == "") && f.OwnerID == tc.ownerID
			})).Return([]*domain.Auth{listed}, 1, nil).Once()
			app := fiber.New()
			app.Get("/gateways/:gateway_id/auths", authhttp.NewListAuthHandler(finder, nil).Handle)

			status, raw := doJSON(t, app, http.MethodGet, "/gateways/"+gwID.String()+"/auths"+tc.query, "")
			require.Equal(t, http.StatusOK, status)
			require.Contains(t, raw, `"total":1`)
			require.Contains(t, raw, `"id":"`+listed.ID.String()+`"`)
			if tc.ownerID == "" {
				require.NotContains(t, raw, "owner_id")
			} else {
				require.Contains(t, raw, `"owner_id":"alice"`)
			}
		})
	}
}

func TestGetAuth_ShowsTheOwnerWithoutTheSecret(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	owned := testAPIKeyAuth(t, gwID, "personal-alice", "alice")
	finder := appauthmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, owned.ID).Return(owned, nil).Once()
	app := fiber.New()
	app.Get("/gateways/:gateway_id/auths/:id", authhttp.NewGetAuthHandler(finder, nil).Handle)

	status, raw := doJSON(t, app, http.MethodGet, "/gateways/"+gwID.String()+"/auths/"+owned.ID.String(), "")
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, raw, `"owner_id":"alice"`)
	require.NotContains(t, raw, owned.KeyHash)
	require.NotContains(t, raw, `"api_key":`)
}

func TestUpdateAndRotateAuth_RefuseAnOwnedKey(t *testing.T) {
	t.Parallel()
	for name, route := range map[string]struct {
		method, suffix, body string
	}{
		"update": {method: http.MethodPut, body: `{"name":"renamed","enabled":false,"expires_at":"2030-01-01T00:00:00Z"}`},
		"rotate": {method: http.MethodPost, suffix: "/rotate", body: `{"expires_at":"2030-01-01T00:00:00Z"}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			owned := testAPIKeyAuth(t, gwID, "personal-alice", "alice")
			before := *owned
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, owned.ID).Return(owned, nil).Once()
			manager := cache.NewTTLMapManager(time.Hour)
			publisher, logger := cachemocks.NewEventPublisher(t), slog.New(slog.DiscardHandler)
			signaler := &configsynctest.FakeSignaler{}
			app := fiber.New()
			app.Put("/gateways/:gateway_id/auths/:id", authhttp.NewUpdateAuthHandler(
				appauth.NewUpdater(repo, consumermocks.NewRepository(t), manager, publisher, logger, signaler)).Handle)
			app.Post("/gateways/:gateway_id/auths/:id/rotate", authhttp.NewRotateAuthHandler(
				appauth.NewRotator(repo, manager, publisher, logger, signaler), nil).Handle)

			status, raw := doJSON(t, app, route.method, "/gateways/"+gwID.String()+"/auths/"+owned.ID.String()+route.suffix, route.body)
			require.Equal(t, http.StatusUnprocessableEntity, status)
			require.Contains(t, raw, `"error":"owned_key"`)
			require.Equal(t, before, *owned)
			require.Zero(t, signaler.Count())
		})
	}
}

func TestCreateAuth_IgnoresAnOwnerInTheBody(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
		return a.Name == "ci" && !a.IsOwned()
	})).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()
	creator := appauth.NewCreator(repo, cache.NewTTLMapManager(time.Hour), publisher, slog.New(slog.DiscardHandler), nil)
	app := fiber.New()
	app.Post("/gateways/:gateway_id/auths", authhttp.NewCreateAuthHandler(creator).Handle)

	status, raw := doJSON(t, app, http.MethodPost, "/gateways/"+gwID.String()+"/auths", `{"name":"ci","type":"api_key","owner_id":"alice"}`)
	require.Equal(t, http.StatusCreated, status)
	require.NotContains(t, raw, "owner_id")
}
