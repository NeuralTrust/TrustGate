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
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func budgetApp(repo domain.Repository, publisher cache.EventPublisher, signaler *configsynctest.FakeSignaler) *fiber.App {
	setter := appauth.NewBudgetSetter(repo, cache.NewTTLMapManager(time.Hour), publisher, slog.New(slog.DiscardHandler), signaler, nil)
	app := fiber.New()
	app.Put("/gateways/:gateway_id/auths/:id/budget", authhttp.NewUpdateAuthBudgetHandler(setter, nil).Handle)
	return app
}

func budgetURL(gwID ids.GatewayID, id string) string {
	return "/gateways/" + gwID.String() + "/auths/" + id + "/budget"
}

func TestUpdateAuthBudget_SetsAndClearsTheBudgetOfAnOwnedKey(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body       string
		budget     *domain.KeyBudget
		wantInBody string
	}{
		"set":   {body: `{"max":50,"time_window":"calendar_month"}`, budget: &domain.KeyBudget{Max: 50, TimeWindow: domain.BudgetWindowCalendarMonth}, wantInBody: `"budget":{"max":50,"time_window":"calendar_month"}`},
		"clear": {body: `null`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			owned := testAPIKeyAuth(t, gwID, "personal-alice", "alice")
			owned.Budget = &domain.KeyBudget{Max: 1, TimeWindow: domain.BudgetWindowCalendarDay}
			hash, expiry := owned.KeyHash, owned.ExpiresAt
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, owned.ID).Return(owned, nil).Once()
			repo.EXPECT().UpdateBudget(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
				return a.ID == owned.ID && a.KeyHash == hash && a.ExpiresAt == expiry &&
					(tc.budget == nil && a.Budget == nil || tc.budget != nil && a.Budget != nil && *a.Budget == *tc.budget)
			})).RunAndReturn(func(_ context.Context, a *domain.Auth) (*domain.Auth, error) { return a, nil }).Once()
			publisher := cachemocks.NewEventPublisher(t)
			publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()
			signaler := &configsynctest.FakeSignaler{}

			status, raw := doJSON(t, budgetApp(repo, publisher, signaler), http.MethodPut, budgetURL(gwID, owned.ID.String()), tc.body)
			require.Equal(t, http.StatusOK, status, raw)
			require.Contains(t, raw, `"owner_id":"alice"`)
			require.NotContains(t, raw, hash)
			require.NotContains(t, raw, `"api_key":`)
			if tc.wantInBody == "" {
				require.NotContains(t, raw, `"budget"`)
			} else {
				require.Contains(t, raw, tc.wantInBody)
			}
			require.Equal(t, 1, signaler.Count())
		})
	}
}

func TestUpdateAuthBudget_RefusesWithoutWriting(t *testing.T) {
	t.Parallel()
	const monthly = `{"max":50,"time_window":"calendar_month"}`
	for name, tc := range map[string]struct {
		body       string
		auth       func(t *testing.T, gwID ids.GatewayID) *domain.Auth
		notFound   bool
		badID      bool
		wantStatus int
		wantCode   string
	}{
		"application key":         {body: monthly, auth: func(t *testing.T, gwID ids.GatewayID) *domain.Auth { return testAPIKeyAuth(t, gwID, "ci", "") }, wantStatus: http.StatusUnprocessableEntity, wantCode: "application_key"},
		"clearing an application": {body: `null`, auth: func(t *testing.T, gwID ids.GatewayID) *domain.Auth { return testAPIKeyAuth(t, gwID, "ci", "") }, wantStatus: http.StatusUnprocessableEntity, wantCode: "application_key"},
		"unknown auth":            {body: monthly, notFound: true, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		"another gateway's key": {body: monthly, auth: func(t *testing.T, _ ids.GatewayID) *domain.Auth {
			return testAPIKeyAuth(t, ids.New[ids.GatewayKind](), "personal-alice", "alice")
		}, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		"zero max":          {body: `{"max":0,"time_window":"calendar_month"}`, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"negative max":      {body: `{"max":-5,"time_window":"calendar_day"}`, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"rolling window":    {body: `{"max":50,"time_window":"24h"}`, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"no window":         {body: `{"max":50}`, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"empty object":      {body: `{}`, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"no body":           {body: ``, wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"max as a string":   {body: `{"max":"50","time_window":"calendar_month"}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"max out of range":  {body: `{"max":1e400,"time_window":"calendar_month"}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"not an object":     {body: `[50]`, wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"malformed auth id": {body: monthly, badID: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_uuid"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			repo := repomocks.NewRepository(t)
			id := ids.New[ids.AuthKind]().String()
			switch {
			case tc.badID:
				id = "not-a-uuid"
			case tc.notFound:
				repo.EXPECT().FindByID(mock.Anything, mock.Anything).Return(nil, domain.ErrNotFound).Once()
			case tc.auth != nil:
				a := tc.auth(t, gwID)
				id = a.ID.String()
				repo.EXPECT().FindByID(mock.Anything, a.ID).Return(a, nil).Once()
			}
			signaler := &configsynctest.FakeSignaler{}

			status, raw := doJSON(t, budgetApp(repo, cachemocks.NewEventPublisher(t), signaler), http.MethodPut, budgetURL(gwID, id), tc.body)
			require.Equal(t, tc.wantStatus, status, raw)
			require.Contains(t, raw, `"error":"`+tc.wantCode+`"`)
			require.Zero(t, signaler.Count())
		})
	}
}

func ownedBy(owner string) func(t *testing.T, gwID ids.GatewayID) *domain.Auth {
	return func(t *testing.T, gwID ids.GatewayID) *domain.Auth {
		return testAPIKeyAuth(t, gwID, "personal-"+owner, owner)
	}
}

func TestListAuths_OwnedListsEveryPersonalKey(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	alice, bob := testAPIKeyAuth(t, gwID, "personal-alice", "alice"), testAPIKeyAuth(t, gwID, "personal-bob", "bob")
	alice.Budget = &domain.KeyBudget{Max: 50, TimeWindow: domain.BudgetWindowCalendarMonth}
	for name, tc := range map[string]struct {
		query      string
		wantFilter func(domain.ListFilter) bool
		listed     []*domain.Auth
	}{
		"owned=true lists every owner's key": {
			query: "?owned=true&page=2&size=1",
			wantFilter: func(f domain.ListFilter) bool {
				return f.OnlyOwned && !f.ExcludeOwned && f.OwnerID == "" && f.Page.Number == 2 && f.Page.Size == 1
			},
			listed: []*domain.Auth{alice, bob},
		},
		"owned=false lists application keys": {
			query:      "?owned=false",
			wantFilter: func(f domain.ListFilter) bool { return !f.OnlyOwned && f.ExcludeOwned && f.OwnerID == "" },
		},
		"owner_id keeps listing one owner": {
			query:      "?owner_id=alice",
			wantFilter: func(f domain.ListFilter) bool { return !f.OnlyOwned && !f.ExcludeOwned && f.OwnerID == "alice" },
			listed:     []*domain.Auth{alice},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			finder := appauthmocks.NewFinder(t)
			finder.EXPECT().List(mock.Anything, mock.MatchedBy(func(f domain.ListFilter) bool {
				return f.GatewayID == gwID && tc.wantFilter(f)
			})).Return(tc.listed, len(tc.listed), nil).Once()
			app := fiber.New()
			app.Get("/gateways/:gateway_id/auths", authhttp.NewListAuthHandler(finder, nil).Handle)

			status, raw := doJSON(t, app, http.MethodGet, "/gateways/"+gwID.String()+"/auths"+tc.query, "")
			require.Equal(t, http.StatusOK, status, raw)
			for _, a := range tc.listed {
				require.Contains(t, raw, `"owner_id":"`+a.OwnerID+`"`)
			}
			if len(tc.listed) > 0 {
				require.Contains(t, raw, `"budget":{"max":50,"time_window":"calendar_month"}`)
				require.Equal(t, 1, strings.Count(raw, `"budget"`), "only the key with a budget carries one")
			}
		})
	}
}

func TestListAuths_RefusesOwnedWithAnOwner(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	app := fiber.New()
	app.Get("/gateways/:gateway_id/auths", authhttp.NewListAuthHandler(appauthmocks.NewFinder(t), nil).Handle)
	for _, query := range []string{"?owned=true&owner_id=alice", "?owned=false&owner_id=alice", "?owned=maybe"} {
		status, raw := doJSON(t, app, http.MethodGet, "/gateways/"+gwID.String()+"/auths"+query, "")
		require.Equal(t, http.StatusUnprocessableEntity, status, query)
		require.Contains(t, raw, `"error":"invalid_filter"`, query)
	}
}
