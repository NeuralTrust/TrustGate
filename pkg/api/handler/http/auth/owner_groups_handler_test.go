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
	"slices"
	"strings"
	"testing"
	"time"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
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

func ownerGroupsApp(repo domain.Repository, publisher cache.EventPublisher, signaler *configsynctest.FakeSignaler) *fiber.App {
	setter := appauth.NewOwnerGroupsSetter(repo, cache.NewTTLMapManager(time.Hour), publisher, slog.New(slog.DiscardHandler), signaler, nil)
	app := fiber.New()
	app.Put("/gateways/:gateway_id/auths/:id/groups", authhttp.NewUpdateAuthOwnerGroupsHandler(setter, unreached{}).Handle)
	return app
}

func ownerGroupsURL(gwID ids.GatewayID, id string) string {
	return "/gateways/" + gwID.String() + "/auths/" + id + "/groups"
}

func TestUpdateAuthOwnerGroups_RecordsAndClearsTheGroupsOfAnOwnedKey(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body       string
		want       []string
		wantInBody string
	}{
		"set, trimmed, deduplicated and sorted": {body: `{"groups":[" sre","engineering","sre",""]}`, want: []string{"engineering", "sre"}, wantInBody: `"owner_groups":["engineering","sre"]`},
		"clear":                                 {body: `{"groups":[]}`},
		"clear with no list":                    {body: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			owned := testAPIKeyAuth(t, gwID, "personal-alice", "alice")
			owned.OwnerGroups = []string{"old"}
			owned.Budget = &domain.KeyBudget{Max: 1, Unit: domain.BudgetUnitDollars, TimeWindow: domain.BudgetWindowCalendarDay}
			hash, expiry := owned.KeyHash, owned.ExpiresAt
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, owned.ID).Return(owned, nil).Once()
			repo.EXPECT().UpdateOwner(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
				return a.ID == owned.ID && a.KeyHash == hash && a.ExpiresAt == expiry && a.Budget != nil &&
					slices.Equal(a.OwnerGroups, tc.want)
			})).RunAndReturn(func(_ context.Context, a *domain.Auth) (*domain.Auth, error) { return a, nil }).Once()
			publisher := cachemocks.NewEventPublisher(t)
			publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()
			signaler := &configsynctest.FakeSignaler{}

			status, raw := doJSON(t, ownerGroupsApp(repo, publisher, signaler), http.MethodPut, ownerGroupsURL(gwID, owned.ID.String()), tc.body)
			require.Equal(t, http.StatusOK, status, raw)
			require.Contains(t, raw, `"owner_id":"alice"`)
			require.NotContains(t, raw, hash)
			if tc.wantInBody == "" {
				require.NotContains(t, raw, `"owner_groups"`)
			} else {
				require.Contains(t, raw, tc.wantInBody)
			}
			require.Equal(t, 1, signaler.Count())
		})
	}
}

// The platform sends the owner's email with their groups; a body without one
// leaves the email the key has, so a console that does not send it yet clears
// nothing.
func TestUpdateAuthOwnerGroups_RecordsTheOwnersEmailWhenSent(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body       string
		want       string
		wantInBody string
	}{
		"set, trimmed": {body: `{"groups":["eng"],"email":" alice@acme.test "}`, want: "alice@acme.test", wantInBody: `"owner_email":"alice@acme.test"`},
		"kept":         {body: `{"groups":["eng"]}`, want: "old@acme.test", wantInBody: `"owner_email":"old@acme.test"`},
		"cleared":      {body: `{"groups":["eng"],"email":""}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			owned := testAPIKeyAuth(t, gwID, "personal-alice", "alice")
			owned.OwnerEmail = "old@acme.test"
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, owned.ID).Return(owned, nil).Once()
			repo.EXPECT().UpdateOwner(mock.Anything, mock.MatchedBy(func(a *domain.Auth) bool {
				return a.ID == owned.ID && a.OwnerEmail == tc.want && slices.Equal(a.OwnerGroups, []string{"eng"})
			})).RunAndReturn(func(_ context.Context, a *domain.Auth) (*domain.Auth, error) { return a, nil }).Once()
			publisher := cachemocks.NewEventPublisher(t)
			publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).Return(nil).Once()

			status, raw := doJSON(t, ownerGroupsApp(repo, publisher, &configsynctest.FakeSignaler{}), http.MethodPut, ownerGroupsURL(gwID, owned.ID.String()), tc.body)
			require.Equal(t, http.StatusOK, status, raw)
			if tc.wantInBody == "" {
				require.NotContains(t, raw, `"owner_email"`)
			} else {
				require.Contains(t, raw, tc.wantInBody)
			}
		})
	}
}

func TestUpdateAuthOwnerGroups_RefusesWithoutWriting(t *testing.T) {
	t.Parallel()
	const groups = `{"groups":["engineering"]}`
	tooLong := `{"groups":["` + strings.Repeat("g", domain.MaxOwnerGroupLength+1) + `"]}`
	for name, tc := range map[string]struct {
		body       string
		auth       func(t *testing.T, gwID ids.GatewayID) *domain.Auth
		notFound   bool
		wantStatus int
		wantCode   string
	}{
		"application key": {body: groups, auth: func(t *testing.T, gwID ids.GatewayID) *domain.Auth { return testAPIKeyAuth(t, gwID, "ci", "") }, wantStatus: http.StatusUnprocessableEntity, wantCode: "application_key"},
		"unknown auth":    {body: groups, notFound: true, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		"another gateway's key": {body: groups, auth: func(t *testing.T, _ ids.GatewayID) *domain.Auth {
			return testAPIKeyAuth(t, ids.New[ids.GatewayKind](), "personal-alice", "alice")
		}, wantStatus: http.StatusNotFound, wantCode: "not_found"},
		"a group name too long": {body: tooLong, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"groups as a string":    {body: `{"groups":"engineering"}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
		"not an email":          {body: `{"groups":["engineering"],"email":"alice at acme"}`, auth: ownedBy("alice"), wantStatus: http.StatusUnprocessableEntity, wantCode: "validation_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gwID := ids.New[ids.GatewayKind]()
			repo := repomocks.NewRepository(t)
			id := ids.New[ids.AuthKind]().String()
			switch {
			case tc.notFound:
				repo.EXPECT().FindByID(mock.Anything, mock.Anything).Return(nil, domain.ErrNotFound).Once()
			case tc.auth != nil:
				a := tc.auth(t, gwID)
				id = a.ID.String()
				repo.EXPECT().FindByID(mock.Anything, a.ID).Return(a, nil).Once()
			}
			signaler := &configsynctest.FakeSignaler{}

			status, raw := doJSON(t, ownerGroupsApp(repo, cachemocks.NewEventPublisher(t), signaler), http.MethodPut, ownerGroupsURL(gwID, id), tc.body)
			require.Equal(t, tc.wantStatus, status, raw)
			require.Contains(t, raw, `"error":"`+tc.wantCode+`"`)
			require.Zero(t, signaler.Count())
		})
	}
}
