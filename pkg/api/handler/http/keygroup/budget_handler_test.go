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

package keygroup_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keygrouphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	appkeygroup "github.com/NeuralTrust/TrustGate/pkg/app/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/keygroup/mocks"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func budgetApp(repo domain.Repository, publisher *cachemocks.EventPublisher) *fiber.App {
	h := keygrouphttp.NewBudgetHandler(appkeygroup.NewBudgets(repo, publisher, slog.New(slog.DiscardHandler), &configsynctest.FakeSignaler{}, nil))
	app := fiber.New()
	app.Get("/v1/gateways/:gateway_id/key-groups/budgets", h.List)
	app.Put("/v1/gateways/:gateway_id/key-groups/:group_id/budget", h.Set)
	app.Delete("/v1/gateways/:gateway_id/key-groups/:group_id/budget", h.Delete)
	return app
}

func call(t *testing.T, app *fiber.App, method, url, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	if body != "" {
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	}
	res, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

func echo(_ context.Context, b *domain.Budget) (*domain.Budget, error) { return b, nil }

func TestBudgetHandler_SetEchoesTheBudget(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	repo := mocks.NewRepository(t)
	repo.EXPECT().Upsert(mock.Anything, mock.MatchedBy(func(b *domain.Budget) bool {
		return b.GatewayID == gw && b.GroupID == "g-eng" && b.MonthlyLimitUSD == nil && *b.MemberMonthlyLimitUSD == 20 && b.MemberOverrides["alice"] == 50
	})).RunAndReturn(echo).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	status, raw := call(t, budgetApp(repo, publisher), http.MethodPut, "/v1/gateways/"+gw.String()+"/key-groups/g-eng/budget",
		`{"monthly_limit_usd":null,"member_monthly_limit_usd":20,"member_overrides":{"alice":50},"action":"block"}`)

	require.Equal(t, http.StatusOK, status, raw)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &got))
	require.Equal(t, "g-eng", got["group_id"])
	require.Contains(t, got, "monthly_limit_usd", "a limit that is not set is answered as null")
	require.Nil(t, got["monthly_limit_usd"])
	require.Equal(t, 20.0, got["member_monthly_limit_usd"])
	require.Equal(t, map[string]any{"alice": 50.0}, got["member_overrides"])
	require.Equal(t, "block", got["action"])
}

func TestBudgetHandler_RefusesWithoutWriting(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	for name, body := range map[string]string{
		"no limit":          `{"action":"block"}`,
		"a negative limit":  `{"monthly_limit_usd":-1,"action":"block"}`,
		"no action":         `{"monthly_limit_usd":10}`,
		"an unknown action": `{"monthly_limit_usd":10,"action":"throttle"}`,
		"a malformed body":  `{"monthly_limit_usd":"ten","action":"block"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			status, raw := call(t, budgetApp(mocks.NewRepository(t), cachemocks.NewEventPublisher(t)), http.MethodPut,
				"/v1/gateways/"+gw.String()+"/key-groups/g-eng/budget", body)
			require.Equal(t, http.StatusUnprocessableEntity, status, raw)
			require.Contains(t, raw, `"error":"validation_failed"`)
		})
	}
	status, raw := call(t, budgetApp(mocks.NewRepository(t), cachemocks.NewEventPublisher(t)), http.MethodPut,
		"/v1/gateways/not-a-gateway/key-groups/g-eng/budget", `{"monthly_limit_usd":10,"action":"block"}`)
	require.Equal(t, http.StatusBadRequest, status, raw)
}

func TestBudgetHandler_ListAndDelete(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	limit := 100.0
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := mocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gw).Return([]*domain.Budget{
		{GatewayID: gw, GroupID: "g-eng", MonthlyLimitUSD: &limit, Action: domain.ActionAlert, CreatedAt: at, UpdatedAt: at},
	}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gw, "g-eng").Return(nil).Once()
	repo.EXPECT().Delete(mock.Anything, gw, "g-sre").Return(domain.ErrNotFound).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()
	app := budgetApp(repo, publisher)

	status, raw := call(t, app, http.MethodGet, "/v1/gateways/"+gw.String()+"/key-groups/budgets", "")
	require.Equal(t, http.StatusOK, status, raw)
	require.JSONEq(t, `{"items":[{"group_id":"g-eng","monthly_limit_usd":100,"member_monthly_limit_usd":null,"member_overrides":{},"action":"alert",`+
		`"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}]}`, raw)

	status, raw = call(t, app, http.MethodDelete, "/v1/gateways/"+gw.String()+"/key-groups/g-eng/budget", "")
	require.Equal(t, http.StatusNoContent, status, raw)
	status, raw = call(t, app, http.MethodDelete, "/v1/gateways/"+gw.String()+"/key-groups/g-sre/budget", "")
	require.Equal(t, http.StatusNotFound, status, raw)
}
