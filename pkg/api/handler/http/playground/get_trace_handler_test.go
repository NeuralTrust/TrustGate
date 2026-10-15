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

package playground_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	playgroundhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/playground"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTraceFinder struct {
	evt *events.Event
	err error
}

func (f fakeTraceFinder) Find(_ context.Context, _ string) (*events.Event, error) {
	return f.evt, f.err
}

var platform = middleware.AdminIdentity{Kind: middleware.AdminIdentityPlatform}

func newApp(finder playgroundhttp.TraceFinder) *fiber.App {
	return newAppAs(finder, platform)
}

func newAppAs(finder playgroundhttp.TraceFinder, caller middleware.AdminIdentity) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		middleware.StoreAdminIdentity(c, caller)
		return c.Next()
	})
	h := playgroundhttp.NewGetTraceHandler(finder)
	app.Get("/v1/playground/traces/:trace_id", h.Handle)
	return app
}

func TestGetTraceHandler_Found(t *testing.T) {
	finder := fakeTraceFinder{evt: &events.Event{TraceID: "trace-1", GatewayID: "gw-1", TenantID: "acme"}}
	app := newApp(finder)

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/playground/traces/trace-1", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var evt events.Event
	require.NoError(t, json.Unmarshal(body, &evt))
	assert.Equal(t, "trace-1", evt.TraceID)
	assert.Equal(t, "gw-1", evt.GatewayID)
}

func TestGetTraceHandler_NotFound(t *testing.T) {
	finder := fakeTraceFinder{evt: nil}
	app := newApp(finder)

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/playground/traces/missing", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
}

func TestGetTraceHandler_Error(t *testing.T) {
	finder := fakeTraceFinder{err: errors.New("redis down")}
	app := newApp(finder)

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/playground/traces/trace-1", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
}

func TestGetTraceHandler_Ownership(t *testing.T) {
	human := func(tenant string) middleware.AdminIdentity {
		return middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: tenant}
	}
	cases := []struct {
		name        string
		caller      middleware.AdminIdentity
		eventTenant string
		want        int
	}{
		{name: "own tenant", caller: human("acme"), eventTenant: "acme", want: fiber.StatusOK},
		{name: "other tenant", caller: human("globex"), eventTenant: "acme", want: fiber.StatusNotFound},
		{name: "platform", caller: platform, eventTenant: "acme", want: fiber.StatusOK},
		{name: "platform on untenanted trace", caller: platform, eventTenant: "", want: fiber.StatusOK},
		{name: "tenant on untenanted trace", caller: human("acme"), eventTenant: "", want: fiber.StatusNotFound},
		{name: "human without tenant", caller: human(""), eventTenant: "", want: fiber.StatusNotFound},
		{name: "unauthenticated", caller: middleware.AdminIdentity{}, eventTenant: "acme", want: fiber.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finder := fakeTraceFinder{evt: &events.Event{TraceID: "trace-1", GatewayID: "gw-1", TenantID: tc.eventTenant}}
			app := newAppAs(finder, tc.caller)

			resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/playground/traces/trace-1", nil))
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, tc.want, resp.StatusCode)
			if tc.want == fiber.StatusNotFound {
				assertUnknownTraceBody(t, resp.Body)
			}
		})
	}
}

func assertUnknownTraceBody(t *testing.T, body io.Reader) {
	t.Helper()
	raw, err := io.ReadAll(body)
	require.NoError(t, err)
	want, err := json.Marshal(httpio.NotFoundBody())
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(raw))
}
