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

package configsync_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	configsynchttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/configsyncconn"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLister struct {
	byScope map[string][]configsyncconn.Connection
}

func (f fakeLister) List(_ context.Context, scope string) ([]configsyncconn.Connection, error) {
	return f.byScope[scope], nil
}

func newApp(lister configsynchttp.ConnectionLister) *fiber.App {
	app := fiber.New()
	h := configsynchttp.NewListConnectionsHandler(lister)
	app.Get("/v1/config-sync/connections", h.Handle)
	return app
}

func decode(t *testing.T, body io.Reader) response.ListConnectionsResponse {
	t.Helper()
	raw, _ := io.ReadAll(body)
	var out response.ListConnectionsResponse
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

func TestListConnectionsHandler_ScopeFilterReturnsMatching(t *testing.T) {
	lister := fakeLister{byScope: map[string][]configsyncconn.Connection{
		"tenant-a": {
			{Scope: "tenant-a", InstanceID: "dp-1", State: "connected", AppliedVersion: "v3"},
		},
	}}
	app := newApp(lister)

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/config-sync/connections?scope=tenant-a", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	out := decode(t, resp.Body)
	require.Len(t, out.Items, 1)
	assert.Equal(t, "tenant-a", out.Items[0].Scope)
	assert.Equal(t, "dp-1", out.Items[0].InstanceID)
	assert.Equal(t, "v3", out.Items[0].AppliedVersion)
}

func TestListConnectionsHandler_UnknownScopeReturnsEmpty(t *testing.T) {
	lister := fakeLister{byScope: map[string][]configsyncconn.Connection{}}
	app := newApp(lister)

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/config-sync/connections?scope=nope", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	out := decode(t, resp.Body)
	assert.Empty(t, out.Items)
	assert.NotNil(t, out.Items)
}

func TestListConnectionsHandler_AdminAuthEnforced(t *testing.T) {
	app := fiber.New()
	auth := middleware.NewAdminAuthMiddleware(nil, nil)
	h := configsynchttp.NewListConnectionsHandler(fakeLister{})
	app.Get("/v1/config-sync/connections", auth.Middleware(), h.Handle)

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/config-sync/connections", nil))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
}
