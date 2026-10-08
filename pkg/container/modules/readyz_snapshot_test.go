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

package modules

import (
	"encoding/json"
	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/dig"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminSnapshotReadinessOnlyControlPlanes(t *testing.T) {
	t.Parallel()
	for _, plane := range []string{"admin", "run", "proxy", "mcp", "worker"} {
		t.Run(plane, func(t *testing.T) {
			t.Parallel()
			c, err := container.New(container.WithModule(adminReadiness(plane)))
			require.NoError(t, err)
			require.NoError(t, c.Provide(func() *appsnapshot.Dispatcher { return &appsnapshot.Dispatcher{} }))
			var check adminSnapshotReadiness
			require.NoError(t, c.Invoke(func(p struct {
				dig.In
				Check adminSnapshotReadiness `optional:"true"`
			}) {
				check = p.Check
			}))
			if plane != "admin" && plane != "run" {
				assert.Nil(t, check)
				return
			}
			require.NotNil(t, check)
			app := fiber.New()
			app.Get("/readyz", apihandler.NewHealthHandler(apihandler.ReadinessCheck{Name: "compiled_snapshot", Ping: check}).Readiness)
			response, err := app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil))
			require.NoError(t, err)
			defer func() { _ = response.Body.Close() }()
			assert.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
			var body map[string]any
			require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
			assert.Equal(t, map[string]any{"compiled_snapshot": "unavailable"}, body["dependencies"])
		})
	}
}
