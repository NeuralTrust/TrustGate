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
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readyz(t *testing.T, store configsync.ConfigStore[*readmodel.Snapshot], status *configsync.SnapshotStatus) (int, map[string]any) {
	t.Helper()
	h := apihandler.NewHealthHandler(apihandler.ReadinessCheck{Name: "snapshot", Ping: configsync.ReadinessCheck(store)}).
		WithSnapshotReport(snapshotReport(status))
	app := fiber.New()
	app.Get("/readyz", h.Readiness)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func TestReadyz_ReportsSnapshotState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := func() time.Time { return now }
	loaded := func() configsync.ConfigStore[*readmodel.Snapshot] {
		store := configsync.NewMemoryStore[*readmodel.Snapshot]()
		store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: &readmodel.Snapshot{}})
		return store
	}

	t.Run("none is 503 without age", func(t *testing.T) {
		t.Parallel()
		status := configsync.NewSnapshotStatus(clock)
		code, body := readyz(t, configsync.NewMemoryStore[*readmodel.Snapshot](), status)

		assert.Equal(t, http.StatusServiceUnavailable, code)
		assert.Equal(t, "not_ready", body["status"])
		assert.Equal(t, map[string]any{"snapshot": "unavailable"}, body["dependencies"])
		assert.Equal(t, map[string]any{"state": "none"}, body["snapshot"])
	})

	t.Run("lkg reports age", func(t *testing.T) {
		t.Parallel()
		status := configsync.NewSnapshotStatus(clock)
		status.MarkLKG("v1", 90*time.Second)
		code, body := readyz(t, loaded(), status)

		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "ready", body["status"])
		assert.Equal(t, map[string]any{"snapshot": "ok"}, body["dependencies"])
		assert.Equal(t, map[string]any{
			"state":       "lkg",
			"applied_at":  now.Add(-90 * time.Second).Format(time.RFC3339),
			"age_seconds": float64(90),
		}, body["snapshot"])
	})

	t.Run("live reports age", func(t *testing.T) {
		t.Parallel()
		status := configsync.NewSnapshotStatus(clock)
		status.MarkLive("v2")
		code, body := readyz(t, loaded(), status)

		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, map[string]any{
			"state":       "live",
			"applied_at":  now.Format(time.RFC3339),
			"age_seconds": float64(0),
		}, body["snapshot"])
	})
}

func TestReadyz_DoesNotExposeSnapshotVersion(t *testing.T) {
	t.Parallel()

	const etag = "3f2a9c1de8b74a55b0c6d41e9f7a2c88d5e1b6a04c93f7e2a1d8b5c60e4f9a37"
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: etag, Snapshot: &readmodel.Snapshot{}})
	status := configsync.NewSnapshotStatus(nil)
	status.MarkLive(etag)

	h := apihandler.NewHealthHandler(apihandler.ReadinessCheck{Name: "snapshot", Ping: configsync.ReadinessCheck(store)}).
		WithSnapshotReport(snapshotReport(status))
	app := fiber.New()
	app.Get("/readyz", h.Readiness)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.NotContains(t, string(raw), etag)
	assert.NotContains(t, string(raw), "version\":\""+etag)
	assert.Contains(t, string(raw), `"state":"live"`)
}

func TestReadyz_WithoutReporterKeepsOriginalShape(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Get("/readyz", apihandler.NewHealthHandler(apihandler.ReadinessCheck{
		Name: "x", Ping: func(context.Context) error { return errors.New("down") },
	}).Readiness)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.NotContains(t, body, "snapshot")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
