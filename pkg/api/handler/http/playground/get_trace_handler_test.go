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

	playgroundhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/playground"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
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

func newApp(finder playgroundhttp.TraceFinder) *fiber.App {
	app := fiber.New()
	h := playgroundhttp.NewGetTraceHandler(finder)
	app.Get("/v1/playground/traces/:trace_id", h.Handle)
	return app
}

func TestGetTraceHandler_Found(t *testing.T) {
	finder := fakeTraceFinder{evt: &events.Event{TraceID: "trace-1", GatewayID: "gw-1"}}
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
