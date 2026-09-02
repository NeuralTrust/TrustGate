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
	"net/http/httptest"
	"strings"
	"testing"

	playgroundhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/playground"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTraceWriter struct {
	stored *events.Event
	err    error
}

func (f *fakeTraceWriter) Put(_ context.Context, evt *events.Event) error {
	f.stored = evt
	return f.err
}

func newPutApp(writer playgroundhttp.TraceWriter) *fiber.App {
	app := fiber.New()
	h := playgroundhttp.NewPutTraceHandler(writer)
	app.Put("/v1/playground/traces/:trace_id", h.Handle)
	return app
}

func putTrace(t *testing.T, app *fiber.App, traceID, body string) int {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPut, "/v1/playground/traces/"+traceID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestPutTraceHandler_StoresEvent(t *testing.T) {
	writer := &fakeTraceWriter{}
	app := newPutApp(writer)

	status := putTrace(t, app, "trace-1", `{"trace_id":"trace-1","gateway_id":"gw-1"}`)

	assert.Equal(t, fiber.StatusNoContent, status)
	require.NotNil(t, writer.stored)
	assert.Equal(t, "trace-1", writer.stored.TraceID)
	assert.Equal(t, "gw-1", writer.stored.GatewayID)
}

func TestPutTraceHandler_FillsTraceIDFromPath(t *testing.T) {
	writer := &fakeTraceWriter{}
	app := newPutApp(writer)

	status := putTrace(t, app, "trace-2", `{"gateway_id":"gw-1"}`)

	assert.Equal(t, fiber.StatusNoContent, status)
	require.NotNil(t, writer.stored)
	assert.Equal(t, "trace-2", writer.stored.TraceID)
}

func TestPutTraceHandler_RejectsMismatchedTraceID(t *testing.T) {
	writer := &fakeTraceWriter{}
	app := newPutApp(writer)

	status := putTrace(t, app, "trace-3", `{"trace_id":"other"}`)

	assert.Equal(t, fiber.StatusBadRequest, status)
	assert.Nil(t, writer.stored)
}

func TestPutTraceHandler_RejectsInvalidJSON(t *testing.T) {
	writer := &fakeTraceWriter{}
	app := newPutApp(writer)

	status := putTrace(t, app, "trace-4", `not-json`)

	assert.Equal(t, fiber.StatusBadRequest, status)
	assert.Nil(t, writer.stored)
}
