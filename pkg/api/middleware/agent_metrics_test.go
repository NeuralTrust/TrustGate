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

package middleware_test

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAgentMetricsMiddleware_TracesAsA2A(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	var (
		mu    sync.Mutex
		gotRT *trace.RequestTrace
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(rt *trace.RequestTrace, _ *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			gotRT = rt
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewAgentMetricsMiddleware(worker, nil, cfg)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), ids.New[ids.GatewayKind]()))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/bot/agents/research", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/bot/agents/research", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.NotEmpty(t, resp.Header.Get(middleware.HeaderTraceID))

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, gotRT)
	require.Equal(t, "a2a", gotRT.Metadata().Kind)
	require.Equal(t, gotRT.TraceID(), resp.Header.Get(middleware.HeaderTraceID))
}

func TestAgentMetricsMiddleware_RelaysStreamEventsAsTheyAreWritten(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	processed := make(chan *infracontext.ResponseContext, 1)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ *trace.RequestTrace, _ *infracontext.RequestContext, resp *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			processed <- resp
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewAgentMetricsMiddleware(worker, nil, cfg)

	release := make(chan struct{})
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), ids.New[ids.GatewayKind]()))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/bot/agents/research", func(c *fiber.Ctx) error {
		rt := trace.FromContext(c.UserContext())
		rt.AddAsync()
		c.Set(fiber.HeaderContentType, "text/event-stream")
		c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			defer rt.Done()
			_, _ = w.WriteString("data: first\n\n")
			_ = w.Flush()
			<-release
			_, _ = w.WriteString("data: last\n\n")
			_ = w.Flush()
		})
		return nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	first := make(chan string, 1)
	go func() {
		resp, err := http.Post("http://"+ln.Addr().String()+"/bot/agents/research", "application/json", nil)
		if err != nil {
			first <- err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		require.Equal(t, "data: first\n", line)
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("the first event did not reach the client before the stream ended")
	}
	close(release)

	select {
	case got := <-processed:
		require.True(t, got.Streaming)
		require.Empty(t, got.Body)
	case <-time.After(2 * time.Second):
		t.Fatal("the stream's telemetry was not processed")
	}
}

// A client reads the agent's card before it calls: the read is the gateway's
// own pinned card, so it is not logged as a call to the agent.
func TestAgentMetricsMiddleware_DoesNotTraceCardReads(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewAgentMetricsMiddleware(worker, nil, cfg)

	app := fiber.New()
	app.Use(mw.Middleware())
	app.Get("/bot/agents/research/.well-known/agent-card.json", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/bot/agents/research/.well-known/agent-card.json", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get(middleware.HeaderTraceID))
}
