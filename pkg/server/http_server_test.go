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

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

const testShutdownBudget = 20 * time.Second

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// routerFunc adapts a closure to the ServerRouter port, so a test declares its
// routes without a production router.
type routerFunc func(*fiber.App) error

func (f routerFunc) BuildRoutes(app *fiber.App) error {
	return f(app)
}

// startTestServer listens on an ephemeral port and returns the server together
// with its base URL.
func startTestServer(t *testing.T, routes routerFunc, hooks ...ShutdownHook) (*httpServer, string) {
	t.Helper()
	srv, ok := NewHTTPServer(
		"test",
		"127.0.0.1:0",
		config.ServerConfig{},
		discardLogger(),
		[]router.ServerRouter{routes},
		hooks...,
	).(*httpServer)
	require.True(t, ok)

	listening := make(chan string, 1)
	srv.Router.Hooks().OnListen(func(data fiber.ListenData) error {
		listening <- "http://" + data.Host + ":" + data.Port
		return nil
	})
	go func() { _ = srv.Run() }()

	select {
	case base := <-listening:
		return srv, base
	case <-time.After(testShutdownBudget):
		t.Fatal("the server never started listening")
		return nil, ""
	}
}

// fiber.App.Shutdown waits for every connection to become idle, and a parked
// request never becomes idle on its own. The hook is what releases it, so this
// only completes if the hooks run before the router shutdown.
func TestHTTPServerRunsShutdownHooksBeforeTheRouterWaitsForIdle(t *testing.T) {
	released := make(chan struct{})
	parked := make(chan struct{})
	var hookRan atomic.Bool

	srv, base := startTestServer(
		t,
		func(app *fiber.App) error {
			app.Get("/park", func(c *fiber.Ctx) error {
				close(parked)
				<-released
				return c.SendString("released")
			})
			return nil
		},
		func(context.Context) error {
			hookRan.Store(true)
			close(released)
			return nil
		},
	)

	body := make(chan string, 1)
	go func() {
		res, err := http.Get(base + "/park")
		if err != nil {
			body <- "error: " + err.Error()
			return
		}
		defer func() { _ = res.Body.Close() }()
		raw, _ := io.ReadAll(res.Body)
		body <- string(raw)
	}()
	<-parked

	done := make(chan error, 1)
	go func() { done <- srv.Shutdown() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(testShutdownBudget):
		t.Fatal("shutdown hung on an in-flight request")
	}
	require.True(t, hookRan.Load())
	require.Equal(t, "released", <-body)
}

// A hook that never returns must not hold shutdown past its budget, and a hook
// that fails must not stop the router from shutting down either.
func TestHTTPServerShutdownSurvivesAFailingHook(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		hook ShutdownHook
	}{
		{
			name: "a failing hook",
			hook: func(context.Context) error { return errors.New("drain failed") },
		},
		{
			name: "a hook bounded by its context",
			hook: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, _ := startTestServer(t, func(*fiber.App) error { return nil }, tc.hook)

			done := make(chan error, 1)
			go func() { done <- srv.Shutdown() }()

			select {
			case err := <-done:
				require.NoError(t, err, "a hook failure must not fail the shutdown")
			case <-time.After(testShutdownBudget):
				t.Fatal("a hook held shutdown past its budget")
			}
		})
	}
}

// The hooks share one budget, so a slow one cannot grant the next a fresh
// deadline.
func TestBaseServerShutdownHooksShareOneBudget(t *testing.T) {
	t.Parallel()
	base := NewBaseServer("test", "127.0.0.1:0", config.ServerConfig{}, discardLogger())
	var second atomic.Bool
	base.WithShutdownHooks(
		nil,
		func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
		func(ctx context.Context) error {
			second.Store(true)
			require.Error(t, ctx.Err(), "the budget is shared, not renewed per hook")
			return nil
		},
	)

	start := time.Now()
	base.runShutdownHooks()

	require.True(t, second.Load(), "every hook runs even after one exhausts the budget")
	require.Less(t, time.Since(start), shutdownHookBudget*2)
}

func TestBaseServerDropsNilShutdownHooks(t *testing.T) {
	t.Parallel()
	base := NewBaseServer("test", "127.0.0.1:0", config.ServerConfig{}, discardLogger())

	base.WithShutdownHooks(nil, nil)

	require.Empty(t, base.hooks)
	base.runShutdownHooks()
}
