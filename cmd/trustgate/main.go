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

// Command trustgate starts a server selected by argv[1] (default proxy):
// "admin", "proxy", "mcp", or "run" (admin + proxy together in one process).
//
// @title                       TrustGate Admin API
// @version                     1.0
// @description                 Administrative API for managing gateways and their registries, policies, consumers and auth credentials.
// @contact.name                NeuralTrust
// @contact.url                 https://neuraltrust.ai/contact
// @contact.email               support@neuraltrust.ai
// @BasePath                    /
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/NeuralTrust/TrustGate/docs"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/container/modules"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	configsyncgrpc "github.com/NeuralTrust/TrustGate/pkg/infra/configsync/grpc"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/joho/godotenv"
	"go.uber.org/dig"
)

const (
	serverAdmin  = "admin"
	serverProxy  = "proxy"
	serverMCP    = "mcp"
	serverRun    = "run"
	serverWorker = "worker"
)

// serverConfigSyncGRPC names the control-plane config-sync gRPC listener in the shared serve loop.
const serverConfigSyncGRPC = "config-sync-grpc"

const bedrockModelsShutdownGrace = time.Second

func main() {
	// Local dev uses .env in cwd; k8s mounts GCP secrets at /etc/secrets/.env
	// (see workingDir in deployment manifests). Distroless has no shell entrypoint.
	for _, path := range []string{".env", "/etc/secrets/.env", "/etc/secrets/secrets"} {
		_ = godotenv.Load(path)
	}

	plane := serverType()
	dbless := config.DBLessDataPlaneEnabled() && isDataPlane(plane)

	c, err := container.New(modules.All(plane, dbless)...)
	if err != nil {
		log.Fatalf("failed to initialize container: %v", err)
	}

	if err := c.Invoke(modules.StartCacheJanitor); err != nil {
		log.Fatalf("failed to start cache janitor: %v", err)
	}

	if !dbless {
		if err := c.Invoke(runMigrations); err != nil {
			log.Fatalf("failed to run migrations: %v", err)
		}
		if err := c.Invoke(modules.StartCacheEventListener); err != nil {
			log.Fatalf("failed to start cache event listener: %v", err)
		}
	}

	if plane == serverAdmin {
		if err := c.Invoke(modules.StartCatalogSync); err != nil {
			log.Fatalf("failed to start catalog sync: %v", err)
		}
		if err := c.Invoke(modules.StartSecretsBackfill); err != nil {
			log.Fatalf("failed to start stored secrets backfill: %v", err)
		}
		if err := c.Invoke(runAdmin); err != nil {
			log.Fatalf("failed to start application: %v", err)
		}
		return
	}

	if plane == serverMCP {
		if err := c.Invoke(modules.StartMetricsWorker); err != nil {
			log.Fatalf("failed to start metrics worker: %v", err)
		}
		if err := c.Invoke(runMCP); err != nil {
			log.Fatalf("failed to start application: %v", err)
		}
		return
	}

	if plane == serverWorker {
		if err := c.Invoke(runLabelWorker); err != nil {
			log.Fatalf("failed to start application: %v", err)
		}
		return
	}

	if plane == serverRun {
		if err := c.Invoke(modules.StartCatalogSync); err != nil {
			log.Fatalf("failed to start catalog sync: %v", err)
		}
		if err := c.Invoke(modules.StartSecretsBackfill); err != nil {
			log.Fatalf("failed to start stored secrets backfill: %v", err)
		}
		if err := c.Invoke(modules.StartMetricsWorker); err != nil {
			log.Fatalf("failed to start metrics worker: %v", err)
		}
		if err := c.Invoke(runAll); err != nil {
			log.Fatalf("failed to start application: %v", err)
		}
		return
	}

	if err := c.Invoke(modules.StartMetricsWorker); err != nil {
		log.Fatalf("failed to start metrics worker: %v", err)
	}
	if err := c.Invoke(runProxy); err != nil {
		log.Fatalf("failed to start application: %v", err)
	}
}

func serverType() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return serverProxy
}

func isDataPlane(plane string) bool {
	return plane == serverProxy || plane == serverMCP || plane == serverWorker
}

func runMigrations(mgr *database.MigrationsManager, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger.Info(bootlog.MigrationsRunning)
	if err := mgr.ApplyPending(ctx); err != nil {
		logger.Error("failed to apply migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info(bootlog.MigrationsApplied)
}

type adminParam struct {
	dig.In
	Srv            server.Server `name:"admin"`
	Conn           *database.Connection
	Dispatcher     *appsnapshot.Dispatcher
	ConfigSyncGRPC *configsyncgrpc.Server
	OpsSDK         *o11y.SDK
}

// rateLimitParams is what the plan rate limiter needs to run in the background
// of a plane that serves proxy or MCP traffic. Meter is nil when the
// limiter is disabled.
type rateLimitParams struct {
	dig.In
	Meter *ratelimitapp.Meter
	// SyncRedis is nil when the limiter is disabled.
	SyncRedis *cache.SyncClient `optional:"true"`
	// Caps is the Postgres planes' tenant caps copy; absent (or nil) elsewhere.
	Caps *ratelimitapp.TenantCapsCache `optional:"true"`
}

type proxyParam struct {
	dig.In
	Srv           server.Server `name:"proxy"`
	Worker        appmetrics.Worker
	TrafficLabels modules.TrafficLabelsParams
	Conn          *database.Connection
	BedrockModels appcatalog.BedrockModelResolver
	Config        *config.Config
	ConfigWorker  *configsync.Worker[*readmodel.Snapshot] `optional:"true"`
	ConfigClient  *configsyncgrpc.Client                  `optional:"true"`
	RateLimit     rateLimitParams
	OpsSDK        *o11y.SDK
}

type mcpParam struct {
	dig.In
	// PendingTools is nil until a pending-tool recorder is wired.
	PendingTools *appmcp.AsyncPendingRecorder `optional:"true"`
	Srv          server.Server                `name:"mcp"`
	Worker       appmetrics.Worker
	Conn         *database.Connection
	ConfigWorker *configsync.Worker[*readmodel.Snapshot] `optional:"true"`
	ConfigClient *configsyncgrpc.Client                  `optional:"true"`
	RateLimit    rateLimitParams
	OpsSDK       *o11y.SDK
}

type allParam struct {
	dig.In
	Admin          server.Server `name:"admin"`
	Proxy          server.Server `name:"proxy"`
	Worker         appmetrics.Worker
	TrafficLabels  modules.TrafficLabelsParams
	Conn           *database.Connection
	BedrockModels  appcatalog.BedrockModelResolver
	Config         *config.Config
	Dispatcher     *appsnapshot.Dispatcher
	ConfigSyncGRPC *configsyncgrpc.Server
	RateLimit      rateLimitParams
	OpsSDK         *o11y.SDK
}

func runAdmin(p adminParam, logger *slog.Logger) {
	stopDispatcher := startDispatcher(p.Dispatcher, logger)
	defer flushOpsTelemetry(p.OpsSDK, logger)
	defer closeResources(p.Conn, logger)
	defer stopDispatcher()
	runServers(logger,
		namedServer{name: serverAdmin, srv: p.Srv},
		namedServer{name: serverConfigSyncGRPC, srv: p.ConfigSyncGRPC},
	)
}

func runMCP(p mcpParam, logger *slog.Logger) {
	stopWorker := startConfigSyncWorker(p.ConfigWorker, p.ConfigClient, logger)
	defer flushOpsTelemetry(p.OpsSDK, logger)
	defer closeResources(p.Conn, logger)
	defer p.Worker.Shutdown()
	defer stopWorker()
	defer p.PendingTools.Close()
	defer startRateLimit(p.RateLimit, logger)()
	runServer(p.Srv, serverMCP, logger)
}

func runProxy(p proxyParam, logger *slog.Logger) {
	stopWorker := startConfigSyncWorker(p.ConfigWorker, p.ConfigClient, logger)
	defer flushOpsTelemetry(p.OpsSDK, logger)
	defer closeResources(p.Conn, logger)
	defer closeBedrockModels(p.BedrockModels, p.Config, logger)
	defer p.Worker.Shutdown()
	defer stopWorker()
	defer modules.StartTrafficLabels(p.TrafficLabels, true)()
	defer startRateLimit(p.RateLimit, logger)()
	runServer(p.Srv, serverProxy, logger)
}

type labelWorkerParam struct {
	dig.In
	TrafficLabels modules.TrafficLabelsParams
	Worker        appmetrics.Worker
	Conn          *database.Connection
	ConfigWorker  *configsync.Worker[*readmodel.Snapshot] `optional:"true"`
	ConfigClient  *configsyncgrpc.Client                  `optional:"true"`
	OpsSDK        *o11y.SDK
}

func runLabelWorker(p labelWorkerParam, logger *slog.Logger) {
	stopConfig := startConfigSyncWorker(p.ConfigWorker, p.ConfigClient, logger)
	defer flushOpsTelemetry(p.OpsSDK, logger)
	defer closeResources(p.Conn, logger)
	defer stopConfig()
	defer p.Worker.Shutdown()
	defer modules.StartTrafficLabels(p.TrafficLabels, false)()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
}

func runAll(p allParam, logger *slog.Logger) {
	stopDispatcher := startDispatcher(p.Dispatcher, logger)
	defer flushOpsTelemetry(p.OpsSDK, logger)
	defer closeResources(p.Conn, logger)
	defer closeBedrockModels(p.BedrockModels, p.Config, logger)
	defer stopDispatcher()
	defer p.Worker.Shutdown()
	defer modules.StartTrafficLabels(p.TrafficLabels, true)()
	defer startRateLimit(p.RateLimit, logger)()
	runServers(logger,
		namedServer{name: serverAdmin, srv: p.Admin},
		namedServer{name: serverProxy, srv: p.Proxy},
		namedServer{name: serverConfigSyncGRPC, srv: p.ConfigSyncGRPC},
	)
}

// startRateLimit runs the plan counter sync loop
// for as long as the process serves traffic. It loads the tenant caps once,
// bounded, before returning, so call it before the servers start: the first
// requests are then measured against the tenant's row and not the gateway stamp.
//
// The returned stop waits for the loop's final flush, so it must run after the
// servers have drained and before Redis is closed: that flush is what keeps the
// last interval of usage from being lost on a rolling restart. The callers
// register it with defer right before the servers run, which makes it the first
// deferred function to run once they return.
func startRateLimit(p rateLimitParams, logger *slog.Logger) func() {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	if p.Meter != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Meter.Run(ctx)
		}()
		logger.Info(bootlog.RateLimitSyncStarted)
	}
	if p.Meter != nil && p.Caps != nil {
		// One bounded load before the servers start. A failure is logged and
		// counted by the cache itself; the gateway stamp applies until Run, which
		// waits before its first retry, gets a copy.
		_ = p.Caps.Prime(ctx)
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Caps.Run(ctx)
		}()
	}
	return func() {
		cancel()
		wg.Wait()
		if p.SyncRedis != nil {
			if err := p.SyncRedis.Close(); err != nil {
				logger.Warn("rate limit redis shutdown error", slog.String("error", err.Error()))
			}
		}
	}
}

// startDispatcher runs the debounced snapshot dispatcher in its own goroutine and
// returns a stop function that cancels its context and joins it. It signals an
// eager initial compile so the gRPC server can serve a version shortly after boot
// rather than waiting for the first admin write.
func startDispatcher(dispatcher *appsnapshot.Dispatcher, logger *slog.Logger) func() {
	if dispatcher == nil {
		return func() {}
	}
	// Serve the persisted snapshot, if any, before the first compile. Restore is
	// bounded and never fails, so a store problem cannot hold the boot.
	dispatcher.Restore(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dispatcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("config snapshot dispatcher stopped", slog.String("error", err.Error()))
		}
	}()
	dispatcher.Signal()
	return func() {
		cancel()
		wg.Wait()
	}
}

func startConfigSyncWorker(
	worker *configsync.Worker[*readmodel.Snapshot],
	client *configsyncgrpc.Client,
	logger *slog.Logger,
) func() {
	if worker == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("config sync worker stopped", slog.String("error", err.Error()))
		}
	}()
	startAttrs := []any{}
	if client != nil {
		startAttrs = append(startAttrs, slog.String("endpoint", client.Endpoint()))
	}
	logger.Info(bootlog.ConfigSyncWorkerStarted, startAttrs...)
	return func() {
		cancel()
		// Closing the client cancels the Sync stream context, unblocking the
		// watch loop's in-flight receive so the worker goroutine can exit.
		if client != nil {
			if err := client.Close(); err != nil {
				logger.Warn("config sync client close failed", slog.String("error", err.Error()))
			}
		}
		wg.Wait()
	}
}

// flushOpsTelemetry drains the operational batch processors before exit. The last
// batch before a rolling restart is the one an operator is most likely reading.
func flushOpsTelemetry(sdk *o11y.SDK, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sdk.Shutdown(ctx); err != nil {
		logger.Warn("operational telemetry shutdown failed", slog.String("error", err.Error()))
	}
}

// closeBedrockModels waits for the model lookups still in flight, so a rolling
// restart does not cut a control plane call off mid-flight. A lookup is bounded by
// the configured control plane timeout, so the wait is that plus a second.
func closeBedrockModels(models appcatalog.BedrockModelResolver, cfg *config.Config, logger *slog.Logger) {
	if models == nil {
		return
	}
	timeout := config.DefaultBedrockNative().ResolverControlPlaneTimeout
	if cfg != nil && cfg.BedrockNative.ResolverControlPlaneTimeout > 0 {
		timeout = cfg.BedrockNative.ResolverControlPlaneTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+bedrockModelsShutdownGrace)
	defer cancel()
	if err := models.Close(ctx); err != nil {
		logger.Warn("bedrock model resolver shutdown timed out", slog.String("error", err.Error()))
	}
}

func closeResources(conn *database.Connection, logger *slog.Logger) {
	if conn == nil {
		return
	}
	logger.Info(bootlog.DatabaseClosing)
	conn.Close()
}

type namedServer struct {
	name string
	srv  server.Server
}

func runServer(srv server.Server, name string, logger *slog.Logger) {
	runServers(logger, namedServer{name: name, srv: srv})
}

func runServers(logger *slog.Logger, servers ...namedServer) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	for _, s := range servers {
		go func(s namedServer) {
			if err := s.srv.Run(); err != nil {
				logger.Error("server failed", slog.String("server", s.name), slog.String("error", err.Error()))
				os.Exit(1)
			}
		}(s)
	}

	<-quit
	for _, s := range servers {
		logger.Info(bootlog.ServerShutdown(s.name), slog.String("server", s.name))
		if err := s.srv.Shutdown(); err != nil {
			logger.Error("server shutdown error", slog.String("server", s.name), slog.String("error", err.Error()))
			continue
		}
		logger.Info(bootlog.ServerStoppedGracefully(s.name), slog.String("server", s.name))
	}
}
