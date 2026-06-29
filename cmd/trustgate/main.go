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
// @description                 Administrative API for managing gateways and their registries, policies, consumers, roles and auth credentials.
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
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/NeuralTrust/TrustGate/docs"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/container/modules"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/joho/godotenv"
	"go.uber.org/dig"
)

const (
	serverAdmin = "admin"
	serverProxy = "proxy"
	serverMCP   = "mcp"
	serverRun   = "run"
)

func main() {
	// Local dev uses .env in cwd; k8s mounts GCP secrets at /etc/secrets/.env
	// (see workingDir in deployment manifests). Distroless has no shell entrypoint.
	for _, path := range []string{".env", "/etc/secrets/.env", "/etc/secrets/secrets"} {
		_ = godotenv.Load(path)
	}

	c, err := container.New(modules.All()...)
	if err != nil {
		log.Fatalf("failed to initialize container: %v", err)
	}

	if err := c.Invoke(runMigrations); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	if err := c.Invoke(modules.StartCacheEventListener); err != nil {
		log.Fatalf("failed to start cache event listener: %v", err)
	}

	if serverType() == serverAdmin {
		if err := c.Invoke(modules.StartCatalogSync); err != nil {
			log.Fatalf("failed to start catalog sync: %v", err)
		}
		if err := c.Invoke(runAdmin); err != nil {
			log.Fatalf("failed to start application: %v", err)
		}
		return
	}

	if serverType() == serverMCP {
		if err := c.Invoke(modules.StartMetricsWorker); err != nil {
			log.Fatalf("failed to start metrics worker: %v", err)
		}
		if err := c.Invoke(runMCP); err != nil {
			log.Fatalf("failed to start application: %v", err)
		}
		return
	}

	if serverType() == serverRun {
		if err := c.Invoke(modules.StartCatalogSync); err != nil {
			log.Fatalf("failed to start catalog sync: %v", err)
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
	Srv server.Server `name:"admin"`
}

type proxyParam struct {
	dig.In
	Srv    server.Server `name:"proxy"`
	Worker appmetrics.Worker
}

type mcpParam struct {
	dig.In
	Srv    server.Server `name:"mcp"`
	Worker appmetrics.Worker
}

type allParam struct {
	dig.In
	Admin  server.Server `name:"admin"`
	Proxy  server.Server `name:"proxy"`
	Worker appmetrics.Worker
}

func runAdmin(p adminParam, logger *slog.Logger) {
	runServer(p.Srv, serverAdmin, logger)
}

func runMCP(p mcpParam, logger *slog.Logger) {
	defer p.Worker.Shutdown()
	runServer(p.Srv, serverMCP, logger)
}

func runProxy(p proxyParam, logger *slog.Logger) {
	defer p.Worker.Shutdown()
	runServer(p.Srv, serverProxy, logger)
}

func runAll(p allParam, logger *slog.Logger) {
	defer p.Worker.Shutdown()
	runServers(logger, namedServer{name: serverAdmin, srv: p.Admin}, namedServer{name: serverProxy, srv: p.Proxy})
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
