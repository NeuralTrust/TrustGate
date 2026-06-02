// Command agentgateway starts the admin or proxy HTTP server (argv[1], default proxy).
//
// @title                       AgentGateway Admin API
// @version                     1.0
// @description                 Administrative API for managing gateways and their backends, policies, consumers and auth credentials.
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

	_ "github.com/NeuralTrust/AgentGateway/docs"
	appmetrics "github.com/NeuralTrust/AgentGateway/pkg/app/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/container/modules"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	_ "github.com/NeuralTrust/AgentGateway/pkg/infra/database/migrations"
	"github.com/NeuralTrust/AgentGateway/pkg/server"
	"github.com/joho/godotenv"
	"go.uber.org/dig"
)

const (
	serverAdmin = "admin"
	serverProxy = "proxy"
)

func main() {
	_ = godotenv.Load()

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
		if err := c.Invoke(runAdmin); err != nil {
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

	logger.Info("running database migrations")
	if err := mgr.ApplyPending(ctx); err != nil {
		logger.Error("failed to apply migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}
	logger.Info("database migrations applied")
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

func runAdmin(p adminParam, logger *slog.Logger) {
	runServer(p.Srv, serverAdmin, logger)
}

func runProxy(p proxyParam, logger *slog.Logger) {
	defer p.Worker.Shutdown()
	runServer(p.Srv, serverProxy, logger)
}

func runServer(srv server.Server, name string, logger *slog.Logger) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Run(); err != nil {
			logger.Error("server failed", slog.String("server", name), slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	<-quit
	logger.Info("shutting down server", slog.String("server", name))
	if err := srv.Shutdown(); err != nil {
		logger.Error("server shutdown error", slog.String("server", name), slog.String("error", err.Error()))
		return
	}
	logger.Info("server stopped gracefully", slog.String("server", name))
}
