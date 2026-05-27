package modules

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/logger"
)

func Core(c *container.Container) error {
	if err := c.Provide(config.LoadConfig); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *slog.Logger {
		log := logger.NewLoggerWithFormat(cfg.Logger.Level, logger.LogFormat(cfg.Logger.Format))
		slog.SetDefault(log)
		return log
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *config.DatabaseConfig {
		return &cfg.Database
	}); err != nil {
		return err
	}
	if err := c.Provide(func() context.Context {
		return context.Background()
	}); err != nil {
		return err
	}
	if err := c.Provide(database.NewConnectionProvider); err != nil {
		return err
	}
	if err := c.Provide(database.NewMigrationsManagerProvider); err != nil {
		return err
	}
	return nil
}
