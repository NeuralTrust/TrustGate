package database

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
)

func NewConnectionProvider(ctx context.Context, cfg *config.DatabaseConfig) (*Connection, error) {
	return NewConnection(ctx, cfg)
}

func NewMigrationsManagerProvider(conn *Connection) *MigrationsManager {
	return NewMigrationsManager(conn.Pool)
}
