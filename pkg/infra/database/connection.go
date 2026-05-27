// Package database wires Postgres connectivity and migrations.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

const healthCheckTimeout = 5 * time.Second

type Connection struct {
	Pool *pgxpool.Pool
}

func NewConnection(ctx context.Context, cfg *config.DatabaseConfig) (*Connection, error) {
	conf, err := buildPoolConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: build pool config: %v", errors.ErrBoot, err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("%w: create connection pool: %v", errors.ErrBoot, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%w: ping database: %v", errors.ErrBoot, err)
	}
	return &Connection{Pool: pool}, nil
}

func (c *Connection) Close() {
	if c.Pool != nil {
		c.Pool.Close()
	}
}

func (c *Connection) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()
	return c.Pool.Ping(ctx)
}

func buildPoolConfig(cfg *config.DatabaseConfig) (*pgxpool.Config, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name, cfg.SSLMode,
	)
	if cfg.SSLRootCert != "" {
		dsn += " sslrootcert=" + cfg.SSLRootCert
	}

	conf, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	conf.MaxConns = cfg.MaxConns
	conf.MinConns = cfg.MinConns
	conf.MaxConnLifetime = cfg.MaxConnLifetime
	conf.MaxConnIdleTime = cfg.MaxConnIdleTime
	conf.HealthCheckPeriod = cfg.HealthCheckPeriod
	conf.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	return conf, nil
}
