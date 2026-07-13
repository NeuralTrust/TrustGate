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

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

const healthCheckTimeout = 5 * time.Second

type Connection struct {
	Pool *pgxpool.Pool
}

func NewConnection(ctx context.Context, cfg *config.DatabaseConfig) (*Connection, error) {
	conf, err := buildPoolConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: build pool config: %w", errors.ErrBoot, err)
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

func buildPoolConfig(ctx context.Context, cfg *config.DatabaseConfig) (*pgxpool.Config, error) {
	password := cfg.Password
	if cfg.Login == "aws" {
		password = ""
	}
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, password, cfg.Name, cfg.SSLMode,
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
	strategy, err := newPoolAuthStrategy(ctx, cfg.Login, defaultAuthDependencies())
	if err != nil {
		return nil, fmt.Errorf("configure database authentication: %w", err)
	}
	strategy(conf)
	return conf, nil
}
