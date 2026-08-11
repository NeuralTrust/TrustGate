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

package modules

import (
	"context"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/logger"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
)

func Core(c *container.Container) error {
	if err := provideRuntimeBase(c); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *config.DatabaseConfig {
		return &cfg.Database
	}); err != nil {
		return err
	}
	if err := c.Provide(database.NewConnectionProvider); err != nil {
		return err
	}
	if err := c.Provide(database.NewMigrationsManagerProvider); err != nil {
		return err
	}
	return provideOutbox(c)
}

// provideOutbox registers the config-snapshot change-marker outbox repository and
// binds it as the infra Appender the config-mutating admin repositories share.
// The control plane additionally binds it as the app-side OutboxRepository the
// dispatcher drains (in ControlConfigSync).
func provideOutbox(c *container.Container) error {
	if err := c.Provide(outboxrepo.NewRepository); err != nil {
		return err
	}
	return c.Provide(func(r *outboxrepo.Repository) outboxrepo.Appender {
		return r
	})
}

func provideRuntimeBase(c *container.Container) error {
	if err := c.Provide(config.LoadConfig); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) *slog.Logger {
		log := logger.NewLoggerWithFormat(cfg.Logger.Level, logger.LogFormat(cfg.Logger.Format), cfg.Logger.FileEnabled)
		slog.SetDefault(log)
		return log
	}); err != nil {
		return err
	}
	if err := c.Provide(func() context.Context {
		return context.Background()
	}); err != nil {
		return err
	}
	return c.Provide(func(cfg *config.Config, cc cache.Client, logger *slog.Logger) (vaultdomain.Encrypter, error) {
		secret := cfg.Server.SecretKey
		if secret == "" {
			env := strings.ToLower(strings.TrimSpace(cfg.AppEnv))
			if env == "prod" || env == "production" {
				resolved, err := crypto.ResolveSharedSecretKey(context.Background(), cc.RedisClient(), logger)
				if err != nil {
					return nil, err
				}
				secret = resolved
				// Mutate the shared ServerConfig so JWT managers (which hold a
				// pointer to it) verify with the same secret as the vault cipher.
				cfg.Server.SecretKey = resolved
			}
		}
		return crypto.NewCipher(secret)
	})
}
