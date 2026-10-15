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
	"fmt"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/logger"
	infraopenapi "github.com/NeuralTrust/TrustGate/pkg/infra/openapi"
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
	if err := provideFieldSealer(c); err != nil {
		return err
	}
	return provideOutbox(c)
}

// provideFieldSealer registers the sealer the registry and auth repositories
// encrypt stored credentials with, keyed from SERVER_SECRET_KEY (provisioned
// the same way as for the vault cipher). It does not depend on the vault
// cipher, so a plane that never needed the key keeps booting without one: with
// STORED_SECRETS_ENCRYPTION_ENABLED off and no usable key the sealer is nil,
// writes stay unencrypted and an encrypted value reads as empty (logged).
func provideFieldSealer(c *container.Container) error {
	return c.Provide(func(cfg *config.Config, cc cache.Client, logger *slog.Logger) (*crypto.FieldSealer, error) {
		secret, err := resolveServerSecret(cfg, cc, logger)
		if err == nil {
			var sealer *crypto.FieldSealer
			if sealer, err = crypto.NewFieldSealer(secret, crypto.RegistrySecretsPurpose); err == nil {
				return sealer, nil
			}
		}
		if cfg.Server.StoredSecretsEncryptionEnabled {
			return nil, fmt.Errorf("STORED_SECRETS_ENCRYPTION_ENABLED needs a usable SERVER_SECRET_KEY: %w", err)
		}
		logger.Warn("stored credential encryption unavailable: no usable SERVER_SECRET_KEY; encrypted values read as empty",
			slog.String("component", "stored_secrets"), slog.String("error", err.Error()))
		return nil, nil
	})
}

// resolveServerSecret returns SERVER_SECRET_KEY. In prod an unset key is
// provisioned once through Redis and shared by every replica; it is written
// back into cfg so JWT managers (which hold a pointer to it) verify with the
// same secret.
func resolveServerSecret(cfg *config.Config, cc cache.Client, logger *slog.Logger) (string, error) {
	if cfg.Server.SecretKey != "" {
		return cfg.Server.SecretKey, nil
	}
	env := strings.ToLower(strings.TrimSpace(cfg.AppEnv))
	if env != "prod" && env != "production" {
		return "", nil
	}
	resolved, err := crypto.ResolveSharedSecretKey(context.Background(), cc.RedisClient(), logger)
	if err != nil {
		return "", err
	}
	cfg.Server.SecretKey = resolved
	return resolved, nil
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
	if err := c.Provide(infraopenapi.NewCompiler); err != nil {
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
	if err := c.Provide(func(cfg *config.Config) mcpoauth.Provider {
		return mcpoauth.NewGoogleWorkspace(
			cfg.Server.GoogleWorkspaceMCP.ClientID,
			cfg.Server.GoogleWorkspaceMCP.ClientSecret,
		)
	}); err != nil {
		return err
	}
	return c.Provide(func(cfg *config.Config, cc cache.Client, logger *slog.Logger) (vaultdomain.Encrypter, error) {
		secret, err := resolveServerSecret(cfg, cc, logger)
		if err != nil {
			return nil, err
		}
		return crypto.NewCipher(secret)
	})
}
