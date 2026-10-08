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
	"fmt"
	"log/slog"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/console"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	authrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/auth"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
)

func Auth(c *container.Container) error {
	if err := provideAuthRepository(c); err != nil {
		return err
	}
	if err := provideAuthServices(c); err != nil {
		return err
	}
	return providePersonalKeyIssuer(c)
}

// providePersonalKeyIssuer is the full plane's: it writes the database. A data
// plane with no database gets the config-sync client instead (ConfigSyncData).
func providePersonalKeyIssuer(c *container.Container) error {
	// It tells the console about every change when CONSOLE_EVENTS_URL is set,
	// so the console audits it and links a new key to its models.
	return c.Provide(func(cfg *config.Config, keys appauth.PersonalKeys, groups appauth.OwnerGroupsSetter, gateways gatewaydomain.Repository, logger *slog.Logger) (appauth.PersonalKeyIssuer, error) {
		var opts []appauth.PersonalKeyIssuerOption
		if endpoint := cfg.Server.ConsoleEventsURL; endpoint != "" {
			events, err := console.NewPersonalKeyEvents(endpoint, cfg.Server.SecretKey, nil)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", commonerrors.ErrInvalidConfig, err)
			}
			opts = append(opts, appauth.WithPersonalKeyNotifier(events, gateways))
		}
		return appauth.NewPersonalKeyIssuer(keys, groups, logger, utcNow, opts...), nil
	})
}

func provideAuthRepository(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection, appender outboxrepo.Appender, sealer *crypto.FieldSealer, cfg *config.Config) *authrepo.Repository {
		return authrepo.NewRepository(conn, appender, authrepo.WithFieldSealer(sealer, cfg.Server.StoredSecretsEncryptionEnabled))
	}); err != nil {
		return err
	}
	return c.Provide(func(r *authrepo.Repository) domain.Repository {
		return r
	})
}

func provideAuthServices(c *container.Container) error {
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Creator {
		return appauth.NewCreator(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, consumerRepo consumerdomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Updater {
		return appauth.NewUpdater(repo, consumerRepo, manager, publisher, logger, sig.Signaler, utcNow)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Rotator {
		return appauth.NewRotator(repo, manager, publisher, logger, sig.Signaler, utcNow)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.OwnerGroupsSetter {
		return appauth.NewOwnerGroupsSetter(repo, manager, publisher, logger, sig.Signaler, utcNow)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.BudgetSetter {
		return appauth.NewBudgetSetter(repo, manager, publisher, logger, sig.Signaler, utcNow)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, consumerRepo consumerdomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Deleter {
		return appauth.NewDeleter(repo, consumerRepo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) *appauth.KeyEvents {
		return appauth.NewKeyEvents(manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, links consumerdomain.LinkReader, gateways gatewaydomain.Repository, rotator appauth.Rotator, deleter appauth.Deleter, events *appauth.KeyEvents) appauth.PersonalKeys {
		return appauth.NewPersonalKeys(repo, links, gateways, rotator, deleter, events, utcNow)
	}); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewAPIKeyFinder); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger, cfg *config.Config) appauth.CredentialFinder {
		defaultIdP := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
			Issuer:       cfg.Server.MCPDefaultIdP.Issuer,
			AuthorizeURL: cfg.Server.MCPDefaultIdP.AuthorizeURL,
			TokenURL:     cfg.Server.MCPDefaultIdP.TokenURL,
			JWKSURL:      cfg.Server.MCPDefaultIdP.JWKSURL,
			ClientID:     cfg.Server.MCPDefaultIdP.ClientID,
			ClientSecret: cfg.Server.MCPDefaultIdP.ClientSecret,
			Audiences:    cfg.Server.MCPDefaultIdP.Audiences,
			Scopes:       cfg.Server.MCPDefaultIdP.Scopes,
		})
		if defaultIdP != nil {
			logger.Info("mcp: built-in NeuralTrust default identity provider enabled",
				slog.String("issuer", defaultIdP.Config.OAuth2.Issuer))
		}
		return appauth.NewCredentialFinder(repo, manager, logger, defaultIdP)
	}); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewIdentityProviderFinder); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewOAuth2Verifier); err != nil {
		return err
	}

	if err := c.Provide(authhttp.NewCreateAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewGetAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewListAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewUpdateAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewRotateAuthHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewUpdateAuthOwnerGroupsHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewUpdateAuthBudgetHandler); err != nil {
		return err
	}
	if err := c.Provide(authhttp.NewDeleteAuthHandler); err != nil {
		return err
	}
	return nil
}
