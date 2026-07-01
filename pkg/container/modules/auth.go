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
	"log/slog"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	authrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/auth"
)

func Auth(c *container.Container) error {
	if err := provideAuthRepository(c); err != nil {
		return err
	}
	return provideAuthServices(c)
}

func provideAuthRepository(c *container.Container) error {
	return c.Provide(func(conn *database.Connection) domain.Repository {
		return authrepo.NewRepository(conn)
	})
}

func provideAuthServices(c *container.Container) error {
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Creator {
		return appauth.NewCreator(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, consumerRepo consumerdomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Updater {
		return appauth.NewUpdater(repo, consumerRepo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, consumerRepo consumerdomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appauth.Deleter {
		return appauth.NewDeleter(repo, consumerRepo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewAPIKeyFinder); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewCredentialFinder); err != nil {
		return err
	}
	if err := c.Provide(appauth.NewOIDCFinder); err != nil {
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
	if err := c.Provide(authhttp.NewDeleteAuthHandler); err != nil {
		return err
	}
	return nil
}
