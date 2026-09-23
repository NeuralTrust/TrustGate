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
	"time"

	policyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	policyrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	"go.uber.org/dig"
)

// credentialBackfillTimeout bounds the one-shot startup pass that converges
// legacy plaintext policy credentials to encrypted (see
// policyrepo.Repository.BackfillCredentialEncryption). It is generous
// compared to catalogSyncTimeout because it walks every policy row rather
// than calling one external API; a timeout mid-pass is not data loss — it
// just leaves the remaining rows for the next boot, same as before this
// feature existed for those rows.
const credentialBackfillTimeout = 5 * time.Minute

func Policy(c *container.Container) error {
	if err := providePolicyRepository(c); err != nil {
		return err
	}
	return providePolicyServices(c)
}

func providePolicyRepository(c *container.Container) error {
	if err := c.Provide(func(
		conn *database.Connection,
		appender outboxrepo.Appender,
		cipher vaultdomain.Encrypter,
		registry appplugins.Registry,
	) *policyrepo.Repository {
		return policyrepo.NewRepository(conn, appender, cipher, registry)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(r *policyrepo.Repository) apppolicy.LevelLock { return r }); err != nil {
		return err
	}
	return c.Provide(func(r *policyrepo.Repository) domain.Repository { return r })
}

func providePolicyServices(c *container.Container) error {
	if err := c.Provide(apppolicy.NewLevelGuard); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, levels apppolicy.LevelGuard, registryRepo registrydomain.Repository, registry appplugins.Registry, manager *cache.TTLMapManager, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Creator {
		return apppolicy.NewCreator(repo, levels, registryRepo, registry, manager, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, consumers consumerdomain.Reader, levels apppolicy.LevelGuard, registryRepo registrydomain.Repository, registry appplugins.Registry, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Updater {
		return apppolicy.NewUpdater(repo, consumers, levels, registryRepo, registry, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Deleter {
		return apppolicy.NewDeleter(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, levels apppolicy.LevelGuard, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Scoper {
		return apppolicy.NewScoper(repo, levels, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewDuplicator); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, consumers consumerdomain.Reader, auths authdomain.Repository, registry appplugins.Registry) apppolicy.Warner {
		return apppolicy.NewWarner(repo, consumers, auths, registry)
	}); err != nil {
		return err
	}

	if err := c.Provide(policyhttp.NewCreatePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewGetPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewListPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewUpdatePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewDeletePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewGlobalPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewDuplicatePolicyHandler); err != nil {
		return err
	}
	return nil
}

// CredentialBackfillParams is the dig.In for StartCredentialBackfill.
type CredentialBackfillParams struct {
	dig.In
	Logger *slog.Logger
	Repo   *policyrepo.Repository
}

// StartCredentialBackfill runs policyrepo.Repository.BackfillCredentialEncryption
// once in the background at boot, on the same planes and in the same
// fire-and-forget shape as StartCatalogSync: it must never block or fail
// startup, because every policy read already tolerates legacy plaintext (see
// scanPolicy) — this backfill only shortens how long a row stays that way at
// rest.
func StartCredentialBackfill(p CredentialBackfillParams) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), credentialBackfillTimeout)
		defer cancel()
		n, err := p.Repo.BackfillCredentialEncryption(ctx)
		if err != nil {
			p.Logger.Warn("policy credential backfill failed, will retry on next boot",
				slog.String("error", err.Error()))
			return
		}
		if n > 0 {
			p.Logger.Info("policy credential backfill encrypted legacy rows", slog.Int("rows", n))
		}
	}()
}
