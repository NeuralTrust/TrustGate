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

	keygrouphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/keygroup"
	appkeygroup "github.com/NeuralTrust/TrustGate/pkg/app/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	keygrouprepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/keygroup"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
)

// KeyGroups registers the full plane's group budgets: the Postgres store, the
// use case the admin routes run and their handler. A data plane with no
// database reads the budgets from the config snapshot (CoreData).
func KeyGroups(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection, appender outboxrepo.Appender) keygroupdomain.Repository {
		return keygrouprepo.NewBudgetRepository(conn, appender)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo keygroupdomain.Repository) keygroupdomain.Reader { return repo }); err != nil {
		return err
	}
	if err := c.Provide(func(repo keygroupdomain.Repository, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appkeygroup.Budgets {
		return appkeygroup.NewBudgets(repo, publisher, logger, sig.Signaler, utcNow)
	}); err != nil {
		return err
	}
	return c.Provide(keygrouphttp.NewBudgetHandler)
}
