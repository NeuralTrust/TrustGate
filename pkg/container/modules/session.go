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

	appsession "github.com/NeuralTrust/TrustGate/pkg/app/session"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	sessiondomain "github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	sessionrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/session"
)

func Session(c *container.Container) error {
	if err := c.Provide(func(cc cache.Client) sessiondomain.Repository {
		return sessionrepo.NewRepository(cc.RedisClient())
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		repo sessiondomain.Repository,
		cfg *config.Config,
		logger *slog.Logger,
	) *appsession.Service {
		return appsession.NewService(repo, cfg, logger)
	}); err != nil {
		return err
	}
	return c.Provide(func(s *appsession.Service) appsession.Store { return s })
}
