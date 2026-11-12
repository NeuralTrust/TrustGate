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

	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	"github.com/NeuralTrust/TrustGate/pkg/common/keyscope"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
)

// STS provides the gateway's token signer. Every plane that mints or verifies
// gateway tokens takes it from here, so they all publish one key.
func STS(c *container.Container) error {
	if err := c.Provide(func(cfg *config.Config, cc cache.Client, logger *slog.Logger) (*infrasts.Signer, error) {
		keyPEM := cfg.Server.STSSigningKey
		if keyPEM == "" {
			env := strings.ToLower(strings.TrimSpace(cfg.AppEnv))
			if env == "prod" || env == "production" {
				resolved, err := infrasts.ResolveSharedSigningKey(context.Background(), cc.RedisClient(), keyscope.Scope(cfg.Redis.KeyScope), logger)
				if err != nil {
					return nil, err
				}
				keyPEM = resolved
			}
		}
		return infrasts.NewSigner(cfg.Server.STSIssuer, keyPEM, logger)
	}); err != nil {
		return err
	}
	return c.Provide(func(s *infrasts.Signer) sts.TokenSigner { return s })
}
