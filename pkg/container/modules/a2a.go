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
	a2ahttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/a2a"
	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	infraa2a "github.com/NeuralTrust/TrustGate/pkg/infra/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infrasts "github.com/NeuralTrust/TrustGate/pkg/infra/identity/sts"
)

// A2A provides the agent plane's forwarding: upstream client, policies,
// credentials, task ownership, forwarder and handler.
func A2A(c *container.Container) error {
	for _, provider := range []any{
		infraa2a.NewUpstreamClient,
		appa2a.NewPluginRunner,
		func(exchanger sts.Exchanger, provider appoauth.ProviderClient, cloud *infraa2a.CloudSigner, signer *infrasts.Signer, cfg *config.Config) *appa2a.Credentials {
			return appa2a.NewCredentials(exchanger, provider, cloud, signer.Ephemeral(), a2aCredentialOptions(cfg)...)
		},
		func(cc cache.Client) appa2a.OwnershipStore {
			return infraa2a.NewOwnershipStore(cc.RedisClient())
		},
		appa2a.NewForwarder,
		a2ahttp.NewHandler,
	} {
		if err := c.Provide(provider); err != nil {
			return err
		}
	}
	return nil
}

// a2aCredentialOptions turns the shared data plane checks on for a saas
// deployment, as registrySaveParams does for saves.
func a2aCredentialOptions(cfg *config.Config) []appa2a.CredentialsOption {
	if cfg != nil && cfg.ConfigSync.SharedDataPlane() {
		return []appa2a.CredentialsOption{appa2a.WithSharedDataPlane()}
	}
	return nil
}
