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
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	embeddingopenai "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/openai"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"go.uber.org/dig"
)

type loadBalancerParams struct {
	dig.In
	EmbeddingRepo  embedding.Repository            `optional:"true"`
	ServiceLocator factory.EmbeddingServiceLocator `optional:"true"`
}

func LoadBalancer(c *container.Container) error {
	if err := c.Provide(func() factory.EmbeddingServiceLocator {
		return factory.NewServiceLocator(factory.ProviderRegistry{
			embeddingopenai.ProviderName: embeddingopenai.NewCreator(),
		})
	}); err != nil {
		return err
	}
	return c.Provide(func(p loadBalancerParams) loadbalancer.Factory {
		return loadbalancer.NewBaseFactory(p.EmbeddingRepo, p.ServiceLocator)
	})
}
