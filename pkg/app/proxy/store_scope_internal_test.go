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

package proxy

import (
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/stretchr/testify/assert"
)

func scopeRegistry(provider string) *domain.Registry {
	return &domain.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &domain.LLMTarget{Provider: provider}}
}

func TestScopedLink_PrimaryIsOneRule(t *testing.T) {
	mistral, openai, deepseek, outside := scopeRegistry("mistral"), scopeRegistry("openai"), scopeRegistry("deepseek"), scopeRegistry("groq")
	group := appconsumer.StoreLink{
		Consumer: &appconsumer.RoutableConsumer{
			Consumer:         &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind]()},
			Registries:       []*domain.Registry{mistral, openai},
			FallbackBackends: []*domain.Registry{deepseek},
		},
		Link: domainconsumer.AuthLink{Level: domainconsumer.GrantLevelGroup},
	}
	user := appconsumer.StoreLink{
		Consumer: &appconsumer.RoutableConsumer{
			Consumer:   &domainconsumer.Consumer{ID: ids.New[ids.ConsumerKind]()},
			Registries: []*domain.Registry{scopeRegistry("openai")},
		},
		Link: domainconsumer.AuthLink{Level: domainconsumer.GrantLevelUser},
	}
	links := storeScope([]appconsumer.StoreLink{user, group})
	scoped := &links[1]

	tests := []struct {
		name      string
		candidate routingdomain.Candidate
		want      bool
	}{
		{name: "a registry of the consumer", candidate: routingdomain.Candidate{Registry: mistral, Sources: []string{"consumer"}}, want: true},
		{name: "a substituted provider", candidate: routingdomain.Candidate{Registry: openai, Sources: []string{"consumer"}}},
		{name: "a fallback", candidate: routingdomain.Candidate{Registry: deepseek, Sources: []string{routingdomain.SourceFallback}}},
		{name: "a pool member reached only as a fallback", candidate: routingdomain.Candidate{Registry: deepseek, Sources: []string{"pool:fast"}}},
		{name: "a registry the consumer does not hold", candidate: routingdomain.Candidate{Registry: outside, Sources: []string{"consumer"}}},
		{name: "no registry", candidate: routingdomain.Candidate{Sources: []string{"consumer"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, scoped.primary(tt.candidate))
		})
	}
}
