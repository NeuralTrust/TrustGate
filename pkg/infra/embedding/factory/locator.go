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

package factory

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
)

const (
	OpenAIProvider = "openai"
)

//go:generate mockery --name=EmbeddingServiceLocator --dir=. --output=./mocks --filename=embedding_locator_mock.go --case=underscore --with-expecter
type EmbeddingServiceLocator interface {
	GetService(provider string) (embedding.Creator, error)
}

type ProviderRegistry map[string]embedding.Creator

func NewServiceLocator(providers ProviderRegistry) EmbeddingServiceLocator {
	if providers == nil {
		providers = make(ProviderRegistry)
	}
	return &embeddingServiceLocator{providers: providers}
}

var _ EmbeddingServiceLocator = (*embeddingServiceLocator)(nil)

type embeddingServiceLocator struct {
	providers ProviderRegistry
}

func (l *embeddingServiceLocator) GetService(provider string) (embedding.Creator, error) {
	if svc, ok := l.providers[provider]; ok {
		return svc, nil
	}
	return nil, fmt.Errorf("unsupported embedding provider: %s", provider)
}
