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

package strategies

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	embeddingmocks "github.com/NeuralTrust/TrustGate/pkg/domain/embedding/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory/mocks"
	"github.com/stretchr/testify/mock"
)

func TestSemantic_CachesBackendEmbeddingsAcrossRequests(t *testing.T) {
	t.Parallel()

	backendA := &registry.Registry{ID: ids.New[ids.RegistryKind](), Name: "a", Description: "alpha", LLMTarget: &registry.LLMTarget{Provider: "openai"}}
	backendB := &registry.Registry{ID: ids.New[ids.RegistryKind](), Name: "b", Description: "beta", LLMTarget: &registry.LLMTarget{Provider: "openai"}}

	repo := embeddingmocks.NewRepository(t)
	repo.EXPECT().GetByTargetID(mock.Anything, backendA.ID.String()).
		Return(&embedding.Embedding{Value: []float64{1, 0}}, nil).Once()
	repo.EXPECT().GetByTargetID(mock.Anything, backendB.ID.String()).
		Return(&embedding.Embedding{Value: []float64{0, 1}}, nil).Once()

	creator := embeddingmocks.NewCreator(t)
	creator.EXPECT().Generate(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&embedding.Embedding{Value: []float64{1, 0}}, nil)

	locator := factorymocks.NewEmbeddingServiceLocator(t)
	locator.EXPECT().GetService(mock.Anything).Return(creator, nil)

	s := NewSemantic(&embedding.Config{Provider: "openai", Model: "m"},
		[]*registry.Registry{backendA, backendB}, repo, locator)

	req := &infracontext.RequestContext{Body: []byte(`{"prompt":"hello"}`)}
	for i := 0; i < 3; i++ {
		got := s.Next(context.Background(), req, nil)
		if got == nil || got.ID != backendA.ID {
			t.Fatalf("request %d: expected backend A (highest similarity), got %+v", i, got)
		}
	}
}
