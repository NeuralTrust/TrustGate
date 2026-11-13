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

package consumer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

type refusingRefs struct{ got appsecretref.EntityRefs }

func (r *refusingRefs) ValidateEntity(_ context.Context, current appsecretref.EntityRefs, _ *appsecretref.Stored) (func(), error) {
	r.got = current
	return nil, refdomain.ErrMissingScope
}

func TestCreator_RefusedSecretReferenceIsNotSaved(t *testing.T) {
	t.Parallel()
	refs := &refusingRefs{}
	creator := appconsumer.NewCreator(repomocks.NewRepository(t), registrymocks.NewRepository(t), gatewaymocks.NewRepository(t),
		newCacheManager(), nil, newTestLogger(), nil, appconsumer.WithSecretRefValidator(refs))

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "chat", Type: domain.TypeLLM,
		LBConfig: &domain.LBConfig{EmbeddingConfig: &registrydomain.EmbeddingConfig{
			Provider: "openai", Model: "text-embedding-3-small", Auth: &registrydomain.APIKeyAuth{APIKey: "secret://vault/emb#k"},
		}},
	})
	require.ErrorIs(t, err, refdomain.ErrMissingScope)
	require.Len(t, refs.got.Uses, 1)
	assert.Equal(t, "lb_config.embedding_config.auth.api_key", strings.Join(refs.got.Uses[0].Path, "."))
}
