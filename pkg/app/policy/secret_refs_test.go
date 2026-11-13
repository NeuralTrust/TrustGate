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

package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

type refusingRefs struct{ got appsecretref.EntityRefs }

func (r *refusingRefs) ValidateEntity(_ context.Context, current appsecretref.EntityRefs, _ *appsecretref.Stored) (func(), error) {
	r.got = current
	return nil, refdomain.ErrMissingScope
}

func TestCreator_RefusedPluginSecretReferenceIsNotSaved(t *testing.T) {
	t.Parallel()
	refs := &refusingRefs{}
	creator := apppolicy.NewCreator(repomocks.NewRepository(t), freeLevels(t), newRegistryRepo(t), credentialRegistryMock(t),
		newCacheManager(), newTestLogger(), nil, apppolicy.WithSecretRefValidator(refs))

	_, err := creator.Create(context.Background(), apppolicy.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](), Name: "moderate", Slug: azureSlug, Enabled: true, Mode: domain.ModeEnforce,
		Settings: map[string]any{"api_key": "secret://vault/azure#key", "endpoint": "https://cs.example.com"},
	})
	require.ErrorIs(t, err, refdomain.ErrMissingScope)
	require.Len(t, refs.got.Uses, 1)
	assert.Equal(t, "settings.api_key", strings.Join(refs.got.Uses[0].Path, "."))
	assert.Contains(t, refs.got.Destination, "endpoint=https://cs.example.com", "the endpoint the key is sent to is the policy's destination")
}
