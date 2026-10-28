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

package configsnapshot_test

import (
	"context"
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func usageCompiler(t *testing.T, opts ...appsnapshot.CompilerOption) *appsnapshot.Compiler {
	t.Helper()
	return twoTenantCompiler(t,
		mustGatewayID(t, capsAcme), mustGatewayID(t, capsGlobex),
		mustConsumerID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), mustConsumerID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc"),
		opts...)
}

func TestCompileStampsUsageEnforcementOnEveryFlavor(t *testing.T) {
	t.Parallel()
	compiler := usageCompiler(t, appsnapshot.WithUsageEnforcement(true))

	single, err := compiler.CompileFor(context.Background(), capsAcme)
	require.NoError(t, err)
	assert.True(t, single.UsageEnforcement())

	global, scoped, _, err := compiler.CompileAll(context.Background())
	require.NoError(t, err)
	assert.True(t, global.UsageEnforcement())
	require.NotEmpty(t, scoped)
	for scope, snap := range scoped {
		assert.True(t, snap.UsageEnforcement(), scope)
	}
}

func TestCompileWithoutUsageEnforcementLeavesFlagOff(t *testing.T) {
	t.Parallel()
	global, _, _, err := usageCompiler(t).CompileAll(context.Background())
	require.NoError(t, err)
	assert.False(t, global.UsageEnforcement())
}
