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

package trustguard

import (
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// on_mask_failure was removed: a mask that cannot be applied to a native Bedrock
// call always fails open. A policy stored with the key keeps loading, whatever
// its value, and the key changes nothing.
func TestOnMaskFailureIsIgnored(t *testing.T) {
	t.Parallel()
	p := newTestPlugin(t, adapter.NewRegistry(), "http://127.0.0.1")
	assert.Equal(t, appplugins.BedrockNativeMasks, appplugins.BedrockNativeOf(p))
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	for _, value := range []string{"pass", "block", "explode"} {
		set := settings("request")
		set["on_mask_failure"] = value
		assert.NoError(t, p.ValidateConfig(set), value)
		assert.NoError(t, reg.Validate(p.Name(), set), value)
	}
}
