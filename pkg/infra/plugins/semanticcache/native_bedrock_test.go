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

package semanticcache

import (
	"context"
	"encoding/json"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A native Bedrock call is relayed as the client sent it, so a plugin that only
// transforms the request has nowhere to write. It declares it is skipped, and the
// executor skips it (appplugins.BedrockNativeAware); the executor tests cover the
// skip itself.
func TestDeclaresItIsSkippedOnNativeBedrockCalls(t *testing.T) {
	t.Parallel()
	assert.Equal(t, appplugins.BedrockNativeSkips, appplugins.BedrockNativeOf(New(nil, nil, nil)))
}

// The span of a skipped semantic cache keeps the shape the console renders for the
// plugin: the cache fields (never a hit, the threshold, the scope and mode), and the
// skip reason beside them.
func TestSkippedOnNativeBedrock_SpanKeepsTheSemanticCacheShape(t *testing.T) {
	t.Parallel()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(New(nil, nil, nil)))
	pols := []*policy.Policy{{
		ID: ids.New[ids.PolicyKind](), Name: PluginName, Slug: PluginName, Enabled: true, Priority: 10,
		Stages: []policy.Stage{policy.StagePreRequest}, Settings: baseSettings(),
	}}
	rt := trace.New("t", trace.Metadata{})
	req := &infracontext.RequestContext{
		Body:          openAIBody(),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse", ModelID: "m"},
	}
	_, err := appplugins.NewExecutor(reg, nil).RunStage(trace.NewContext(context.Background(), rt), appplugins.StageInput{
		Stage: policy.StagePreRequest, Policies: pols, Request: req, Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)

	var extras map[string]any
	for _, span := range rt.Spans() {
		if span.Type == trace.SpanPlugin {
			raw, err := json.Marshal(span.PluginAttrsCopy().Extras)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &extras))
		}
	}
	assert.Equal(t, "native_bedrock_passthrough", extras["skip_reason"])
	assert.Equal(t, false, extras["cache_hit"])
	assert.InDelta(t, 0.8, extras["threshold"], 1e-9)
	assert.Contains(t, extras, "scope")
	assert.Contains(t, extras, "mode")
	assert.Equal(t, true, extras["skipped"], "and the generic marker the console reads on every skipped entry")
}
