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

package modelallowlist

import (
	"context"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nativeRequest(modelID string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		SourceFormat:  "bedrock",
		Body:          []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse", ModelID: modelID, RawModelID: modelID},
	}
}

// A native Bedrock call carries its model in the path. The body is relayed as
// received, so the plugin may check the model but must never default or
// substitute one: either would rewrite the body and turn every request into a
// block.
func TestPlugin_NativeBedrockChecksThePathModelAndNeverRewrites(t *testing.T) {
	t.Parallel()
	allow := func(extra map[string]any) map[string]any {
		s := map[string]any{"allowed_models": []string{"amazon.nova-*"}}
		for k, v := range extra {
			s[k] = v
		}
		return s
	}
	tests := []struct {
		name       string
		mode       policy.Mode
		settings   map[string]any
		model      string
		wantReject bool
	}{
		{"allowed model passes untouched", policy.ModeEnforce, allow(nil), "amazon.nova-lite-v1:0", false},
		{"a default_model is never injected into the body", policy.ModeEnforce, allow(map[string]any{"default_model": "amazon.nova-lite-v1:0"}), "amazon.nova-lite-v1:0", false},
		{"disallowed model is rejected", policy.ModeEnforce, allow(map[string]any{"behavior_on_disallowed": "reject"}), "meta.llama3-8b-instruct-v1:0", true},
		{"substitute cannot rewrite a native body, so it rejects", policy.ModeEnforce,
			allow(map[string]any{"behavior_on_disallowed": "substitute", "substitute_with": "amazon.nova-lite-v1:0"}), "meta.llama3-8b-instruct-v1:0", true},
		{"observe never blocks", policy.ModeObserve, allow(map[string]any{"behavior_on_disallowed": "reject"}), "meta.llama3-8b-instruct-v1:0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := New().Execute(context.Background(), input(tt.mode, tt.settings, nativeRequest(tt.model)))
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Nil(t, res.RequestBody, "the body of a native call must never be rewritten")
			if tt.wantReject {
				assert.True(t, res.StopUpstream)
				assert.Equal(t, http.StatusForbidden, res.StatusCode)
				return
			}
			assert.False(t, res.StopUpstream)
			assert.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}
