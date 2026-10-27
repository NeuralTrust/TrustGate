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

package prompttemplate

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A native Bedrock call is relayed as the client sent it, so a plugin that only
// transforms the request has nowhere to write. It declares it is skipped, and the
// executor skips it (appplugins.BedrockNativeAware); the executor tests cover the
// skip itself.
func TestDeclaresItIsSkippedOnNativeBedrockCalls(t *testing.T) {
	t.Parallel()
	assert.Equal(t, appplugins.BedrockNativeSkips, appplugins.BedrockNativeOf(New()))
}

func TestNativeBedrock_InjectsOnlyWhenThePolicyOptsIn(t *testing.T) {
	t.Parallel()
	p := New()
	assert.Equal(t, appplugins.BedrockNativeSkips, p.BedrockNativeFor(nil))
	assert.Equal(t, appplugins.BedrockNativeSkips, p.BedrockNativeFor(map[string]any{"apply_on_native_bedrock": false}))
	assert.Equal(t, appplugins.BedrockNativeInjects, p.BedrockNativeFor(map[string]any{"apply_on_native_bedrock": true}))
}

func nativeInjectSettings() map[string]any {
	return map[string]any{
		"apply_on_native_bedrock": true,
		"inject_templates": []any{
			map[string]any{"id": "sys", "role": "system", "content": "Be brief."},
		},
	}
}

func runNativeTemplate(t *testing.T, op bedrocknative.Op, body string, mode policy.Mode) (*appplugins.Result, error) {
	t.Helper()
	return New().Execute(context.Background(), appplugins.ExecInput{
		Stage:  policy.StagePreRequest,
		Mode:   mode,
		Config: policy.PluginConfig{Settings: nativeInjectSettings()},
		Request: &infracontext.RequestContext{
			Body:          []byte(body),
			Provider:      "bedrock",
			SourceFormat:  "bedrock_native",
			BedrockNative: &infracontext.BedrockNativeTarget{Op: op, ModelID: "m"},
		},
	})
}

func TestNativeBedrock_InjectsAndKeepsEveryOtherByte(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		op   bedrocknative.Op
		body string
		want string
	}{
		{
			name: "converse with a client cachePoint",
			op:   bedrocknative.Converse,
			body: `{"system": [{"text": "Hi"}, {"cachePoint": {"type": "default"}}],
  "messages": [{"role": "user", "content": [{"text": "q"}]}],
  "inferenceConfig": {"maxTokens": 10},
  "additionalModelRequestFields": {"thinking": {"type": "enabled", "budget_tokens": 1024}}}`,
			want: `{"system": [{"text":"Hi"},{"cachePoint":{"type":"default"}},{"text":"Be brief."}],
  "messages": [{"role": "user", "content": [{"text": "q"}]}],
  "inferenceConfig": {"maxTokens": 10},
  "additionalModelRequestFields": {"thinking": {"type": "enabled", "budget_tokens": 1024}}}`,
		},
		{
			name: "converse stream without a system",
			op:   bedrocknative.ConverseStream,
			body: `{"messages": [{"role": "user", "content": [{"text": "q"}]}], "outputConfig": {"x": 1}}`,
			want: `{"messages": [{"role": "user", "content": [{"text": "q"}]}], "outputConfig": {"x": 1},"system":[{"text":"Be brief."}]}`,
		},
		{
			name: "invoke with an Anthropic body",
			op:   bedrocknative.Invoke,
			body: `{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 5, "system": "Hi", "messages": [{"role": "user", "content": "q"}]}`,
			want: `{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 5, "system": "Hi\n\nBe brief.", "messages": [{"role": "user", "content": "q"}]}`,
		},
		{
			name: "invoke stream with an OpenAI body",
			op:   bedrocknative.InvokeStream,
			body: `{"messages": [{"role": "user", "content": "q"}], "max_completion_tokens": 5, "reasoning_effort": "low"}`,
			want: `{"messages": [{"role":"system","content":"Be brief."},{"role":"user","content":"q"}], "max_completion_tokens": 5, "reasoning_effort": "low"}`,
		},
		{
			name: "invoke with a Converse body",
			op:   bedrocknative.Invoke,
			body: `{"messages": [{"role": "user", "content": [{"text": "q"}]}], "inferenceConfig": {"maxTokens": 10}}`,
			want: `{"messages": [{"role": "user", "content": [{"text": "q"}]}], "inferenceConfig": {"maxTokens": 10},"system":[{"text":"Be brief."}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := runNativeTemplate(t, tc.op, tc.body, policy.ModeEnforce)
			require.NoError(t, err)
			require.NotNil(t, res.RequestBody)
			assert.Equal(t, tc.want, string(res.RequestBody))
		})
	}
}

func TestNativeBedrock_PromptShapesAreNeverSkippedSilently(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"llama prompt": `{"prompt": "<|begin_of_text|>q", "max_gen_len": 5}`,
		"titan":        `{"inputText": "q"}`,
	} {
		t.Run(name+" is refused in enforce", func(t *testing.T) {
			t.Parallel()
			_, err := runNativeTemplate(t, bedrocknative.Invoke, body, policy.ModeEnforce)
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok, "%v", err)
			assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
			assert.Equal(t, typeUnsupportedShape, pe.Type)
			assert.Contains(t, pe.Message, "unsupported_native_shape")
		})
		t.Run(name+" is recorded as skipped in observe", func(t *testing.T) {
			t.Parallel()
			res, err := runNativeTemplate(t, bedrocknative.Invoke, body, policy.ModeObserve)
			require.NoError(t, err)
			assert.Nil(t, res.RequestBody)
		})
	}
}
