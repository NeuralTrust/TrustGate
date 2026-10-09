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

package regexreplace

import (
	"context"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nativeReq(op string, body string) *infracontext.RequestContext {
	req := reqCtx("bedrock", "bedrock_native", []byte(body))
	req.BedrockNative = &infracontext.BedrockNativeTarget{Op: bedrocknative.Op(op), ModelID: "m"}
	return req
}

// The forwarder turns any rewrite of a native Bedrock body into a block, which
// only works if a leg that finds nothing leaves the bytes alone: a plugin that
// re-serialised an unchanged body would block every request.
func TestNativeBedrock_NoMatchLeavesTheBytesAlone(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
	bodies := map[string]struct{ op, body string }{
		"converse":      {"converse", `{"messages":[{"role":"user","content":[{"text":"nothing to see"}]}]}`},
		"anthropic":     {"invoke", `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"nothing to see"}]}]}`},
		"titan":         {"invoke", `{"inputText":"nothing to see"}`},
		"llama prompt":  {"invoke", `{"prompt":"nothing to see","max_gen_len":10}`},
		"cohere":        {"invoke", `{"message":"nothing to see"}`},
		"chat messages": {"invoke-with-response-stream", `{"messages":[{"role":"user","content":"nothing to see"}]}`},
	}
	for name, tc := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			event, _ := newEvent()
			res, err := p.Execute(context.Background(),
				execInput(policy.StagePreRequest, policy.ModeEnforce, set, nativeReq(tc.op, tc.body), nil, event))
			assertPassThrough(t, res, err)
		})
	}
}

// The guardrail view is what makes a masking policy see an InvokeModel prompt at
// all: without it the plugin finds nothing in a Llama or Titan body.
func TestNativeBedrock_TheViewLetsAPolicySeeInvokeBodies(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := settings(targetRequest, maskRule("secret", "[REDACTED]"))
	bodies := map[string]string{
		"converse":     `{"messages":[{"role":"user","content":[{"text":"my secret code"}]}]}`,
		"anthropic":    `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":[{"type":"text","text":"my secret code"}]}]}`,
		"titan":        `{"inputText":"my secret code"}`,
		"llama prompt": `{"prompt":"my secret code","max_gen_len":10}`,
		"cohere":       `{"message":"my secret code"}`,
		"unknown":      `{"payload":{"prompt":"my secret code"}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			event, span := newEvent()
			op := "invoke"
			if name == "converse" {
				op = "converse"
			}
			res, err := p.Execute(context.Background(),
				execInput(policy.StagePreRequest, policy.ModeEnforce, set, nativeReq(op, body), nil, event))
			require.NoError(t, err)
			d := extras(t, span)
			assert.True(t, d.Changed, "the policy must have found the secret in %s", name)
			// The rewrite is reported to the forwarder, which refuses to forward it.
			assert.NotEmpty(t, res.RequestBody)
		})
	}
}

// on_mask_failure was removed: a mask that cannot be applied to a native Bedrock
// call always fails open. A policy stored with the key keeps loading, whatever
// its value, and the key changes nothing.
func TestOnMaskFailureIsIgnored(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	assert.Equal(t, appplugins.BedrockNativeMasks, appplugins.BedrockNativeOf(p))
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	for _, value := range []string{"pass", "block", "explode"} {
		set := settings(targetRequest, maskRule("a", "b"))
		set["on_mask_failure"] = value
		assert.NoError(t, p.ValidateConfig(set), value)
		assert.NoError(t, reg.Validate(p.Name(), set), value)
	}
}
