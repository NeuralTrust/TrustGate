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

package plugins

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nativeFake is a fakePlugin that declares what it does on a native Bedrock call.
type nativeFake struct {
	fakePlugin
	behavior BedrockNativeBehavior
}

func (n *nativeFake) BedrockNative() BedrockNativeBehavior { return n.behavior }

func nativeRequest(body string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Body:          []byte(body),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse", ModelID: "m"},
		NativeMask:    &infracontext.NativeMaskLog{},
	}
}

func runNative(t *testing.T, stage policy.Stage, req *infracontext.RequestContext, resp *infracontext.ResponseContext, p Plugin, settings map[string]any, mode policy.Mode) (*StageOutcome, *trace.RequestTrace, error) {
	t.Helper()
	pols := policies(t, polSpec{slug: p.Name(), enabled: true, priority: 10, stages: []policy.Stage{stage}, mode: mode})
	pols[0].Settings = settings
	rt := trace.New("t", trace.Metadata{})
	out, err := NewExecutor(newRegistry(t, p), nil).RunStage(trace.NewContext(context.Background(), rt), StageInput{
		Stage: stage, Policies: pols, Request: req, Response: resp,
	})
	return out, rt, err
}

func TestNativeBedrock_ASkippingPluginIsNotRunAndSaysSo(t *testing.T) {
	t.Parallel()
	var calls int32
	p := &nativeFake{fakePlugin: fakePlugin{name: "tmpl", stages: []policy.Stage{policy.StagePreRequest}, calls: &calls,
		result: &Result{StatusCode: 200, RequestBody: []byte(`{"templated":true}`)}}, behavior: BedrockNativeSkips}

	req := nativeRequest(`{"messages":[]}`)
	_, rt, err := runNative(t, policy.StagePreRequest, req, &infracontext.ResponseContext{}, p, nil, policy.ModeEnforce)
	require.NoError(t, err)
	assert.Zero(t, atomic.LoadInt32(&calls), "the plugin never ran")
	assert.Equal(t, `{"messages":[]}`, string(req.Body))

	var extras []byte
	for _, s := range rt.Spans() {
		if s.Type == trace.SpanPlugin {
			extras, _ = json.Marshal(s.PluginAttrsCopy().Extras)
		}
	}
	assert.JSONEq(t, `{"stage":"pre_request","skipped":true,"skip_reason":"native_bedrock_passthrough"}`, string(extras))

	// The same plugin runs on a call that is not native.
	plain := &infracontext.RequestContext{Body: []byte(`{"messages":[]}`)}
	_, _, err = runNative(t, policy.StagePreRequest, plain, &infracontext.ResponseContext{}, p, nil, policy.ModeEnforce)
	require.NoError(t, err)
	assert.EqualValues(t, 1, atomic.LoadInt32(&calls))
}

func TestNativeBedrock_ARewriteByAPluginThatDoesNotMaskIsRefused(t *testing.T) {
	t.Parallel()
	t.Run("a plugin that rewrites for enforcement", func(t *testing.T) {
		t.Parallel()
		p := &nativeFake{fakePlugin: fakePlugin{name: "tool_allowlist", stages: []policy.Stage{policy.StagePreRequest},
			result: &Result{StatusCode: 200, RequestBody: []byte(`{"stripped":true}`)}}, behavior: BedrockNativeRuns}
		req := nativeRequest(`{"tools":["a","b"]}`)
		_, _, err := runNative(t, policy.StagePreRequest, req, &infracontext.ResponseContext{}, p, nil, policy.ModeEnforce)
		pe, ok := AsPluginError(err)
		require.True(t, ok, "%v", err)
		assert.Equal(t, http.StatusForbidden, pe.StatusCode)
		assert.Equal(t, BedrockNativePassthrough, pe.Type)
		assert.Empty(t, req.NativeMask.Sources("pre_request"), "not recorded as a mask")
	})
	t.Run("a plugin that changes nothing is not refused", func(t *testing.T) {
		t.Parallel()
		p := &nativeFake{fakePlugin: fakePlugin{name: "guard", stages: []policy.Stage{policy.StagePreRequest},
			result: &Result{StatusCode: 200, RequestBody: []byte(`{"same":true}`)}}, behavior: BedrockNativeRuns}
		req := nativeRequest(`{"same":true}`)
		_, _, err := runNative(t, policy.StagePreRequest, req, &infracontext.ResponseContext{}, p, nil, policy.ModeEnforce)
		require.NoError(t, err)
	})
	t.Run("observe never rewrites: its body is dropped, not refused", func(t *testing.T) {
		t.Parallel()
		for name, behavior := range map[string]BedrockNativeBehavior{"runs": BedrockNativeRuns, "masks": BedrockNativeMasks} {
			p := &nativeFake{fakePlugin: fakePlugin{name: "tool_allowlist", stages: []policy.Stage{policy.StagePreRequest},
				result: &Result{StatusCode: 200, RequestBody: []byte(`{"stripped":true}`)}}, behavior: behavior}
			req := nativeRequest(`{"tools":[]}`)
			_, _, err := runNative(t, policy.StagePreRequest, req, &infracontext.ResponseContext{}, p, nil, policy.ModeObserve)
			require.NoError(t, err, name)
			assert.Equal(t, `{"tools":[]}`, string(req.Body), "%s: observe left the call as it was", name)
			assert.Empty(t, req.NativeMask.Sources("pre_request"), name)
		}
	})
	t.Run("observe on the response leg does not short-circuit", func(t *testing.T) {
		t.Parallel()
		p := &nativeFake{fakePlugin: fakePlugin{name: "trustguard", stages: []policy.Stage{policy.StagePreResponse},
			result: &Result{StatusCode: 200, StopUpstream: true, Body: []byte(`{"text":"masked"}`)}}, behavior: BedrockNativeMasks}
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"text":"secret"}`)}
		out, _, err := runNative(t, policy.StagePreResponse, nativeRequest(`{}`), resp, p, nil, policy.ModeObserve)
		require.NoError(t, err)
		assert.False(t, out.ShortCircuit)
		assert.Equal(t, `{"text":"secret"}`, string(resp.Body))
	})
	t.Run("a call that is not native is untouched", func(t *testing.T) {
		t.Parallel()
		p := &nativeFake{fakePlugin: fakePlugin{name: "tool_allowlist", stages: []policy.Stage{policy.StagePreRequest},
			result: &Result{StatusCode: 200, RequestBody: []byte(`{"stripped":true}`)}}, behavior: BedrockNativeRuns}
		_, _, err := runNative(t, policy.StagePreRequest, &infracontext.RequestContext{Body: []byte(`{"tools":[]}`)}, &infracontext.ResponseContext{}, p, nil, policy.ModeEnforce)
		require.NoError(t, err)
	})
}

func TestNativeBedrock_AMaskIsRecordedWhateverAStoredOnMaskFailureSays(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		settings map[string]any
	}{
		"nothing set":   {nil},
		"pass":          {map[string]any{"on_mask_failure": "pass"}},
		"block":         {map[string]any{"on_mask_failure": "block"}},
		"unknown value": {map[string]any{"on_mask_failure": "explode"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := &nativeFake{fakePlugin: fakePlugin{name: "regex_replace", stages: []policy.Stage{policy.StagePreRequest},
				result: &Result{StatusCode: 200, RequestBody: []byte(`{"masked":true}`)}}, behavior: BedrockNativeMasks}
			req := nativeRequest(`{"secret":true}`)
			_, _, err := runNative(t, policy.StagePreRequest, req, &infracontext.ResponseContext{}, p, tc.settings, policy.ModeEnforce)
			require.NoError(t, err)
			require.Equal(t, []infracontext.NativeMaskSource{{Plugin: "regex_replace", Stage: policy.StagePreRequest}},
				req.NativeMask.Sources(policy.StagePreRequest))
			assert.Equal(t, `{"masked":true}`, string(req.Body), "the executor applies the plugin's body: the forwarder carries it onto the original")
		})
	}
}

func TestNativeBedrock_TheResponseLegIsClassifiedTheSame(t *testing.T) {
	t.Parallel()
	resp := func() *infracontext.ResponseContext {
		return &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"text":"secret"}`)}
	}
	mask := &Result{StatusCode: 200, StopUpstream: true, Body: []byte(`{"text":"masked"}`)}

	maskPlugin := &nativeFake{fakePlugin: fakePlugin{name: "trustguard", stages: []policy.Stage{policy.StagePreResponse}, result: mask}, behavior: BedrockNativeMasks}
	req := nativeRequest(`{}`)
	_, _, err := runNative(t, policy.StagePreResponse, req, resp(), maskPlugin, nil, policy.ModeEnforce)
	require.NoError(t, err)
	assert.Equal(t, []infracontext.NativeMaskSource{{Plugin: "trustguard", Stage: policy.StagePreResponse}}, req.NativeMask.Sources(policy.StagePreResponse))

	other := &nativeFake{fakePlugin: fakePlugin{name: "tool_allowlist", stages: []policy.Stage{policy.StagePreResponse}, result: mask}, behavior: BedrockNativeRuns}
	_, _, err = runNative(t, policy.StagePreResponse, nativeRequest(`{}`), resp(), other, nil, policy.ModeEnforce)
	pe, ok := AsPluginError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)

	// A mask of an AWS error keeps its status: still a mask.
	errResp := &infracontext.ResponseContext{StatusCode: 400, Body: []byte(`{"message":"secret"}`)}
	errMask := &nativeFake{fakePlugin: fakePlugin{name: "trustguard", stages: []policy.Stage{policy.StagePreResponse},
		result: &Result{StatusCode: 400, StopUpstream: true, Body: []byte(`{"message":"masked"}`)}}, behavior: BedrockNativeMasks}
	req = nativeRequest(`{}`)
	_, _, err = runNative(t, policy.StagePreResponse, req, errResp, errMask, nil, policy.ModeEnforce)
	require.NoError(t, err)
	assert.Len(t, req.NativeMask.Sources("pre_response"), 1)
}

func TestNativeBedrock_StreamTransformsFollowTheSameRule(t *testing.T) {
	t.Parallel()
	transform := &SegmentVerdict{HasTransform: true, Transformed: "masked"}
	run := func(t *testing.T, behavior BedrockNativeBehavior, settings map[string]any) *SegmentOutcome {
		t.Helper()
		_, pols, inspectors := streamChain(t, entrySpec{slug: "guard", mode: policy.ModeEnforce, verdict: transform})
		wrapped := &nativeStream{streamPlugin: inspectors["guard"], behavior: behavior}
		reg := newRegistry(t, wrapped)
		for k, v := range settings {
			pols[0].Settings[k] = v
		}
		out, err := NewExecutor(reg, nil).(*executor).RunStreamSegment(context.Background(), StageInput{
			Stage: policy.StagePreResponse, Policies: pols, Response: &infracontext.ResponseContext{},
			Request: &infracontext.RequestContext{BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse-stream", ModelID: "m"}},
		}, segment(1, false))
		require.NoError(t, err)
		return out
	}
	t.Run("a mask is kept, whatever a stored on_mask_failure says", func(t *testing.T) {
		t.Parallel()
		out := run(t, BedrockNativeMasks, nil)
		assert.True(t, out.HasTransform)
		assert.False(t, out.Block)
		out = run(t, BedrockNativeMasks, map[string]any{"on_mask_failure": "block"})
		assert.True(t, out.HasTransform)
		assert.False(t, out.Block)
	})
	t.Run("a transform that is not a mask is a block", func(t *testing.T) {
		t.Parallel()
		out := run(t, BedrockNativeRuns, nil)
		assert.True(t, out.Block)
		assert.False(t, out.HasTransform)
		assert.Equal(t, BedrockNativePassthrough, out.Type)
	})
}

type nativeStream struct {
	*streamPlugin
	behavior BedrockNativeBehavior
}

func (n *nativeStream) BedrockNative() BedrockNativeBehavior { return n.behavior }

func TestRegistry_AcceptsAStoredOnMaskFailure(t *testing.T) {
	t.Parallel()
	masker := &nativeFake{fakePlugin: fakePlugin{name: "masker", stages: []policy.Stage{policy.StagePreRequest}}, behavior: BedrockNativeMasks}
	reg := newRegistry(t, masker)

	for _, stored := range []any{"pass", "block", "Block", "explode", 1} {
		assert.NoError(t, reg.Validate("masker", map[string]any{"on_mask_failure": stored}), "%v", stored)
	}
}
