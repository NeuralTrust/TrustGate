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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// streamingBlocks are the streaming blocks a stored policy can carry. None of
// them takes a streamed response away from the stream guard (RUN-1661).
func streamingBlocks() map[string]map[string]any {
	return map[string]map[string]any{
		"absent":             nil,
		"explicitly enabled": {"enabled": true},
		"explicitly off":     {"enabled": false},
		"tuning keys only":   {"head_chars": 100},
	}
}

func withStreamingBlock(set, block map[string]any) map[string]any {
	if block != nil {
		set["streaming"] = block
	}
	return set
}

func streamEvent() (*metrics.EventContext, *trace.Span) {
	rt := trace.New("trace-stream", trace.Metadata{GatewayID: "gw-1"})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func TestStreamedResponseIsLeftToTheStreamGuardWhateverStreamingSays(t *testing.T) {
	t.Parallel()
	for name, block := range streamingBlocks() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := New(adapter.NewRegistry(), nil)
			set := withStreamingBlock(settings(targetResponse, maskRule("answer", "solution")), block)
			event, span := streamEvent()
			in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
				reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), true), event)

			res, err := p.Execute(context.Background(), in)

			assertPassThrough(t, res, err)
			assert.Nil(t, span.PluginAttrsCopy().Extras, "the stream guard reports a streamed response, not the buffered run")

			joins, _ := p.StreamSettings(set)
			assert.True(t, joins, "every response-targeted policy rewrites a streamed response block by block")
		})
	}
}

func TestBufferedResponseIsRewrittenWhateverStreamingSays(t *testing.T) {
	t.Parallel()
	for name, block := range streamingBlocks() {
		p := New(adapter.NewRegistry(), nil)
		set := withStreamingBlock(settings(targetResponse, maskRule("answer", "solution")), block)
		event, _ := streamEvent()
		in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
			reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), false), event)

		res, err := p.Execute(context.Background(), in)

		require.NoError(t, err, name)
		assert.Contains(t, string(res.Body), "the solution", name)
	}
}

func TestStoredStreamingEnabledKeyStillValidates(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	for name, block := range streamingBlocks() {
		set := withStreamingBlock(settings(targetResponse, maskRule("answer", "solution")), block)
		require.NoError(t, p.ValidateConfig(set), name)
	}
}

// A policy that targets the request is not on the response leg, so it never
// joins the stream guard whatever its streaming block says.
func TestRequestTargetedPolicyNeverJoinsTheStream(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	for name, block := range streamingBlocks() {
		set := withStreamingBlock(settings(targetRequest, maskRule("answer", "solution")), block)
		joins, _ := p.StreamSettings(set)
		assert.False(t, joins, name)
	}
}

// A stored policy whose settings no longer parse already fails every buffered
// run, streamed or not. It is not a stream participant (see StreamSettings),
// so the guard never calls it per block and it fails no second time.
func TestStreamedResponseWithUnparseableSettingsFailsAsItAlwaysDid(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	set := map[string]any{"target": targetResponse, "rules": []map[string]any{{"pattern": "(", "replacement": "x"}}}
	event, span := streamEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, set,
		reqCtx(openAIProvider, openAIProvider, openAIRequest("be safe", "q")), respCtx(openAIResponse("the answer"), true), event)

	_, err := p.Execute(context.Background(), in)

	require.Error(t, err)
	assert.Nil(t, span.PluginAttrsCopy().Extras)
	joins, _ := p.StreamSettings(set)
	assert.False(t, joins, "an unparseable policy must not join the stream guard")
}

func TestSettingsWriteRefusesANewStreamingOptOut(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), nil)
	off := withStreamingBlock(settings(targetResponse, maskRule("answer", "solution")), map[string]any{"enabled": false})
	on := withStreamingBlock(settings(targetResponse, maskRule("answer", "solution")), map[string]any{"enabled": true})

	err := p.ValidateSettingsWrite(off, nil)
	require.Error(t, err, "a new streaming.enabled: false must be refused")
	assert.Contains(t, err.Error(), "streaming.enabled cannot turn it off")

	require.Error(t, p.ValidateSettingsWrite(off, on), "turning an enabled policy off is a new opt-out")
	require.NoError(t, p.ValidateSettingsWrite(off, off), "a policy stored with the value stays editable")
	require.NoError(t, p.ValidateSettingsWrite(on, nil))
	require.NoError(t, p.ValidateSettingsWrite(settings(targetResponse, maskRule("answer", "solution")), nil))
}
