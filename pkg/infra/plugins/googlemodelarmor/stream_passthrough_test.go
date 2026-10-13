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

package googlemodelarmor

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
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

func TestStreamedResponseIsLeftToTheStreamGuardWhateverStreamingSays(t *testing.T) {
	t.Parallel()
	for name, block := range streamingBlocks() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stub := newModelArmorStub(t, http.StatusOK, raiBlockResponse)
			p := pluginWithStub(stub)
			set := withStreamingBlock(modelArmorSettings(), block)
			rt := trace.New("trace-stream", trace.Metadata{GatewayID: "gw-1"})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			in := execInput(policy.StagePreResponse, policy.ModeObserve, set, reqCtx(openAIRequest()), respCtx(openAIResponse(), true))
			in.Event = metrics.NewEventContext(span)

			res, err := p.Execute(context.Background(), in)

			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Zero(t, stub.count(), "the header-only leg must leave the stream to the guard")
			assert.Nil(t, span.PluginAttrsCopy().Extras, "the stream guard reports a streamed response, not the buffered run")

			joins, _ := p.StreamSettings(set)
			assert.True(t, joins, "every policy inspects a streamed response block by block")
		})
	}
}

func TestStoredStreamingEnabledKeyStillValidates(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, raiBlockResponse))
	for name, block := range streamingBlocks() {
		set := withStreamingBlock(modelArmorSettings(), block)
		require.NoError(t, p.ValidateConfig(set), name)
		require.NoError(t, p.ValidateSettingsWrite(set, set), name)
	}
}

func TestSettingsWriteRefusesANewStreamingOptOut(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, raiBlockResponse))
	off := withStreamingBlock(modelArmorSettings(), map[string]any{"enabled": false})
	on := withStreamingBlock(modelArmorSettings(), map[string]any{"enabled": true})

	err := p.ValidateSettingsWrite(off, nil)
	require.Error(t, err, "a new streaming.enabled: false must be refused")
	assert.Contains(t, err.Error(), "streaming.enabled cannot turn it off")

	require.Error(t, p.ValidateSettingsWrite(off, on), "turning an enabled policy off is a new opt-out")
	require.NoError(t, p.ValidateSettingsWrite(off, off), "a policy stored with the value stays editable")
	require.NoError(t, p.ValidateSettingsWrite(on, nil))
	require.NoError(t, p.ValidateSettingsWrite(modelArmorSettings(), nil))
}
