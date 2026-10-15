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

package pluginutil_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/pluginutiltest"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func newEvent(t *testing.T) (*metrics.EventContext, *trace.Span) {
	t.Helper()
	span := trace.New("t", trace.Metadata{}).StartSpan(trace.SpanPlugin, "plugin")
	return metrics.NewEventContext(span), span
}

// A request that does not decode is a skip only on a route that carries no
// chat; the route decides, from the capability or, when unset, the format.
func TestSkipNonChatRoute(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		capability string
		format     adapter.Format
		want       bool
	}{
		{"chat route", "chat", adapter.FormatOpenAI, false},
		{"chat format, capability unset", "", adapter.FormatOpenAI, false},
		{"native bedrock route", "bedrock_native", adapter.FormatBedrockNative, false},
		{"images route", "images", adapter.FormatOpenAIImages, true},
		{"audio format, capability unset", "", adapter.FormatOpenAIAudio, true},
	}
	for _, route := range pluginutiltest.NonChatRoutes(t) {
		cases = append(cases, struct {
			name       string
			capability string
			format     adapter.Format
			want       bool
		}{route.Name, route.Capability, adapter.Format(route.Format), true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			event, span := newEvent(t)
			assert.Equal(t, tc.want, pluginutil.SkipNonChatRoute(event, "pre_request", tc.capability, tc.format))
			extras := span.PluginAttrsCopy().Extras
			if !tc.want {
				assert.Nil(t, extras, "a chat route records nothing")
				return
			}
			skipped, reason := pluginutiltest.SkipOf(t, extras)
			assert.True(t, skipped)
			assert.Equal(t, pluginutil.SkipReasonNoInspectableInput, reason)
		})
	}
}

func TestResponseCarriesCompletion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		resp *infracontext.ResponseContext
		want bool
	}{
		{"no response", nil, true},
		{"status unset", &infracontext.ResponseContext{}, true},
		{"200", &infracontext.ResponseContext{StatusCode: http.StatusOK}, true},
		{"299", &infracontext.ResponseContext{StatusCode: 299}, true},
		{"199", &infracontext.ResponseContext{StatusCode: 199}, false},
		{"300", &infracontext.ResponseContext{StatusCode: http.StatusMultipleChoices}, false},
		{"429", &infracontext.ResponseContext{StatusCode: http.StatusTooManyRequests}, false},
		{"503", &infracontext.ResponseContext{StatusCode: http.StatusServiceUnavailable}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, pluginutil.ResponseCarriesCompletion(tc.resp))
		})
	}
}

func TestSkipWithoutCompletionRecordsTheSkip(t *testing.T) {
	t.Parallel()
	event, span := newEvent(t)
	assert.False(t, pluginutil.SkipWithoutCompletion(event, "pre_response", &infracontext.ResponseContext{StatusCode: http.StatusOK}))
	assert.Nil(t, span.PluginAttrsCopy().Extras, "a completion records nothing")

	assert.True(t, pluginutil.SkipWithoutCompletion(event, "pre_response", &infracontext.ResponseContext{StatusCode: http.StatusBadGateway}))
	skipped, reason := pluginutiltest.SkipOf(t, span.PluginAttrsCopy().Extras)
	assert.True(t, skipped)
	assert.Equal(t, pluginutil.SkipReasonNoInspectableOutput, reason)

	assert.True(t, pluginutil.SkipWithoutCompletion(nil, "pre_response", &infracontext.ResponseContext{StatusCode: http.StatusBadGateway}),
		"a response without a completion is reported as skipped even with no event to record on")
}
