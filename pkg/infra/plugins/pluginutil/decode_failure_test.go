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
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/pluginutiltest"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The decision is read from the error the real registry returns for each body,
// not from a hand-built error.
func TestRequestDecodeFailure(t *testing.T) {
	t.Parallel()
	registry := adapter.NewRegistry()
	decode := func(body []byte, format string) error {
		_, err := registry.DecodeRequestFor(body, adapter.Format(format))
		return err
	}

	malformed := decode(pluginutiltest.MalformedChatBody, "openai")
	require.Error(t, malformed)

	cases := []struct {
		name       string
		err        error
		capability string
		format     adapter.Format
		want       bool
	}{
		{"malformed chat body on a chat route", malformed, "chat", adapter.FormatOpenAI, true},
		{"malformed chat body, capability unset, chat format", malformed, "", adapter.FormatOpenAI, true},
		{"malformed body on the native bedrock route", malformed, "bedrock_native", adapter.FormatBedrockNative, true},
		{"malformed body on an images route", malformed, "images", adapter.FormatOpenAIImages, false},
		{"malformed body, capability unset, audio format", malformed, "", adapter.FormatOpenAIAudio, false},
		{"an error that is not a decode error on a chat route", errors.New("no adapter"), "chat", adapter.FormatOpenAI, false},
		{"no error", nil, "chat", adapter.FormatOpenAI, false},
	}
	for _, route := range pluginutiltest.NonChatRoutes(t) {
		cases = append(cases, struct {
			name       string
			err        error
			capability string
			format     adapter.Format
			want       bool
		}{route.Name + " is never a failure", decode(route.Body, route.Format), route.Capability, adapter.Format(route.Format), false})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, pluginutil.RequestDecodeFailure(tc.err, tc.capability, tc.format))
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
	assert.False(t, pluginutil.SkipWithoutCompletion(nil, "pre_response", &infracontext.ResponseContext{StatusCode: http.StatusOK}))
	assert.True(t, pluginutil.SkipWithoutCompletion(nil, "pre_response", &infracontext.ResponseContext{StatusCode: http.StatusBadGateway}),
		"a response without a completion is reported as skipped even with no event to record on")
}
