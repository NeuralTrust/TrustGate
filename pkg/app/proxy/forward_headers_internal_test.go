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

package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func TestForwardedClientHeaders(t *testing.T) {
	bk := &registry.Registry{Type: registry.TypeLLM, LLMTarget: &registry.LLMTarget{
		Provider:        "openai",
		ProviderOptions: map[string]any{registry.ProviderOptionForwardClientHeaders: []any{"traceparent", "tracestate"}},
	}}
	req := &infracontext.RequestContext{Headers: map[string][]string{
		"traceparent":   {"00-abc-def-01"},
		"Tracestate":    {""},
		"Authorization": {"Bearer gateway-key"},
		"X-Request-Id":  {"r-1"},
	}}
	got := forwardedClientHeaders(bk, req)
	assert.Equal(t, "00-abc-def-01", got.Get("Traceparent"))
	assert.Empty(t, got.Values("Tracestate"), "an empty value is not forwarded")
	assert.Empty(t, got.Get("Authorization"), "only listed headers are forwarded")
	assert.Empty(t, got.Get("X-Request-Id"))

	none := &registry.Registry{Type: registry.TypeLLM, LLMTarget: &registry.LLMTarget{Provider: "openai"}}
	assert.Nil(t, forwardedClientHeaders(none, req), "a registry that lists nothing forwards nothing")
}
