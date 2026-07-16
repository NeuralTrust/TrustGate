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

package events_test

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
)

func TestRedactHeaders_RedactsSensitiveHeaders(t *testing.T) {
	headers := map[string][]string{
		"Authorization":         {"Bearer secret"},
		"X-AG-Api-Key":          {"super-secret-key"},
		"X-TG-Api-Key":          {"tgk_gateway_secret"},
		"X-AG-Playground-Token": {"eyJhbGciOiJIUzI1NiJ9.playground.jwt"},
		"Content-Type":          {"application/json"},
	}

	out := events.RedactHeaders(headers)

	assert.Equal(t, []string{"Bearer [REDACTED]"}, out["Authorization"])
	assert.Equal(t, []string{"[REDACTED]"}, out["X-AG-Api-Key"])
	assert.Equal(t, []string{"[REDACTED]"}, out["X-TG-Api-Key"])
	assert.Equal(t, []string{"[REDACTED]"}, out["X-AG-Playground-Token"])
	assert.Equal(t, []string{"application/json"}, out["Content-Type"])
}

func TestRedactHeaders_NilReturnsNil(t *testing.T) {
	assert.Nil(t, events.RedactHeaders(nil))
}

func TestRedactHeaders_RedactsProviderAPIKeySuffix(t *testing.T) {
	out := events.RedactHeaders(map[string][]string{
		"X-OpenAI-Api-Key": {"sk-live"},
	})
	assert.Equal(t, []string{"[REDACTED]"}, out["X-OpenAI-Api-Key"])
}

func TestSanitizeBody_HidesJSONCredentialKeys(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"api_key":"sk-secret"}`)
	got := events.SanitizeBody(body, map[string][]string{"Content-Type": {"application/json"}})

	assert.NotContains(t, got, "sk-secret")
	assert.Contains(t, got, "[REDACTED]")
	assert.Contains(t, got, "gpt-4o")
}

func TestSanitizeBody_HidesJSONCredentialsWithoutContentType(t *testing.T) {
	body := []byte(`{"openai_api_key":"sk-secret","input":"hello"}`)
	got := events.SanitizeBody(body, nil)

	assert.NotContains(t, got, "sk-secret")
	assert.Contains(t, got, "[REDACTED]")
	assert.Contains(t, got, "hello")
}

func TestSanitizeExtras_RedactsCredentialKeys(t *testing.T) {
	out, ok := events.SanitizeExtras(map[string]any{
		"findings_count": 2,
		"api_key":        "sk-leak",
		"matched":        []any{map[string]any{"type": "pii"}},
	}).(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, float64(2), out["findings_count"])
	assert.Equal(t, "[REDACTED]", out["api_key"])
	assert.NotNil(t, out["matched"])
}

func TestSanitizeBody_PreservesPlainTextWithoutCredentials(t *testing.T) {
	got := events.SanitizeBody([]byte("plain user text"), map[string][]string{"Content-Type": {"text/plain"}})
	assert.Equal(t, "plain user text", got)
	assert.False(t, strings.Contains(got, "[REDACTED]"))
}
