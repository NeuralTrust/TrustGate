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

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func regexSettings(pattern, replacement string, extra map[string]any) map[string]any {
	set := map[string]any{
		"target": "response",
		"rules":  []map[string]any{{"pattern": pattern, "replacement": replacement}},
	}
	for k, v := range extra {
		set[k] = v
	}
	return set
}

func regexPolicy(set map[string]any) *policy.Policy {
	return &policy.Policy{
		ID:       ids.New[ids.PolicyKind](),
		Name:     regexreplace.PluginName,
		Slug:     regexreplace.PluginName,
		Enabled:  true,
		Parallel: true,
		Stages:   []policy.Stage{policy.StagePreResponse},
		Mode:     policy.ModeEnforce,
		Settings: set,
	}
}

// regexGuardFor builds the real guard over the given policies with blocks large
// enough that a short response is the held head plus the final block, so a value
// split across deltas is masked rather than cut.
func regexGuardFor(t *testing.T, pols ...*policy.Policy) *streamGuard {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(regexreplace.New(adapter.NewRegistry(), nil)))
	in := stageInputFixture()
	in.Policies = pols
	runner, ok := appplugins.NewExecutor(reg, nil).(segmentRunner)
	require.True(t, ok)
	cfg := streamGuardConfig{headChars: 4096, minChars: 4096}
	return newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, in, cfg, newGuardLogger())
}

// ENG-1735: a policy saved from the console carries no streaming key. It must
// mask a streamed response all the same, including a value split across deltas.
func TestStreamGuard_RegexWithNoStreamingKeyMasksASplitCard(t *testing.T) {
	t.Parallel()
	g := regexGuardFor(t, regexPolicy(regexSettings(`\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`, "[CARD]", nil)))

	text := runRegexGuard(t, g, "the card is 4242 42", "42 4242 4242 and that is all")

	assert.Equal(t, "the card is [CARD] and that is all", text)
	assert.False(t, g.stopped)
}

func TestStreamGuard_RegexExplicitlyDisabledLeavesTheStreamAlone(t *testing.T) {
	t.Parallel()
	g := regexGuardFor(t, regexPolicy(regexSettings(`\d{16}`, "[CARD]",
		map[string]any{"streaming": map[string]any{"enabled": false}})))

	text := runRegexGuard(t, g, "the card is 4242424242", "424242 ok")

	assert.Equal(t, "the card is 4242424242424242 ok", text)
}

// A request-only policy must not start inspecting responses because streaming
// is now on when the key is absent.
func TestStreamGuard_RegexRequestOnlyPolicyLeavesTheResponseAlone(t *testing.T) {
	t.Parallel()
	set := regexSettings(`\d{16}`, "[CARD]", nil)
	set["target"] = "request"
	g := regexGuardFor(t, regexPolicy(set))

	text := runRegexGuard(t, g, "the card is 4242424242", "424242 ok")

	assert.Equal(t, "the card is 4242424242424242 ok", text)
}

// F8: a stored regex policy whose settings no longer parse fails every
// buffered run already. Default-on must not also make it fail every block of a
// stream: it is not a participant, so the guard neither cuts nor errors, and a
// valid policy beside it still masks.
func TestStreamGuard_RegexUnparseableStoredPolicyIsNotAParticipant(t *testing.T) {
	t.Parallel()
	broken := regexPolicy(map[string]any{"target": "response", "rules": []map[string]any{{"pattern": "(", "replacement": "x"}}})
	valid := regexPolicy(regexSettings(`\d{16}`, "[CARD]", nil))
	g := regexGuardFor(t, broken, valid)

	text := runRegexGuard(t, g, "the card is 4242424242", "424242 ok")

	assert.Equal(t, "the card is [CARD] ok", text)
	assert.False(t, g.stopped, "a policy that cannot parse must not cut the stream")
}

func TestStreamGuard_RegexUnparseableStoredPolicyAloneDoesNotCut(t *testing.T) {
	t.Parallel()
	broken := regexPolicy(map[string]any{"target": "response", "rules": []map[string]any{{"pattern": "(", "replacement": "x"}}})
	g := regexGuardFor(t, broken)

	text := runRegexGuard(t, g, "plain ", "text")

	assert.Equal(t, "plain text", text)
	assert.False(t, g.stopped)
}
