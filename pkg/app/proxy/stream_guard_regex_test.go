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
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// regexGuard runs the real regex_replace through the real executor and stream
// guard, one rule, every delta its own block.
func regexGuard(t *testing.T, cfg streamGuardConfig, pattern, replacement string) *streamGuard {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(regexreplace.New(adapter.NewRegistry(), nil)))
	in := stageInputFixture()
	in.Policies = []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     regexreplace.PluginName,
		Slug:     regexreplace.PluginName,
		Enabled:  true,
		Parallel: true,
		Stages:   []policy.Stage{policy.StagePreResponse},
		Mode:     policy.ModeEnforce,
		Settings: map[string]any{
			"target":    "response",
			"rules":     []map[string]any{{"pattern": pattern, "replacement": replacement}},
			"streaming": map[string]any{"enabled": true},
		},
	}}
	runner, ok := appplugins.NewExecutor(reg, nil).(segmentRunner)
	require.True(t, ok)
	cfg.minChars, cfg.headChars = 1, 1
	return newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, in, cfg, newGuardLogger())
}

func runRegexGuard(t *testing.T, g *streamGuard, chunks ...string) string {
	t.Helper()
	out, pe := g.Run(context.Background(), invariantSource(t, g, textStreamLines(chunks...), nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	return streamedText(t, adapter.FormatOpenAI, got)
}

// RUN-1745 F2: the replacement matches its own pattern. On the next block the
// rule used to rewrite the placeholder the client already had, and the guard
// cut the stream with "masking could not be applied".
func TestStreamGuard_RegexPlaceholderMatchingItsPatternKeepsStreaming(t *testing.T) {
	t.Parallel()
	g := regexGuard(t, streamGuardConfig{}, `(?i)ssn`, "[SSN]")

	text := runRegexGuard(t, g, "my ssn is 1", "234", " and my SSN again")

	assert.Equal(t, "my [SSN] is 1234 and my [SSN] again", text)
	assert.False(t, g.stopped, "a placeholder in released text is not a reason to cut")
}

// RUN-1745 F4: past max_accumulated_bytes a block sees a tail window, and ^
// matched where the window happened to start, in text already released.
func TestStreamGuard_RegexAnchorAtTheWindowStartKeepsStreaming(t *testing.T) {
	t.Parallel()
	// The third block's window is "456 and more": it starts on three digits
	// the first block already released.
	g := regexGuard(t, streamGuardConfig{maxAccumBytes: len("456 and more")}, `^\d{3}`, "NNN")

	text := runRegexGuard(t, g, "Hi 123 456", " and", " more")

	assert.Equal(t, "Hi 123 456 and more", text)
	assert.False(t, g.stopped, "an anchor matching at the window start is not a finding")
}

// A value split across two blocks still has its second half masked, and the
// guard still cuts when the first half has already reached the client: the
// change to what F2 and F4 skip is limited to matches wholly in released text.
func TestStreamGuard_RegexMatchReachingIntoReleasedTextStillCuts(t *testing.T) {
	t.Parallel()
	g := regexGuard(t, streamGuardConfig{}, `\d{16}`, "[CARD]")

	text := runRegexGuard(t, g, "card 411111", "1111111111")

	assert.Equal(t, "card 411111", text, "the second half is never released")
	assert.True(t, g.stopped)
}
