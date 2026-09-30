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
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainInspector is a stream inspector driven by a function of the segment, so
// the guard test can run the REAL executor chain and assert both what the
// client received and what each entry was shown.
type chainInspector struct {
	inspectorPlugin
	name     string
	rewrites bool
	reads    bool
	fn       func(appplugins.StreamSegment) *appplugins.SegmentVerdict
	seen     []string
}

func (c *chainInspector) Name() string              { return c.name }
func (c *chainInspector) MutatesResponseBody() bool { return c.rewrites }
func (c *chainInspector) ReadsContent() bool        { return c.reads }

func (c *chainInspector) InspectSegment(
	_ context.Context,
	_ appplugins.ExecInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	if seg.Closing {
		return nil, nil
	}
	c.seen = append(c.seen, seg.Accumulated)
	if c.fn == nil {
		return nil, nil
	}
	return c.fn(seg), nil
}

func replaceIn(from, to string) func(appplugins.StreamSegment) *appplugins.SegmentVerdict {
	return func(seg appplugins.StreamSegment) *appplugins.SegmentVerdict {
		if !strings.Contains(seg.Accumulated, from) {
			return nil
		}
		return &appplugins.SegmentVerdict{HasTransform: true, Transformed: strings.ReplaceAll(seg.Accumulated, from, to)}
	}
}

func realChainGuard(t *testing.T, plugins ...*chainInspector) *streamGuard {
	t.Helper()
	reg := appplugins.NewRegistry()
	pols := make([]*policy.Policy, 0, len(plugins))
	for _, p := range plugins {
		require.NoError(t, reg.Register(p))
		pols = append(pols, &policy.Policy{
			ID:       ids.New[ids.PolicyKind](),
			Name:     p.name,
			Slug:     p.name,
			Enabled:  true,
			Priority: 10,
			Parallel: true,
			Stages:   []policy.Stage{policy.StagePreResponse},
			Mode:     policy.ModeEnforce,
		})
	}
	runner, ok := appplugins.NewExecutor(reg, nil).(segmentRunner)
	require.True(t, ok)
	in := stageInputFixture()
	in.Policies = pols
	return newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, in, streamGuardConfig{}, newGuardLogger())
}

// TestStreamGuard_ReaderJudgesWhatTheClientReceives is RUN-1744: the reader's
// slug sorts before the masker's, yet the client receives the mask and the
// reader was never shown the raw card number.
func TestStreamGuard_ReaderJudgesWhatTheClientReceives(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("Hello ", "secret")
	reader := &chainInspector{name: "a_moderation", reads: true}
	masker := &chainInspector{name: "z_masker", rewrites: true, fn: replaceIn("secret", "****")}
	g := realChainGuard(t, reader, masker)

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	assert.Equal(t, "Hello ****", streamedText(t, adapter.FormatOpenAI, got))
	assert.NotContains(t, strings.Join(got, "\n"), "secret")
	assert.Equal(t, []string{"Hello ****"}, reader.seen, "the reader inspects the masked text only")
	assert.Equal(t, "Hello ****", g.text.String())
}

func TestStreamGuard_TwoRewritersReachTheClientComposed(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("Hello ", "secret")
	first := &chainInspector{name: "a_first", rewrites: true, fn: replaceIn("secret", "****")}
	second := &chainInspector{name: "b_second", rewrites: true, fn: replaceIn("Hello", "Hi")}
	g := realChainGuard(t, first, second)

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)

	assert.Equal(t, "Hi ****", streamedText(t, adapter.FormatOpenAI, got))
	assert.Equal(t, []string{"Hello ****"}, second.seen)
}

// TestStreamGuard_ComposedMaskEqualToProducedStillCuts keeps the guard's
// masked == produced refusal load-bearing under composition: the second
// rewriter undoes the first, so the final text is the produced one, which the
// guard cannot tell from a mask it already applied and ends the stream on.
func TestStreamGuard_ComposedMaskEqualToProducedStillCuts(t *testing.T) {
	t.Parallel()
	lines := textStreamLines("Hello ", "secret")
	first := &chainInspector{name: "a_first", rewrites: true, fn: replaceIn("secret", "****")}
	second := &chainInspector{name: "b_second", rewrites: true, fn: replaceIn("****", "secret")}
	g := realChainGuard(t, first, second)

	out, pe := g.Run(context.Background(), invariantSource(t, g, lines, nil))
	require.NotNil(t, pe, "a mask the guard cannot land in the head is a block")
	_, err := collectGuardOutput(t, g, out)
	require.NoError(t, err)
	assert.Contains(t, pe.Error(), streamMaskedMessage)
}
