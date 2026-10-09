// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package pluginutil_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

func maskOutcomes(n int) []textchunk.Outcome[struct{}] {
	outs := make([]textchunk.Outcome[struct{}], n)
	for i := range outs {
		outs[i].Started = true
	}
	return outs
}

func TestFirstMaskedChunkSkipsFailedAndUnsentChunks(t *testing.T) {
	t.Parallel()
	outs := maskOutcomes(4)
	outs[0].Err = errors.New("boom")
	outs[1].Started = false
	asked := func(int) bool { return true }

	assert.Equal(t, 2, pluginutil.FirstMaskedChunk(outs, asked))
	assert.Equal(t, -1, pluginutil.FirstMaskedChunk(outs, func(int) bool { return false }))
}

func TestMergeChunkMasksMapsEachMaskBackOntoTheOriginal(t *testing.T) {
	t.Parallel()
	text := "alpha secret-one beta secret-two gamma"
	chunks := textchunk.Split(text, textchunk.Spec{Max: 24, Overlap: 4})
	require.Greater(t, len(chunks), 1)
	outs := maskOutcomes(len(chunks))
	masked := func(i int) (string, bool) {
		out := chunks[i].Text
		for _, s := range []string{"secret-one", "secret-two"} {
			out = strings.ReplaceAll(out, s, "X")
		}
		return out, true
	}

	got, failed := pluginutil.MergeChunkMasks(text, chunks, outs, func(int) bool { return true }, masked)

	assert.Empty(t, failed)
	assert.Equal(t, "alpha X beta X gamma", got)
}

func TestMergeChunkMasksOfOneChunkIsItsOwnOutput(t *testing.T) {
	t.Parallel()
	chunks := textchunk.Split("hello", textchunk.Spec{Max: 100, Overlap: 4})
	outs := maskOutcomes(1)

	got, failed := pluginutil.MergeChunkMasks("hello", chunks, outs, func(int) bool { return true },
		func(int) (string, bool) { return "h***o", true })
	assert.Empty(t, failed)
	assert.Equal(t, "h***o", got)

	_, failed = pluginutil.MergeChunkMasks("hello", chunks, outs, func(int) bool { return true },
		func(int) (string, bool) { return "", false })
	assert.Equal(t, appplugins.DetailAnonymizeNoOutput, failed)
}

func TestMergeChunkMasksNamesTheStepThatFailed(t *testing.T) {
	t.Parallel()
	text := "alpha secret-one beta secret-two gamma"
	chunks := textchunk.Split(text, textchunk.Spec{Max: 24, Overlap: 4})
	outs := maskOutcomes(len(chunks))

	_, failed := pluginutil.MergeChunkMasks(text, chunks, outs, func(int) bool { return true },
		func(int) (string, bool) { return "", false })
	assert.Equal(t, appplugins.DetailAnonymizeNoOutput, failed, "a chunk asked for a mask and gave none")
}
