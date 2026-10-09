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

package openaimoderation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// sizeBoundModerator answers like a classifier whose latency grows with the
// text it is sent, which is what makes an evaluation of a growing prefix run
// into the fixed per-block deadline. It flags a text that ends in the marker.
type sizeBoundModerator struct {
	mu    sync.Mutex
	sizes []int
}

const hateMarker = "I HATE YOU ALL"

func (m *sizeBoundModerator) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req moderationRequest
		_ = json.Unmarshal(raw, &req)
		text := ""
		if len(req.Input) > 0 {
			text = req.Input[0].Text
		}
		m.mu.Lock()
		m.sizes = append(m.sizes, len(text))
		m.mu.Unlock()
		select {
		case <-time.After(time.Duration(len(raw)) * 8 * time.Microsecond):
		case <-r.Context().Done():
			return
		}
		resp := moderationResponse{ID: "mod-1", Model: defaultModel, Results: []moderationResult{{
			Categories:     map[string]bool{"hate": strings.HasSuffix(text, hateMarker)},
			CategoryScores: map[string]float64{"hate": map[bool]float64{true: 0.95, false: 0.01}[strings.HasSuffix(text, hateMarker)]},
			Flagged:        strings.HasSuffix(text, hateMarker),
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (m *sizeBoundModerator) largest() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	largest := 0
	for _, s := range m.sizes {
		largest = max(largest, s)
	}
	return largest
}

// A client that opens a stream with a long preamble must not be able to push
// the evaluation of what follows past the per-block deadline: every call sends
// at most the entry's window, so its cost does not grow with the stream and the
// block that carries the violation is still judged.
func TestALongStreamIsEvaluatedThroughABoundedWindow(t *testing.T) {
	t.Parallel()
	mod := &sizeBoundModerator{}
	srv := mod.server(t)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(p))
	exec, ok := appplugins.NewExecutor(reg, nil).(interface {
		RunStreamSegment(context.Context, appplugins.StageInput, appplugins.StreamSegment) (*appplugins.SegmentOutcome, error)
	})
	require.True(t, ok)

	pol := &policy.Policy{
		ID: ids.New[ids.PolicyKind](), Slug: PluginName, Name: PluginName, Enabled: true, Priority: 1, Parallel: true,
		Stages: []policy.Stage{policy.StagePreResponse}, Mode: policy.ModeEnforce,
		Settings: blockSettings(),
	}
	in := appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Policies: []*policy.Policy{pol},
		Request:  requestContext(),
		Response: &infracontext.ResponseContext{},
	}
	const block = 2048
	filler := strings.Repeat("a long preamble that says nothing wrong. ", 8000)
	for i, size := range []int{20000, 150000, 250000, 300000, 320000} {
		acc := filler[:size]
		last := i == 4
		if last {
			acc = filler[:size-len(hateMarker)] + hateMarker
		}
		seg := appplugins.StreamSegment{StreamID: "s", Seq: i + 1, Text: acc[len(acc)-block:], Accumulated: acc}
		out, err := exec.RunStreamSegment(context.Background(), in, seg)
		require.NoError(t, err)
		require.NotNil(t, out)
		assert.Zero(t, out.FailedEntries, "block %d went uninspected", seg.Seq)
		if last {
			assert.True(t, out.Block, "the violation at the end of a long stream must still cut it")
		}
	}
	assert.LessOrEqual(t, mod.largest(), 64<<10, "no call may carry more than its window")
}
