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
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// A provider whose quota admits only the first call to arrive throttles chunks
// that are the request's own siblings. Chunk 0 is sent alone, so it is the first
// to arrive and is never the one throttled: the throttle lands on a later chunk
// and is the request's size (input), whichever order the goroutines would have
// reached the provider in.
func TestAQuotaThatAdmitsTheFirstArrivalNeverThrottlesChunkZero(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("a", 40000) + " FLAGGED " + strings.Repeat("a", 55000)
	require.Equal(t, 4, textchunk.Count(text, chunkSpec))

	var failedOpen atomic.Int32
	for n := range 60 {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			srv := answeringServer(t, func(n int32, w http.ResponseWriter, _ *http.Request) {
				if n > 1 {
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(rateLimited))
					return
				}
				_, _ = w.Write([]byte(moderationAllowed))
			})
			p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
			event, span := newEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, text), nil, event)

			_, err := p.Execute(context.Background(), in)

			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			if err == nil || !ok || extras.FailureDetail != appplugins.DetailThrottledOversize {
				failedOpen.Add(1)
			}
		})
	}
	t.Cleanup(func() { assert.Zero(t, failedOpen.Load(), "runs of 60 that failed open") })
}

// A provider that hangs is found on chunk 0, which is sent alone: no other chunk
// starts after its call timed out, and the request fails open after about one
// call, however many rounds the text has.
func TestAHangStopsTheEvaluationAfterTheFirstCallTimesOut(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := answeringServer(t, func(_ int32, _ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	})
	const timeout = 500 * time.Millisecond
	p := New(adapter.NewRegistry(), srv.URL, timeout, nil)
	text := strings.Repeat("a", 270000)
	require.GreaterOrEqual(t, textchunk.Count(text, chunkSpec), 9, "three rounds of four calls")
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, text), nil, event)

	started := time.Now()
	res, err := p.Execute(context.Background(), in)
	took := time.Since(started)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Less(t, took, 2*timeout, "three rounds would take at least 3x")
	assert.EqualValues(t, 1, calls.Load(), "no chunk starts after the first call timed out")
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
}

// A text of six chunks with a marker that is in chunk k only.
func markedChunks(t *testing.T) string {
	t.Helper()
	b := []byte(strings.Repeat("a ", 85000))
	for k := range 6 {
		copy(b[k*(chunkBytes-chunkOverlap)+10000:], fmt.Sprintf("MARK%d", k))
	}
	text := string(b)
	require.Equal(t, 6, textchunk.Count(text, chunkSpec))
	return text
}

// Under LeadAlone the first round is chunks 1..Parallel: a single throttle on
// chunk 4 is other traffic and is retried once (two calls for that chunk), while
// a throttle that persists on chunk 5, which waited for a slot, is the text's
// size.
func TestALeadAloneFirstRoundRetriesChunkParallelAndChunkParallelPlusOneDoesNot(t *testing.T) {
	t.Parallel()
	text := markedChunks(t)

	run := func(t *testing.T, throttled string, persistent bool) (map[string]int, ModerationData, error) {
		t.Helper()
		var mu sync.Mutex
		calls := map[string]int{}
		srv := answeringServer(t, func(_ int32, w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			defer mu.Unlock()
			for k := range 6 {
				m := fmt.Sprintf("MARK%d", k)
				if !strings.Contains(string(raw), m) {
					continue
				}
				calls[m]++
				if m == throttled && (persistent || calls[m] == 1) {
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(rateLimited))
					return
				}
			}
			_, _ = w.Write([]byte(moderationAllowed))
		})
		p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
		event, span := newEvent()
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, text), nil, event)
		_, err := p.Execute(context.Background(), in)
		extras, _ := span.PluginAttrsCopy().Extras.(ModerationData)
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range calls {
			out[k] = v
		}
		return out, extras, err
	}

	calls, _, err := run(t, "MARK4", false)
	require.NoError(t, err)
	assert.Equal(t, 2, calls["MARK4"], "a single throttle on chunk Parallel is retried")

	calls, extras, err := run(t, "MARK5", true)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	assert.Equal(t, appplugins.DetailThrottledOversize, extras.FailureDetail)
	assert.Equal(t, 1, calls["MARK5"], "a chunk that waited for a slot is not retried")
}
