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

package azurecontentsafety

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	text := strings.Repeat("a", 12000) + " FLAGGED " + strings.Repeat("a", 14000)
	require.Equal(t, 4, textchunk.Count(text, chunkSpec))
	body := chatBody(t, map[string]string{"role": "user", "content": text})

	var failedOpen atomic.Int32
	for n := range 60 {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			var arrivals atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				if arrivals.Add(1) > 1 {
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":{"code":"429","message":"Rate limit is exceeded. Try again in 1 seconds."}}`))
					return
				}
				_, _ = w.Write([]byte(`{"categoriesAnalysis":[{"category":"Hate","severity":0}]}`))
			}))
			t.Cleanup(srv.Close)

			_, data, err := run(t, New(adapter.NewRegistry(), nil), policy.ModeEnforce, srv.URL, body)

			if err == nil || data == nil || data.FailureDetail != appplugins.DetailThrottledOversize {
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
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	const timeout = 500 * time.Millisecond
	p := New(adapter.NewRegistry(), nil)
	p.client.http.Timeout = timeout
	text := strings.Repeat("a", 80000)
	require.GreaterOrEqual(t, textchunk.Count(text, chunkSpec), 9, "three rounds of four calls")

	started := time.Now()
	res, data, err := run(t, p, policy.ModeEnforce, srv.URL, chatBody(t, map[string]string{"role": "user", "content": text}))
	took := time.Since(started)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Less(t, took, timeout*3/2)
	assert.EqualValues(t, 1, calls.Load(), "no chunk starts after the first call timed out")
	assert.Equal(t, "availability", data.FailureClass)
}
