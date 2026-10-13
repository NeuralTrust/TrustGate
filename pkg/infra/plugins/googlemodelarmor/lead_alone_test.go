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

package googlemodelarmor

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// A provider whose quota admits only the first call to arrive throttles chunks
// that are the request's own siblings. Chunk 0 is sent alone, so it is the first
// to arrive and is never the one throttled: the throttle lands on a later chunk
// and is the request's size (input), whichever order the goroutines would have
// reached the provider in.
func TestAQuotaThatAdmitsTheFirstArrivalNeverThrottlesChunkZero(t *testing.T) {
	t.Parallel()
	text := armorPlain(194560)
	require.Equal(t, 4, textchunk.Count(text, chunkSpec))

	var failedOpen atomic.Int32
	for n := range 60 {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			s := newArmorScript(t, func(call int, _ string) (int, string) {
				if call > 1 {
					return http.StatusTooManyRequests, rpcResourceExhausted
				}
				return http.StatusOK, allowResponse
			})
			p := pluginWithStub(s.modelArmorStub)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(chatBody(t, text)), nil)
			in.Event = event

			_, err := p.Execute(context.Background(), in)

			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			if err == nil || !ok || data.FailureDetail != appplugins.DetailThrottledOversize {
				failedOpen.Add(1)
			}
		})
	}
	t.Cleanup(func() { assert.Zero(t, failedOpen.Load(), "runs of 60 that failed open") })
}
