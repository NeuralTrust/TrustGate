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
package bedrockguardrail

import (
	"context"
	"time"

	"golang.org/x/time/rate"

	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
)

// regionQuota is the on-demand quota of one ApplyGuardrail policy type: text
// units a second, and the burst. A text unit is up to 1,000 characters and a
// partial unit is billed whole.
type regionQuota struct{ unitsPerSecond, burst int }

// The quota that bounds one call is the lowest over the policy types it may
// carry, and which types or tier a customer's guardrail uses is not known, so a
// region's floor is the minimum over content filters, denied topics, word filters
// and sensitive-information filters on either tier: 50 units a second with a burst
// of 200 in the largest US regions, 25 and 25 everywhere else. Every one of them
// is adjustable, and a raised quota only makes the spacing slower than needed.
// https://docs.aws.amazon.com/general/latest/gr/bedrock.html
var regionFloors = map[string]regionQuota{
	"us-east-1": {unitsPerSecond: 50, burst: 200},
	"us-west-2": {unitsPerSecond: 50, burst: 200},
}

var defaultFloor = regionQuota{unitsPerSecond: 25, burst: 25}

func floorFor(region string) regionQuota {
	if region == "" {
		region = defaultRegion
	}
	if q, ok := regionFloors[region]; ok {
		return q
	}
	return defaultFloor
}

// textUnits is how many text units n bytes are billed; bytes are never fewer
// than characters, so it is an upper bound.
func textUnits(n int) int { return (n + 999) / 1000 }

// A request's chunks are sent one at a time and spaced at the region's floor: the
// first burst of units goes at once and every later chunk waits for its units to
// refill. The spacing is local to the request, with no state shared between
// requests. The request's own calls therefore stay under the quota, and a throttle
// that still comes back is other traffic, which is availability.
//
// Because the waits and the calls are known before the first call, the request is
// refused when they cannot fit the evaluation's budget, so a client cannot pad a
// message until its last chunk is paced to the deadline.

// estimateDuration is the time the chunks need: the waits that spacing adds plus
// a reserve per call.
func estimateDuration(chunks []textchunk.Chunk, q regionQuota) time.Duration {
	tokens := float64(q.burst)
	var wait time.Duration
	for _, c := range chunks {
		u := float64(min(textUnits(len(c.Text)), q.burst))
		if tokens < u {
			d := time.Duration((u - tokens) / float64(q.unitsPerSecond) * float64(time.Second))
			wait += d
			tokens += d.Seconds() * float64(q.unitsPerSecond)
		}
		tokens -= u
	}
	return wait + time.Duration(len(chunks))*callReserve
}

// spacer spaces one request's chunks.
type spacer struct{ lim *rate.Limiter }

func newSpacer(q regionQuota) *spacer {
	return &spacer{lim: rate.NewLimiter(rate.Limit(q.unitsPerSecond), q.burst)}
}

// wait blocks until the units of a chunk of n bytes are available or ctx ends.
func (s *spacer) wait(ctx context.Context, n int) error {
	r := s.lim.ReserveN(time.Now(), min(textUnits(n), s.lim.Burst()))
	d := r.Delay()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		r.Cancel()
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
