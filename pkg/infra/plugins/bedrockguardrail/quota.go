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

package bedrockguardrail

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// regionQuota is the on-demand quota of one ApplyGuardrail policy type: text
// units a second, and the burst a single second may use. A text unit is up to
// 1,000 characters, and a partial unit is billed whole.
type regionQuota struct{ unitsPerSecond, burst int }

// The quota that bounds one call is the lowest over the policy types it may
// carry, and which types or tier (classic or standard) a customer's guardrail
// uses is not known, so a region's floor is the minimum over content filters,
// denied topics, word filters and sensitive-information filters on either tier.
// The largest US regions give a denied topic (classic) 50 units a second with a
// burst of 200; every other supported region gives 25 and 25. Every one of them
// is an adjustable quota, and a raised quota only makes the pacer slower than
// it needs to be. Whether ServiceQuotaExceededException answers the size or the
// rate of a call is undocumented, so it stays a throttle.
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

// textUnits is how many text units a text of n bytes is billed. Bytes are never
// fewer than characters, so it is an upper bound.
func textUnits(n int) int {
	return (n + 999) / 1000
}

// errPacerSaturated is the quota being held by other traffic for longer than a
// call can wait: availability, since the request's own calls never exceed the
// floor.
var errPacerSaturated = errors.New("bedrock_guardrail: the region quota is held by other traffic for longer than the call can wait")

// pacer spends each credential's text units no faster than its region's floor.
// The calls of one request then never exceed the quota by themselves, so a
// throttle can only come from other traffic, which is availability. The zero
// value is ready to use. The pacer is per process: several pods can still
// exceed the account's quota together, and AWS then throttles them, which is
// availability as well.
type pacer struct {
	limiters sync.Map
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
}

func (p *pacer) limiter(creds awsCredentials) *rate.Limiter {
	key := creds.fingerprint()
	if v, ok := p.limiters.Load(key); ok {
		if l, isLimiter := v.(*rate.Limiter); isLimiter {
			return l
		}
	}
	q := floorFor(creds.region)
	v, _ := p.limiters.LoadOrStore(key, rate.NewLimiter(rate.Limit(q.unitsPerSecond), q.burst))
	l, _ := v.(*rate.Limiter)
	return l
}

// Wait reserves n text units and sleeps until they are available. When the
// wait would run past ctx's deadline it gives the reservation back and returns
// errPacerSaturated.
func (p *pacer) Wait(ctx context.Context, creds awsCredentials, n int) error {
	if n <= 0 {
		return nil
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	lim := p.limiter(creds)
	r := lim.ReserveN(now(), n)
	if !r.OK() {
		return errPacerSaturated
	}
	delay := r.DelayFrom(now())
	if delay <= 0 {
		return nil
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < delay {
		r.CancelAt(now())
		return errPacerSaturated
	}
	if err := p.sleepFor(ctx, delay); err != nil {
		r.CancelAt(now())
		return err
	}
	return nil
}

func (p *pacer) sleepFor(ctx context.Context, d time.Duration) error {
	if p.sleep != nil {
		return p.sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
