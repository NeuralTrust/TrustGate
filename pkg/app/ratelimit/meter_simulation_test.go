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

package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The simulation drives several meters ("pods") over a virtual millisecond
// clock against one shared counter. It runs the real admission and sync code
// (prepare, apply, the kick channel); only time and Redis are fake, which makes
// the overshoot a number the test can assert instead of a flaky measurement.
//
// A sync is modelled as the loop does it: it starts on the tick or on a kick,
// never sooner than KickMinGap after the previous sync finished, the counters
// move in Redis when it starts, and the pod learns the answer one round trip
// later.

type simConfig struct {
	pods         int
	limits       domain.Limits
	interval     time.Duration
	gap          time.Duration
	latency      time.Duration
	kick         bool
	duration     time.Duration
	reqPerMsPod  func(elapsed time.Duration) int // offered requests per millisecond, per pod
	startAtMinut time.Time
}

type simPod struct {
	meter     *Meter
	backend   *memBackend
	nextTick  time.Time
	busyUntil time.Time
	lastEnd   time.Time
	inFlight  []simInFlight
	admitted  int
	rejected  int
}

type simInFlight struct {
	at      time.Time
	entries []*syncEntry
	results []domain.SyncResult
}

type simResult struct {
	admitted     int
	perPod       []int
	syncs        int
	totalInRedis int64
}

func runSim(t *testing.T, cfg simConfig) simResult {
	t.Helper()
	clock := newClock(cfg.startAtMinut)
	shared := newShared()
	resolver := newResolver()
	id := ids.New[ids.GatewayKind]()
	resolver.set(id, "tenant", cfg.limits)

	pods := make([]*simPod, cfg.pods)
	for i := range pods {
		backend := newBackend(shared)
		pods[i] = &simPod{
			backend: backend,
			meter: testMeter(resolver, backend, clock, func(o *Options) {
				o.SyncInterval = cfg.interval
				o.KickMinGap = cfg.gap
				o.DisableKick = !cfg.kick
			}),
			// Pods tick out of phase, as independent processes do.
			nextTick: cfg.startAtMinut.Add(time.Duration(i+1) * cfg.interval / time.Duration(cfg.pods+1)),
		}
	}

	syncs := 0
	step := time.Millisecond
	start := cfg.startAtMinut
	for elapsed := time.Duration(0); elapsed < cfg.duration; elapsed += step {
		now := start.Add(elapsed)
		clock.Set(now)

		for _, p := range pods {
			// Answers that arrive now.
			rest := p.inFlight[:0]
			for _, f := range p.inFlight {
				if !f.at.After(now) {
					require.Zero(t, p.meter.apply(context.Background(), f.entries, f.results, nil, nil))
				} else {
					rest = append(rest, f)
				}
			}
			p.inFlight = rest

			// Requests.
			for k := 0; k < cfg.reqPerMsPod(elapsed); k++ {
				if err := p.meter.Check(bg, id); err == nil {
					p.admitted++
				} else {
					p.rejected++
				}
			}

			// Start a sync if the tick is due or a kick is waiting, the loop is
			// idle, and the gap since the last sync has passed.
			due := !now.Before(p.nextTick)
			kicked := len(p.meter.kick) > 0
			idle := !now.Before(p.busyUntil)
			gapOK := p.lastEnd.IsZero() || !now.Before(p.lastEnd.Add(cfg.gap)) || (due && !kicked)
			if (due || kicked) && idle && (gapOK || due) {
				if kicked {
					<-p.meter.kick
				}
				if due {
					for !p.nextTick.After(now) {
						p.nextTick = p.nextTick.Add(cfg.interval)
					}
				}
				if due || gapOK {
					entries := p.meter.prepare(now)
					items := make([]domain.SyncItem, len(entries))
					for i := range entries {
						items[i] = entries[i].item
					}
					results, err := p.backend.Sync(context.Background(), items)
					require.NoError(t, err)
					p.inFlight = append(p.inFlight, simInFlight{at: now.Add(cfg.latency), entries: entries, results: results})
					p.busyUntil = now.Add(cfg.latency)
					p.lastEnd = now.Add(cfg.latency)
					syncs++
				}
			}
		}
	}

	res := simResult{syncs: syncs}
	for _, p := range pods {
		res.admitted += p.admitted
		res.perPod = append(res.perPod, p.admitted)
	}
	res.totalInRedis = shared.total("tenant", domain.KindBurst, burstWindow(start))
	return res
}

func simBase() simConfig {
	return simConfig{
		pods: 3, limits: domain.Limits{BurstPerMin: 300, QuotaPerMonth: 0},
		interval: time.Second, gap: DefaultKickMinGap, latency: 5 * time.Millisecond,
		startAtMinut: time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC),
	}
}

// perPodRate returns an offered load of rps requests per second per pod, spread
// evenly over the virtual milliseconds.
func perPodRate(rps int) func(time.Duration) int {
	every := time.Second / time.Duration(rps)
	return func(e time.Duration) int {
		if e%every == 0 {
			return 1
		}
		return 0
	}
}

// Steady overload: the tenant offers more than its cap for the whole minute.
// Blocking starts at the cap plus what the other pods admitted while this one
// did not yet know, which is the tenant's request rate times the sync lag.
func TestSimSteadyOverloadOvershootIsWithinTenantRPSTimesInterval(t *testing.T) {
	t.Parallel()
	for _, pods := range []int{2, 3, 5} {
		for _, kick := range []bool{false, true} {
			cfg := simBase()
			cfg.pods = pods
			cfg.kick = kick
			cfg.duration = 59 * time.Second
			const perPodRPS = 10
			cfg.reqPerMsPod = perPodRate(perPodRPS)

			r := runSim(t, cfg)
			over := r.admitted - cfg.limits.BurstPerMin
			tenantRPS := pods * perPodRPS
			bound := int(float64(tenantRPS) * (cfg.interval + cfg.latency).Seconds())
			t.Logf("pods=%d kick=%v tenantRPS=%d cap=%d admitted=%d overshoot=%d bound(RPS x interval)=%d",
				pods, kick, tenantRPS, cfg.limits.BurstPerMin, r.admitted, over, bound)

			assert.GreaterOrEqual(t, r.admitted, cfg.limits.BurstPerMin, "never blocks before the cap")
			assert.LessOrEqual(t, over, bound, "pods=%d kick=%v", pods, kick)
		}
	}
}

// The worst case, at a minute boundary: every pod starts the new bucket at zero
// and the tenant floods all of them at once. Without the early flush each pod
// admits a full cap before its first sync, so the tenant gets pods x cap.
func TestSimBoundaryFloodWithoutKickAdmitsPodsTimesCap(t *testing.T) {
	t.Parallel()
	for _, pods := range []int{3, 10} {
		cfg := simBase()
		cfg.pods = pods
		cfg.kick = false
		cfg.duration = 3 * time.Second
		cfg.reqPerMsPod = perPodRate(1000)

		r := runSim(t, cfg)
		t.Logf("NO KICK pods=%d cap=%d admitted=%d (%.1fx cap)", pods, cfg.limits.BurstPerMin, r.admitted,
			float64(r.admitted)/float64(cfg.limits.BurstPerMin))
		assert.GreaterOrEqual(t, float64(r.admitted), 0.9*float64(pods*cfg.limits.BurstPerMin))
	}
}

// With the kick a pod asks for a sync once it holds a tenth of the cap
// unsynced, so what a flood can add before the pods see each other is each
// pod's threshold plus what it admits during one minimum gap and one round trip.
func TestSimBoundaryFloodWithKickIsBoundedByThresholdPlusLag(t *testing.T) {
	t.Parallel()
	const rate = 1000
	for _, pods := range []int{3, 10} {
		cfg := simBase()
		cfg.pods = pods
		cfg.kick = true
		cfg.duration = 3 * time.Second
		cfg.reqPerMsPod = perPodRate(rate)

		noKick := cfg
		noKick.kick = false

		r := runSim(t, cfg)
		without := runSim(t, noKick)

		threshold := int(kickThreshold(cfg.limits.BurstPerMin))
		lag := int(float64(rate) * (cfg.gap + cfg.latency + 2*time.Millisecond).Seconds())
		bound := cfg.limits.BurstPerMin + pods*(threshold+lag)
		t.Logf("KICK pods=%d cap=%d admitted=%d (%.1fx cap) vs %d without kick; bound=%d syncs=%d",
			pods, cfg.limits.BurstPerMin, r.admitted, float64(r.admitted)/float64(cfg.limits.BurstPerMin), without.admitted, bound, r.syncs)

		assert.LessOrEqual(t, r.admitted, bound)
		assert.Less(t, r.admitted, without.admitted/2, "the kick must at least halve the flood")
		assert.GreaterOrEqual(t, r.admitted, cfg.limits.BurstPerMin, "and still never block below the cap")
	}
}
