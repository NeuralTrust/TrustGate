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
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// Run is the background loop that keeps the pod's counters and Redis in step.
// It returns when ctx is cancelled, after one last sync so that what this pod
// admitted since the previous tick is not lost on a rolling restart.
//
// A kick, raised by a request when a tenant's unsynced usage reaches a tenth of
// its cap, brings the next sync forward, but never closer than KickMinGap to the
// previous one: a flood must not turn into a flood of Redis calls.
func (m *Meter) Run(ctx context.Context) {
	ticker := time.NewTicker(m.opts.SyncInterval)
	defer ticker.Stop()

	var last time.Time
	for {
		select {
		case <-ctx.Done():
			m.flushOnShutdown()
			return
		case <-ticker.C:
		case <-m.kick:
			if m.failing.Load() {
				continue // a kick queued before the failure; the tick is the cadence now
			}
			if wait := m.opts.KickMinGap - time.Since(last); wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					m.flushOnShutdown()
					return
				}
			}
		}
		_ = m.SyncNow(ctx) // failures are logged and counted inside
		last = time.Now()
	}
}

func (m *Meter) flushOnShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.FlushTimeout)
	defer cancel()
	if err := m.sync(ctx, true); err != nil {
		m.logger.Warn("rate limit: final flush failed; the last interval of usage is lost",
			slog.String("component", "ratelimit"),
			slog.Any("error", err))
	}
}

// SyncNow runs one sync round: it pushes every tenant's pending usage to Redis,
// pulls the tenant-wide totals back, and applies them. It is the only code path
// that talks to the backend.
func (m *Meter) SyncNow(ctx context.Context) error {
	return m.sync(ctx, false)
}

// sync is SyncNow. Once ctx is done it stops starting chunks, but a chunk
// already on the wire is never cancelled. The usage of the chunks it did not
// start is kept for the next round, or, when final is set (the shutdown flush,
// there is no next round), dropped and counted with reason "shutdown".
func (m *Meter) sync(ctx context.Context, final bool) error {
	entries := m.prepare(m.opts.Now())
	if len(entries) == 0 {
		return nil
	}

	ctx, span := m.metrics.tracer.Start(ctx, "ratelimit.sync")
	started := time.Now()
	var firstErr error
	// callFailed is whether Redis itself looked down: a call that failed, or a
	// round with several tenants in which every one of them did. It is judged
	// over the whole round, not per chunk: a chunk of one that holds the only bad
	// tenant says nothing about Redis. A round of a single tenant failing only on
	// its own item is not an outage either. Tenants are counted by slot, not by
	// entry: a tenant with a retained round plus a new one owns two entries, and
	// one poisoned tenant must not look like every tenant failing.
	callFailed := false
	failedSlots := make(map[*slot]struct{})
	allSlots := make(map[*slot]struct{}, len(entries))
	for _, e := range entries {
		allSlots[e.slot] = struct{}{}
	}
	for start := 0; start < len(entries); start += m.opts.MaxBatch {
		end := min(start+m.opts.MaxBatch, len(entries))
		chunk := entries[start:end]

		// ctx decides whether to start a chunk, never whether to finish one.
		if ctx.Err() != nil {
			skipped := entries[start:]
			for _, e := range skipped {
				m.unsent(ctx, e, final)
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("ratelimit sync: stopped before %d tenants: %w", len(skipped), ctx.Err())
			}
			break
		}

		// The call is detached from ctx on purpose. A shutdown must not abort a
		// round that is already on the wire: the backend may apply it anyway,
		// and the caller would never learn the totals. SyncTimeout alone bounds it.
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.opts.SyncTimeout)
		items := make([]domain.SyncItem, len(chunk))
		for i := range chunk {
			items[i] = chunk[i].item
		}
		results, err := m.backend.Sync(callCtx, items)
		cancel()

		failed := m.apply(ctx, chunk, results, err, failedSlots)
		if err != nil {
			callFailed = true
		}
		if failed > 0 && firstErr == nil {
			firstErr = fmt.Errorf("ratelimit sync: %d of %d tenants failed: %w", failed, len(chunk), errOrFirst(err, results))
		}
	}

	if len(allSlots) > 1 && len(failedSlots) == len(allSlots) {
		callFailed = true
	}
	failed := firstErr != nil
	m.failing.Store(callFailed)
	m.metrics.recordSync(ctx, time.Since(started).Seconds(), failed)
	span.SetAttributes(
		attribute.Int("ratelimit.tenants", len(entries)),
		attribute.Bool("ratelimit.failed", failed),
		attribute.Bool("ratelimit.outage", callFailed),
	)
	if failed {
		span.RecordError(firstErr)
		span.SetStatus(codes.Error, "sync failed")
		if suppressed, ok := m.syncWarn.allow(m.opts.Now()); ok {
			m.logger.Warn("rate limit: sync failed; serving from memory",
				slog.String("component", "ratelimit"),
				slog.Int("failures_since_last_log", suppressed+1),
				slog.Any("error", firstErr))
		}
	}
	span.End()
	return firstErr
}

func errOrFirst(err error, results []domain.SyncResult) error {
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
	}
	return errors.New("unknown error")
}

// syncEntry is one tenant's share of a sync round. It is also what is kept when
// the round fails: the same deltas, under the same token, are sent again, so a
// round that Redis applied but never answered is not applied twice.
type syncEntry struct {
	slot        *slot
	item        domain.SyncItem
	quotaWindow string
	burstWindow string
	quotaDelta  int64
	burstDelta  int64
	carries     []carried
	firstFailed time.Time
}

// hasDelta reports whether the entry owes Redis anything. A pure read has no
// token and nothing to retry.
func (e *syncEntry) hasDelta() bool {
	return e.quotaDelta > 0 || e.burstDelta > 0 || len(e.carries) > 0
}

// prepare freezes each tenant's pending usage into an in-flight delta, hands
// back the rounds that failed earlier so they are sent again as they were, and
// evicts tenants nobody has asked about for a while.
//
// New usage never joins a failed round: that round may already have been
// applied, and adding to it under the same token would lose the addition. It
// travels in a round of its own, under a new token.
func (m *Meter) prepare(now time.Time) []*syncEntry {
	m.mu.RLock()
	slots := make([]*slot, 0, len(m.slots))
	for _, s := range m.slots {
		slots = append(slots, s)
	}
	m.mu.RUnlock()

	entries := make([]*syncEntry, 0, len(slots))
	for _, s := range slots {
		if m.evictIfIdle(s, now) {
			continue
		}
		s.mu.Lock()
		s.roll(now)
		e := &syncEntry{
			slot:        s,
			quotaWindow: s.quota.window,
			burstWindow: s.burst.window,
			quotaDelta:  s.quota.pending,
			burstDelta:  s.burst.pending,
			carries:     s.carry,
		}
		retry := s.retry
		s.retry = nil
		s.quota.inflight += s.quota.pending
		s.quota.pending = 0
		s.burst.inflight += s.burst.pending
		s.burst.pending = 0
		s.carry = nil
		s.mu.Unlock()

		entries = append(entries, retry...)
		if len(retry) > 0 && !e.hasDelta() {
			// The retried rounds already bring the totals back.
			continue
		}
		e.item = domain.SyncItem{Subject: s.subject, Bumps: []domain.Bump{
			{Kind: domain.KindQuota, Window: e.quotaWindow, Delta: e.quotaDelta},
			{Kind: domain.KindBurst, Window: e.burstWindow, Delta: e.burstDelta},
		}}
		for _, c := range e.carries {
			e.item.Bumps = append(e.item.Bumps, domain.Bump{Kind: domain.KindQuota, Window: c.window, Delta: c.delta})
		}
		if e.hasDelta() {
			e.item.Token = m.podID + "-" + strconv.FormatUint(m.round.Add(1), 10)
		}
		entries = append(entries, e)
	}

	return entries
}

// evictIfIdle drops a tenant nobody has asked about for a while and that owes
// Redis nothing. The slot is marked and removed from the map under both locks
// at once (the map's, then the slot's), so a request holding a reference to it
// finds it evicted and its next lookup already misses it: nothing spins.
func (m *Meter) evictIfIdle(s *slot, now time.Time) bool {
	idle := func() bool {
		s.roll(now)
		return now.Sub(s.lastSeen) > m.opts.IdleEviction && s.quiet()
	}
	// A cheap look first, so the map's write lock is taken only for a candidate.
	s.mu.Lock()
	candidate := idle()
	s.mu.Unlock()
	if !candidate {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !idle() { // a request got in between
		return false
	}
	s.evicted = true
	if m.slots[s.subject] == s {
		delete(m.slots, s.subject)
	}
	return true
}

// quiet reports whether the slot owes Redis nothing.
func (s *slot) quiet() bool {
	return s.quota.pending == 0 && s.quota.inflight == 0 &&
		s.burst.pending == 0 && s.burst.inflight == 0 && len(s.carry) == 0
}

// apply folds the backend's answer into the slots and returns how many tenants
// failed.
func (m *Meter) apply(ctx context.Context, entries []*syncEntry, results []domain.SyncResult, callErr error, failedSlots map[*slot]struct{}) int {
	failed := 0
	for i, e := range entries {
		var res domain.SyncResult
		switch {
		case callErr != nil:
			res.Err = callErr
		case i >= len(results):
			res.Err = errors.New("backend returned fewer results than items")
		default:
			res = results[i]
			if res.Err == nil && len(res.Totals) != len(e.item.Bumps) {
				res.Err = errors.New("backend returned a malformed result")
			}
		}

		if res.Err != nil {
			failed++
			if failedSlots != nil {
				failedSlots[e.slot] = struct{}{}
			}
			m.fail(ctx, e)
			continue
		}
		e.slot.mu.Lock()
		if e.slot.quota.window == e.quotaWindow {
			e.slot.quota.synced = res.Totals[0]
			e.slot.quota.inflight -= e.quotaDelta
		}
		if e.slot.burst.window == e.burstWindow {
			e.slot.burst.synced = res.Totals[1]
			e.slot.burst.inflight -= e.burstDelta
		}
		e.slot.mu.Unlock()
	}
	return failed
}

// fail keeps a failed round for the next tick, as it was, for as long as
// FailedRetention since its first failure. Its usage stays in flight, so it keeps
// counting against the tenant meanwhile. Redis being slow or down must neither
// stall requests nor leak memory, so a round that has failed for that long is
// dropped and counted: an undercount for a tenant, never an unbounded queue.
//
// Time, not attempts, is the bound: with an attempt count the retry cadence
// would decide how much usage is lost.
func (m *Meter) fail(ctx context.Context, e *syncEntry) {
	if !e.hasDelta() {
		return
	}
	now := m.opts.Now()
	if e.firstFailed.IsZero() {
		e.firstFailed = now
	}
	s := e.slot
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(e.firstFailed) < m.opts.FailedRetention {
		s.retry = append(s.retry, e)
		return
	}
	dropped := m.dropLocked(ctx, e, dropReasonRetention)
	m.logger.Warn("rate limit: dropped unsynced usage after Redis stayed unreachable",
		slog.String("component", "ratelimit"),
		slog.Int64("units", dropped),
		slog.Duration("retention", m.opts.FailedRetention))
}

// unsent handles a round whose chunk was never started because the sync's ctx
// ended. It is not a failure: the round was never sent, so it keeps its token
// and firstFailed. Outside the final flush it waits for the next round; in it,
// nobody will send it, so it is dropped and counted.
func (m *Meter) unsent(ctx context.Context, e *syncEntry, final bool) {
	if !e.hasDelta() {
		return
	}
	s := e.slot
	s.mu.Lock()
	defer s.mu.Unlock()
	if !final {
		s.retry = append(s.retry, e)
		return
	}
	m.dropLocked(ctx, e, dropReasonShutdown)
}

const (
	dropReasonRetention = "retention"
	dropReasonShutdown  = "shutdown"
)

// dropLocked gives up on a round: its usage stops counting as in flight and is
// recorded as dropped. The slot's lock must be held.
func (m *Meter) dropLocked(ctx context.Context, e *syncEntry, reason string) int64 {
	s := e.slot
	if s.quota.window == e.quotaWindow {
		s.quota.inflight -= e.quotaDelta
	}
	if s.burst.window == e.burstWindow {
		s.burst.inflight -= e.burstDelta
	}
	dropped := e.quotaDelta
	for _, c := range e.carries {
		dropped += c.delta
	}
	m.metrics.recordDropped(ctx, dropped, reason)
	return dropped
}

// throttle lets one event through per interval and counts what it held back.
type throttle struct {
	every time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (t *throttle) allow(now time.Time) (suppressed int, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.last.IsZero() && now.Sub(t.last) < t.every {
		t.suppressed++
		return 0, false
	}
	t.last = now
	suppressed, t.suppressed = t.suppressed, 0
	return suppressed, true
}
