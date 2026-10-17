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
	"io"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/google/uuid"
)

const (
	// failureLogEvery is the shortest time between two "sync failed" warnings.
	failureLogEvery = 30 * time.Second

	DefaultSyncInterval    = time.Second
	DefaultKickMinGap      = 50 * time.Millisecond
	DefaultIdleEviction    = 10 * time.Minute
	DefaultFailedRetention = 30 * time.Second
	DefaultMaxBatch        = 500
	DefaultFlushTimeout    = 2 * time.Second
	DefaultSyncTimeout     = 200 * time.Millisecond
	// DefaultColdReadTimeout bounds the one read that fills a slot this pod does
	// not have yet. It is longer than the sync round trip because that read can
	// be the first command on the connection.
	DefaultColdReadTimeout = time.Second
	// DefaultSyncWarmTimeout bounds the startup ping and script load. Redis
	// being down must not hold boot; the limiter still serves and fails open.
	DefaultSyncWarmTimeout = 2 * time.Second

	// kickDivisor makes the early-flush threshold a tenth of the cap.
	kickDivisor = 10

	monthWindowLayout = "2006-01"
)

// Options tunes the meter. The zero value of every field means its default.
type Options struct {
	// SyncInterval is how often pending usage is pushed to Redis and the
	// tenant-wide totals are pulled back.
	SyncInterval time.Duration
	// KickMinGap is the shortest time between two syncs when a pod asks for an
	// early one.
	KickMinGap time.Duration
	// IdleEviction is how long a tenant may go unseen before its in-memory
	// counter is dropped.
	IdleEviction time.Duration
	// FailedRetention is how long the usage of a round that keeps failing is
	// kept for resending, counted from that round's first failure. After it the
	// usage is dropped and counted. It is time and not a number of attempts so
	// that how fast the loop retries does not decide how much is lost.
	FailedRetention time.Duration
	// MaxBatch is how many tenants share one pipelined round trip.
	MaxBatch int
	// SyncTimeout bounds one background sync round trip. A request that already
	// has a counter does not wait on it. The cold read uses ColdReadTimeout.
	SyncTimeout time.Duration
	// ColdReadTimeout bounds the Redis read that fills a slot this pod does not
	// have yet. A hard error still fails open.
	ColdReadTimeout time.Duration
	// FlushTimeout is how long the final sync on shutdown may keep starting
	// chunks. A chunk already on the wire is not cancelled (SyncTimeout bounds
	// it), so the flush can overrun FlushTimeout by one chunk. Usage not sent by
	// then is dropped and counted with reason "shutdown".
	FlushTimeout time.Duration
	// DisableKick turns the early-flush off. It exists to measure what the kick
	// buys; production leaves it false.
	DisableKick bool
	// Now is the clock, replaceable in tests.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.SyncInterval <= 0 {
		o.SyncInterval = DefaultSyncInterval
	}
	if o.KickMinGap <= 0 {
		o.KickMinGap = DefaultKickMinGap
	}
	if o.IdleEviction <= 0 {
		o.IdleEviction = DefaultIdleEviction
	}
	if o.FailedRetention <= 0 {
		o.FailedRetention = DefaultFailedRetention
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = DefaultMaxBatch
	}
	if o.SyncTimeout <= 0 {
		o.SyncTimeout = DefaultSyncTimeout
	}
	if o.ColdReadTimeout <= 0 {
		o.ColdReadTimeout = DefaultColdReadTimeout
	}
	if o.FlushTimeout <= 0 {
		o.FlushTimeout = DefaultFlushTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Meter is the plan rate limiter. It counts in memory and reconciles with Redis
// in the background, so a request that already has a counter never waits on Redis.
//
// A pod with no counter for the tenant reads the shared totals once before it
// decides. That counter is dropped after IdleEviction of quiet time, and the
// next request would otherwise see zeros and be admitted until a background
// sync filled them back in. A missing counter is not zero usage. A failed read
// leaves the counters at zero and the request is admitted: Redis being down
// stays fail-open, the same as a failed background sync.
//
// Each pod keeps, per tenant, how much the tenant had spent when it last
// looked (synced), how much it has admitted since (pending), and how much is on
// its way to Redis (inflight). A request is admitted while
// synced+inflight+pending+1 stays within the cap. Because every pod pulls the
// tenant-wide total on each sync, pods converge on the same view within about
// one interval, and the overshoot is what the other pods admit in that window.
type Meter struct {
	resolver GatewayTierLoader
	backend  SyncBackend
	opts     Options
	logger   *slog.Logger
	metrics  *meterMetrics

	mu    sync.RWMutex
	slots map[string]*slot

	kick chan struct{}

	// podID and round name a sync round: the pair is the idempotency token the
	// backend uses to apply a round at most once. The id is random per meter,
	// so two pods (or a restarted pod) never share a token.
	podID string
	round atomic.Uint64

	// failing is true while the last sync looked like an outage: a failed call, or
	// every tenant in a call failing. Early syncs are not asked for
	// meanwhile: Redis being down is not made better by calling it more often.
	failing  atomic.Bool
	syncWarn throttle
}

// NewMeter builds the meter. It does nothing until Run is started.
func NewMeter(resolver GatewayTierLoader, backend SyncBackend, opts Options, logger *slog.Logger) *Meter {
	logger = loggerOrDefault(logger)
	m := &Meter{
		resolver: resolver,
		backend:  backend,
		opts:     opts.withDefaults(),
		logger:   logger,
		slots:    make(map[string]*slot),
		kick:     make(chan struct{}, 1),
		podID:    uuid.NewString(),
	}
	m.syncWarn.every = failureLogEvery
	m.metrics = newMeterMetrics(logger, m.tracked)
	return m
}

var _ Checker = (*Meter)(nil)

func (m *Meter) tracked() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.slots))
}

// Check charges one request against the gateway's plan. A tenant this pod
// already tracks is decided from memory and does not wait on Redis. A tenant
// it does not track is read from the shared counters first; see primeAndAdmit.
//
// The tier lookup runs on every call. A gateway that is not metered (no tenant,
// or neither tenant caps nor a stamp) is let through without touching the
// meter, so self-hosted traffic leaves no counter behind. A lookup that fails
// for any other reason fails open and is counted.
func (m *Meter) Check(ctx context.Context, gatewayID ids.GatewayID) error {
	resolved, err := m.resolver.Resolve(ctx, gatewayID)
	if err != nil {
		if !errors.Is(err, ErrUnmetered) {
			m.logger.Warn("rate limit: failed to load entitlements; fail-open",
				slog.String("gateway_id", gatewayID.String()),
				slog.Any("error", err))
			m.metrics.recordFailOpen(ctx, "tier_load")
		}
		return nil
	}
	return m.admit(resolved)
}

func (m *Meter) admit(r Resolved) error {
	now := m.opts.Now()
	for {
		s, created := m.slotFor(r.Subject, now)
		if created {
			err, retry := m.primeAndAdmit(s, r.Limits, now)
			if retry {
				continue
			}
			return err
		}
		<-s.ready
		s.mu.Lock()
		if s.evicted {
			// Eviction removes the slot from the map under the same locks that
			// mark it, so the next lookup already finds a fresh one.
			s.mu.Unlock()
			continue
		}
		wantKick, err := s.admit(r.Limits, now)
		s.mu.Unlock()
		if wantKick {
			m.signalKick()
		}
		return err
	}
}

// primeAndAdmit loads the shared totals for a slot this pod has just created,
// then admits one request against them. retry is set when the slot was evicted
// during the read; the caller looks up a fresh one.
//
// The read is a zero-delta sync: it does not create keys and it does not add
// usage. It runs before the decision and before ready is closed, so a burst
// that arrives on the empty slot waits and is judged on the same total. When
// the read fails the counters stay at zero and the request is admitted.
func (m *Meter) primeAndAdmit(s *slot, limits domain.Limits, now time.Time) (err error, retry bool) {
	defer close(s.ready)
	quota, burst, ok := m.readShared(s.subject, now)
	s.mu.Lock()
	if s.evicted {
		s.mu.Unlock()
		return nil, true
	}
	if ok {
		s.seed(now, quota, burst)
	}
	_, err = s.admit(limits, now)
	s.mu.Unlock()
	// The slot is new, so ask for a sync now rather than at the next tick: what
	// this request admitted has to reach the shared counters. A rejection
	// admitted nothing; the read above is already the shared total, and the
	// kick is still the same one a new tenant has always asked for.
	m.signalKick()
	return err, false
}

// readShared is the one request-path read. A successful answer is the shared
// total, including zero for a key that is not there. An error is not a total:
// the caller fails open and the background sync keeps trying. The budget is
// ColdReadTimeout, not the sync round trip: this call can be the first command
// on the connection.
//
// A closed socket is retried once, on this same context. The bumps are a zero
// delta, so the first attempt cannot have added usage. Any other error, a
// second failure, or a context that is already done fails open.
func (m *Meter) readShared(subject string, now time.Time) (quota, burst int64, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.ColdReadTimeout)
	defer cancel()
	quota, burst, err := m.readSharedOnce(ctx, subject, now)
	if err != nil && ctx.Err() == nil && isClosedSocket(err) {
		quota, burst, err = m.readSharedOnce(ctx, subject, now)
	}
	if err == nil {
		return quota, burst, true
	}
	m.metrics.recordFailOpen(context.WithoutCancel(ctx), "cold_read")
	m.logger.Warn("rate limit: cold counter read failed; fail-open",
		slog.String("component", "ratelimit"),
		slog.String("subject", subject),
		slog.Any("error", err))
	return 0, 0, false
}

func (m *Meter) readSharedOnce(ctx context.Context, subject string, now time.Time) (quota, burst int64, err error) {
	results, err := m.backend.Sync(ctx, []domain.SyncItem{{
		Subject: subject,
		Bumps: []domain.Bump{
			{Kind: domain.KindQuota, Window: quotaWindow(now), Delta: 0},
			{Kind: domain.KindBurst, Window: burstWindow(now), Delta: 0},
		},
	}})
	if err == nil && len(results) == 1 && results[0].Err == nil && len(results[0].Totals) == 2 {
		return results[0].Totals[0], results[0].Totals[1], nil
	}
	if err == nil {
		if len(results) == 1 && results[0].Err != nil {
			err = results[0].Err
		} else {
			err = errors.New("malformed cold counter read")
		}
	}
	return 0, 0, err
}

// isClosedSocket reports a peer that hung up. Those three are the only errors
// the cold read retries. A timeout, a refusal, or Redis being down is not one
// of them.
func isClosedSocket(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// Warm asks the backend to authenticate and load the sync script. A backend
// with nothing to warm succeeds. The caller bounds ctx and logs a failure;
// enforcement is unchanged either way.
func (m *Meter) Warm(ctx context.Context) error {
	type warmer interface {
		Warm(context.Context) error
	}
	w, ok := m.backend.(warmer)
	if !ok || w == nil {
		return nil
	}
	return w.Warm(ctx)
}

// slotFor returns the tenant's counter, and whether this call created it.
func (m *Meter) slotFor(subject string, now time.Time) (s *slot, created bool) {
	m.mu.RLock()
	s, ok := m.slots[subject]
	m.mu.RUnlock()
	if ok {
		return s, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok = m.slots[subject]; ok {
		return s, false
	}
	s = &slot{subject: subject, lastSeen: now, ready: make(chan struct{})}
	m.slots[subject] = s
	return s, true
}

// signalKick asks the sync loop for an early round. The send never blocks: the
// channel holds one request, and a second one while the first is pending adds
// nothing.
//
// While the last sync failed no early round is asked for: the loop keeps its
// own cadence, so a Redis outage costs one attempt per interval and not one per
// KickMinGap.
func (m *Meter) signalKick() {
	if m.opts.DisableKick || m.failing.Load() {
		return
	}
	select {
	case m.kick <- struct{}{}:
		m.metrics.recordKick(context.Background())
	default:
	}
}

// slot is one tenant's counters on this pod.
type slot struct {
	subject string

	mu       sync.Mutex
	limits   domain.Limits
	quota    counter
	burst    counter
	carry    []carried
	retry    []*syncEntry
	lastSeen time.Time
	evicted  bool
	// ready is closed once the slot's first shared read has finished or failed
	// open. Requests that arrive during that read wait on it.
	ready chan struct{}
}

// counter is one window of one tenant counter.
type counter struct {
	window   string
	synced   int64
	inflight int64
	pending  int64
}

func (c counter) total() int64 { return c.synced + c.inflight + c.pending }

// seed records a shared total learned before the first decision on this slot.
// The windows are set too, so the admission that follows does not roll the
// counters back to zero. A later read only raises a total.
func (s *slot) seed(now time.Time, quota, burst int64) {
	qw := quotaWindow(now)
	if s.quota.window == "" || s.quota.window == qw {
		s.quota.window = qw
		if quota > s.quota.synced {
			s.quota.synced = quota
		}
	}
	bw := burstWindow(now)
	if s.burst.window == "" || s.burst.window == bw {
		s.burst.window = bw
		if burst > s.burst.synced {
			s.burst.synced = burst
		}
	}
}

// carried is usage that belongs to a quota month that has already ended and has
// not reached Redis yet. It is flushed to the month it was spent in.
type carried struct {
	window string
	delta  int64
}

func (s *slot) admit(limits domain.Limits, now time.Time) (kick bool, err error) {
	// The caps come from the snapshot on every call, so a tier change applies
	// to the next request without waiting for a sync.
	s.limits = limits
	s.lastSeen = now
	s.roll(now)

	if exc := s.exceeded(limits, now); exc != nil {
		return false, exc
	}

	// The quota is counted even for a plan without a monthly cap, so the
	// number is there the day the plan gets one.
	s.burst.pending++
	s.quota.pending++

	kick = s.burst.pending >= kickThreshold(limits.BurstPerMin)
	if limits.HasMonthlyQuota() && s.quota.pending >= kickThreshold(limits.QuotaPerMonth) {
		kick = true
	}
	return kick, nil
}

// exceeded is the memory decision: would one more unit go past a cap? The
// counters must already be rolled to now.
func (s *slot) exceeded(limits domain.Limits, now time.Time) *Exceeded {
	if s.burst.total()+1 > int64(limits.BurstPerMin) {
		return &Exceeded{
			Reason:     ReasonBurst,
			Limit:      limits.BurstPerMin,
			Remaining:  0,
			RetryAfter: timeUntilNextMinute(now),
		}
	}
	return s.quotaExceeded(limits, now)
}

// quotaExceeded is the monthly half of the memory decision.
func (s *slot) quotaExceeded(limits domain.Limits, now time.Time) *Exceeded {
	if limits.HasMonthlyQuota() && s.quota.total()+1 > int64(limits.QuotaPerMonth) {
		return &Exceeded{
			Reason:     ReasonQuota,
			Limit:      limits.QuotaPerMonth,
			Remaining:  0,
			RetryAfter: timeUntilNextUTCMonth(now),
		}
	}
	return nil
}

// kickThreshold is the unsynced usage at which a pod asks for an early sync:
// a tenth of the cap, and never less than one.
func kickThreshold(limit int) int64 {
	t := int64(limit) / kickDivisor
	if t < 1 {
		return 1
	}
	return t
}

// roll moves the counters to the windows of now. A new minute starts empty: the
// previous minute's usage is of no use to anyone. A new month does too, but the
// usage still unsent for the old one is carried, because it is billing.
func (s *slot) roll(now time.Time) {
	qw := quotaWindow(now)
	if s.quota.window != qw {
		if s.quota.window != "" && s.quota.pending > 0 {
			s.carry = append(s.carry, carried{window: s.quota.window, delta: s.quota.pending})
		}
		s.quota = counter{window: qw}
	}
	bw := burstWindow(now)
	if s.burst.window != bw {
		s.burst = counter{window: bw}
	}
}

func quotaWindow(now time.Time) string { return now.UTC().Format(monthWindowLayout) }

func burstWindow(now time.Time) string { return strconv.FormatInt(now.Unix()/60, 10) }

func timeUntilNextMinute(now time.Time) time.Duration {
	d := now.Truncate(time.Minute).Add(time.Minute).Sub(now)
	if d < time.Second {
		return time.Second
	}
	return d
}

func timeUntilNextUTCMonth(now time.Time) time.Duration {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	d := next.Sub(now)
	if d < time.Second {
		return time.Second
	}
	return d
}
