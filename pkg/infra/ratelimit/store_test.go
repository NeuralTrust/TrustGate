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
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	bg  = context.Background()
	now = time.Date(2026, time.October, 15, 12, 0, 10, 0, time.UTC)
)

func testStore(t *testing.T) (*Store, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	s := NewStore(rc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = func() time.Time { return now }
	return s, mr, rc
}

func bumps(quota, burst int64) []domain.Bump {
	return []domain.Bump{
		{Kind: domain.KindQuota, Window: "2026-10", Delta: quota},
		{Kind: domain.KindBurst, Window: "29660400", Delta: burst},
	}
}

func TestStoreSyncAppliesDeltasAndReturnsTotals(t *testing.T) {
	s, mr, _ := testStore(t)

	res, err := s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Bumps: bumps(5, 3)}})
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.NoError(t, res[0].Err)
	assert.Equal(t, []int64{5, 3}, res[0].Totals)

	res, err = s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Bumps: bumps(2, 1)}})
	require.NoError(t, err)
	assert.Equal(t, []int64{7, 4}, res[0].Totals, "totals are tenant-wide and accumulate across calls")

	got, err := mr.Get("gt:rl:quota:{tenant-1}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, "7", got)
	got, err = mr.Get("gt:rl:burst:{tenant-1}:29660400")
	require.NoError(t, err)
	assert.Equal(t, "4", got)
}

// The subject sits in a hash tag so every key of one tenant lands in one
// Redis Cluster slot, which the multi-key script requires.
func TestStoreSyncAppliesAnItemOncePerToken(t *testing.T) {
	s, mr, _ := testStore(t)
	item := domain.SyncItem{Subject: "tenant-1", Token: "pod-a-1", Bumps: bumps(5, 3)}

	res, err := s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)
	assert.Equal(t, []int64{5, 3}, res[0].Totals)

	res, err = s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)
	require.NoError(t, res[0].Err)
	assert.Equal(t, []int64{5, 3}, res[0].Totals, "a repeat reports the totals and applies nothing")

	other := domain.SyncItem{Subject: "tenant-1", Token: "pod-a-2", Bumps: bumps(2, 1)}
	res, err = s.Sync(bg, []domain.SyncItem{other})
	require.NoError(t, err)
	assert.Equal(t, []int64{7, 4}, res[0].Totals, "a new token is a new round")

	got, err := mr.Get("gt:rl:quota:{tenant-1}:2026-10")
	require.NoError(t, err)
	assert.Equal(t, "7", got)
}

func TestStoreTokenKeySharesTheSubjectHashTagAndExpires(t *testing.T) {
	s, mr, _ := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Token: "pod-a-1", Bumps: bumps(1, 1)}})
	require.NoError(t, err)

	key := "gt:rl:tok:{tenant-1}:pod-a-1"
	assert.True(t, mr.Exists(key), "same hash tag as the counters, so one slot")
	assert.Equal(t, domain.TokenTTL(0), mr.TTL(key))
}

func TestStoreItemWithoutATokenWritesNoTokenKey(t *testing.T) {
	s, mr, _ := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Bumps: bumps(0, 0)}})
	require.NoError(t, err)
	assert.Empty(t, mr.Keys())
}

func TestStoreKeysHashTagTheSubject(t *testing.T) {
	s, mr, _ := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Bumps: bumps(1, 1)}})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"gt:rl:quota:{tenant-1}:2026-10", "gt:rl:burst:{tenant-1}:29660400"}, mr.Keys())
}

func TestStoreSubjectBracesCannotCutTheHashTagShort(t *testing.T) {
	assert.Equal(t, "a_b_c", subjectTag("a{b}c"))
	s, mr, _ := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "a{b}c", Bumps: bumps(1, 1)}})
	require.NoError(t, err)
	assert.True(t, mr.Exists("gt:rl:quota:{a_b_c}:2026-10"))
}

func TestStoreSetsTTLs(t *testing.T) {
	s, mr, _ := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.NoError(t, err)

	// "now" is 2026-10-15 12:00:10 UTC; the quota key lives until 2026-11-01 00:00:00 UTC.
	wantQuota := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC).Sub(now)
	assert.Equal(t, wantQuota, mr.TTL("gt:rl:quota:{t}:2026-10"))
	assert.Equal(t, 2*time.Minute, mr.TTL("gt:rl:burst:{t}:29660400"))
}

func TestStoreTTLIsSetOnceNotExtendedByLaterWrites(t *testing.T) {
	s, mr, _ := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.NoError(t, err)

	mr.FastForward(90 * time.Second)
	_, err = s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.NoError(t, err)

	assert.LessOrEqual(t, mr.TTL("gt:rl:burst:{t}:29660400"), 30*time.Second,
		"a busy tenant must not keep its own burst bucket alive")
}

func TestStoreGivesAKeyThatLostItsTTLOneBack(t *testing.T) {
	s, mr, _ := testStore(t)
	require.NoError(t, mr.Set("gt:rl:burst:{t}:29660400", "9"))
	require.Zero(t, mr.TTL("gt:rl:burst:{t}:29660400"))

	res, err := s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(0, 1)}})
	require.NoError(t, err)
	assert.EqualValues(t, 10, res[0].Totals[1])
	assert.Equal(t, 2*time.Minute, mr.TTL("gt:rl:burst:{t}:29660400"), "otherwise it would live forever")
}

// A zero delta is how a pod that spent nothing learns what the others spent.
// It must read, not create.
func TestStoreZeroDeltaReadsWithoutCreatingKeys(t *testing.T) {
	s, mr, _ := testStore(t)

	res, err := s.Sync(bg, []domain.SyncItem{{Subject: "quiet", Bumps: bumps(0, 0)}})
	require.NoError(t, err)
	assert.Equal(t, []int64{0, 0}, res[0].Totals)
	assert.Empty(t, mr.Keys())

	_, err = s.Sync(bg, []domain.SyncItem{{Subject: "busy", Bumps: bumps(4, 2)}})
	require.NoError(t, err)
	res, err = s.Sync(bg, []domain.SyncItem{{Subject: "busy", Bumps: bumps(0, 0)}})
	require.NoError(t, err)
	assert.Equal(t, []int64{4, 2}, res[0].Totals)
}

func TestStoreSubjectsInOneBatchAreIsolated(t *testing.T) {
	s, _, _ := testStore(t)
	res, err := s.Sync(bg, []domain.SyncItem{
		{Subject: "a", Bumps: bumps(3, 3)},
		{Subject: "b", Bumps: bumps(1, 1)},
	})
	require.NoError(t, err)
	assert.Equal(t, []int64{3, 3}, res[0].Totals)
	assert.Equal(t, []int64{1, 1}, res[1].Totals)
}

func TestStoreCarriedBumpGoesToTheOldMonth(t *testing.T) {
	s, mr, _ := testStore(t)
	res, err := s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: []domain.Bump{
		{Kind: domain.KindQuota, Window: "2026-10", Delta: 2},
		{Kind: domain.KindBurst, Window: "29660400", Delta: 0},
		{Kind: domain.KindQuota, Window: "2026-09", Delta: 7},
	}}})
	require.NoError(t, err)
	assert.Equal(t, []int64{2, 0, 7}, res[0].Totals)
	assert.True(t, mr.Exists("gt:rl:quota:{t}:2026-09"))
	assert.GreaterOrEqual(t, mr.TTL("gt:rl:quota:{t}:2026-09"), minQuotaTTL,
		"a late delta for a month that ended must not create an already-expired key")
}

func TestStoreOneBadItemDoesNotFailTheBatch(t *testing.T) {
	s, _, _ := testStore(t)
	res, err := s.Sync(bg, []domain.SyncItem{
		{Subject: "bad", Bumps: []domain.Bump{{Kind: "nope", Window: "x", Delta: 1}}},
		{Subject: "good", Bumps: bumps(1, 1)},
	})
	require.NoError(t, err)
	require.Error(t, res[0].Err)
	require.NoError(t, res[1].Err)
	assert.Equal(t, []int64{1, 1}, res[1].Totals)
}

// A restart or failover of Redis forgets the script. go-redis does not fall
// back to EVAL inside a pipeline, so the store must reload it itself.
func TestStoreRecoversFromAFlushedScriptCache(t *testing.T) {
	s, _, rc := testStore(t)
	_, err := s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.NoError(t, err)

	require.NoError(t, rc.ScriptFlush(bg).Err())

	res, err := s.Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.NoError(t, err)
	require.NoError(t, res[0].Err, "NOSCRIPT must be retried after a reload")
	assert.Equal(t, []int64{2, 2}, res[0].Totals)
}

func TestStoreWithoutAClientFails(t *testing.T) {
	_, err := NewStore(nil, nil).Sync(bg, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.Error(t, err)
}

func TestStoreDownRedisReturnsAnError(t *testing.T) {
	s, mr, _ := testStore(t)
	mr.Close()
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	_, err := s.Sync(ctx, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.Error(t, err)
}

// A Redis that accepts the connection and never answers is the worst case for
// a client: no error to react to. The call has to give up on the sync timeout.
func TestStoreUnresponsiveRedisGivesUpOnTheContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	rc := redis.NewClient(&redis.Options{
		Addr: ln.Addr().String(), ContextTimeoutEnabled: true, MaxRetries: -1,
		DialTimeout: 200 * time.Millisecond, ReadTimeout: 200 * time.Millisecond, WriteTimeout: 200 * time.Millisecond,
	})
	t.Cleanup(func() { _ = rc.Close() })
	s := NewStore(rc, nil)

	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.Sync(ctx, []domain.SyncItem{{Subject: "t", Bumps: bumps(1, 1)}})
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}

func TestStoreAcquireAuditGrantsExactlyOneCaller(t *testing.T) {
	s, mr, _ := testStore(t)
	first, err := s.AcquireAudit(bg, "per-tenant-rollout:2026-10")
	require.NoError(t, err)
	second, err := s.AcquireAudit(bg, "per-tenant-rollout:2026-10")
	require.NoError(t, err)
	assert.True(t, first)
	assert.False(t, second)
	assert.Greater(t, mr.TTL("gt:rl:audit:per-tenant-rollout:2026-10"), 30*24*time.Hour, "the gateway outlives the month")

	other, err := s.AcquireAudit(bg, "per-tenant-rollout:2026-11")
	require.NoError(t, err)
	assert.True(t, other, "a new month is a new audit")
}

func TestStoreReleaseAuditGivesTheClaimBack(t *testing.T) {
	s, _, _ := testStore(t)
	first, err := s.AcquireAudit(bg, "per-tenant-rollout:2026-10")
	require.NoError(t, err)
	require.True(t, first)

	require.NoError(t, s.ReleaseAudit(bg, "per-tenant-rollout:2026-10"))

	again, err := s.AcquireAudit(bg, "per-tenant-rollout:2026-10")
	require.NoError(t, err)
	assert.True(t, again, "a released claim can be taken by the next pod or boot")
}

func TestStoreLegacyQuotaByGatewayReadsOnlyOldPerGatewayKeys(t *testing.T) {
	s, mr, _ := testStore(t)
	g1, g2 := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	tenantUUID := ids.New[ids.GatewayKind]()
	require.NoError(t, mr.Set("gt:rl:quota:"+g1.String()+":2026-10", "40"))
	require.NoError(t, mr.Set("gt:rl:quota:"+g2.String()+":2026-10", "2"))
	require.NoError(t, mr.Set("gt:rl:quota:"+g1.String()+":2026-09", "99"))          // another month
	require.NoError(t, mr.Set("gt:rl:quota:{tenant-1}:2026-10", "7"))                // current format
	require.NoError(t, mr.Set("gt:rl:quota:{"+tenantUUID.String()+"}:2026-10", "8")) // current format, tenant id is a uuid
	require.NoError(t, mr.Set("gt:rl:burst:"+g1.String(), "5"))                      // not quota
	require.NoError(t, mr.Set("gt:rl:quota:not-a-uuid:2026-10", "1"))                // junk

	got, err := s.LegacyQuotaByGateway(bg, "2026-10")
	require.NoError(t, err)
	assert.Equal(t, map[ids.GatewayID]int64{g1: 40, g2: 2}, got)
}

func TestStoreTokenTTLFollowsTheConfiguredRetention(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	s := NewStore(rc, nil, WithFailedRetention(2*time.Minute))
	s.now = func() time.Time { return now }

	_, err = s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Token: "pod-a-1", Bumps: bumps(1, 1)}})
	require.NoError(t, err)
	assert.Equal(t, 4*time.Minute, mr.TTL("gt:rl:tok:{tenant-1}:pod-a-1"))
}

// A round resent at the very end of its retention is still recognised: the
// token outlives retention + the slowest resend.
func TestStoreDeduplicatesARoundResentAtTheEndOfRetention(t *testing.T) {
	const retention = 45 * time.Second
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	s := NewStore(rc, nil, WithFailedRetention(retention))
	s.now = func() time.Time { return now }

	item := domain.SyncItem{Subject: "tenant-1", Token: "pod-a-1", Bumps: bumps(3, 3)}
	res, err := s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)
	require.Equal(t, []int64{3, 3}, res[0].Totals)

	mr.FastForward(retention + time.Second + 200*time.Millisecond)
	res, err = s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)
	assert.Equal(t, []int64{3, 3}, res[0].Totals, "the resend was recognised, not applied again")
}

// Gate and Guard share a Redis cluster (different databases, same tenants), and
// their plan budgets are independent. The prefix is what keeps them apart on a
// deployment that points both at one database, so every key the Gate sync writes
// is proved to carry the Gate prefix and a Guard counter for the same tenant is
// neither read nor written.
func TestStoreKeysNeverTouchTheGuardNamespace(t *testing.T) {
	s, mr, _ := testStore(t)
	require.NoError(t, mr.Set("tg:rl:quota:{tenant-1}:2026-10", "999"))
	require.NoError(t, mr.Set("tg:rl:burst:{tenant-1}:29660400", "777"))

	res, err := s.Sync(bg, []domain.SyncItem{{Subject: "tenant-1", Token: "pod-a-1", Bumps: bumps(5, 3)}})
	require.NoError(t, err)
	assert.Equal(t, []int64{5, 3}, res[0].Totals, "the Gate total starts from zero, whatever Guard has spent")

	for _, key := range mr.Keys() {
		if key == "tg:rl:quota:{tenant-1}:2026-10" || key == "tg:rl:burst:{tenant-1}:29660400" {
			continue
		}
		assert.Truef(t, len(key) > 6 && key[:6] == "gt:rl:", "key %q is not in the Gate namespace", key)
	}
	got, _ := mr.Get("tg:rl:quota:{tenant-1}:2026-10")
	assert.Equal(t, "999", got, "the Guard counter must be left alone")
	got, _ = mr.Get("tg:rl:burst:{tenant-1}:29660400")
	assert.Equal(t, "777", got)
}

// A resend that finds its token pushes the expiry out again, so a retried entry
// whose later chunks go out late cannot lose its token between two sends.
func TestStoreResendRefreshesTheTokenTTL(t *testing.T) {
	const retention = 45 * time.Second
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	s := NewStore(rc, nil, WithFailedRetention(retention))
	s.now = func() time.Time { return now }

	item := domain.SyncItem{Subject: "tenant-1", Token: "pod-a-1", Bumps: bumps(3, 3)}
	_, err = s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)

	key := "gt:rl:tok:{tenant-1}:pod-a-1"
	ttl := domain.TokenTTL(retention)
	mr.FastForward(ttl - 10*time.Second)
	require.Equal(t, 10*time.Second, mr.TTL(key))

	res, err := s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)
	require.Equal(t, []int64{3, 3}, res[0].Totals, "the resend was recognised")
	assert.Equal(t, ttl, mr.TTL(key), "the duplicate send reset the token's expiry")

	mr.FastForward(ttl - time.Second)
	res, err = s.Sync(bg, []domain.SyncItem{item})
	require.NoError(t, err)
	// Only the quota counter outlives that long; the burst key has expired.
	assert.EqualValues(t, 3, res[0].Totals[0], "still recognised past the original expiry, not applied again")
}
