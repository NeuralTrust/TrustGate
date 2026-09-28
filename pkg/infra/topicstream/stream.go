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

// Package topicstream carries topic classification requests on a Redis
// stream consumed by a single consumer group, so each request is classified
// by exactly one data plane.
package topicstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/redis/go-redis/v9"
)

// The hash tag keeps the stream and every quota key in one cluster slot, which
// the enqueue script needs to touch both atomically.
const (
	streamKey      = "{topicclassifier}:stream"
	quotaKeyPrefix = "{topicclassifier}:quota:"
	groupName      = "topic-classifier"
	fieldRequest   = "req"

	defaultMaxLen      = 100_000
	defaultRetention   = time.Hour
	quotaWindow        = time.Second
	busyGroupErrPrefix = "BUSYGROUP"
	noGroupErrPrefix   = "NOGROUP"
	claimStart         = "0-0"
)

var enqueueScript = redis.NewScript(`
local quota = tonumber(ARGV[4])
if quota > 0 then
  local n = redis.call('INCR', KEYS[2])
  if n == 1 then
    redis.call('PEXPIRE', KEYS[2], ARGV[5])
  end
  if n > quota then
    return 0
  end
end
redis.call('XADD', KEYS[1], 'MINID', '~', ARGV[3], '*', 'req', ARGV[1])
redis.call('XTRIM', KEYS[1], 'MAXLEN', '~', ARGV[2])
return 1
`)

// Config bounds the stream. Retention is how long an entry may wait before it
// is trimmed, which is also how long customer text can sit in Redis: entries
// are deleted once acknowledged, and Trim drops older ones even when nothing
// new is enqueued.
// GatewayQuotaPerSecond caps what one gateway may enqueue per second so a
// burst from one tenant cannot push everybody else out; zero disables it.
type Config struct {
	MaxLen                int64
	Retention             time.Duration
	GatewayQuotaPerSecond int64
}

func (c Config) withDefaults() Config {
	if c.MaxLen <= 0 {
		c.MaxLen = defaultMaxLen
	}
	if c.Retention <= 0 {
		c.Retention = defaultRetention
	}
	if c.GatewayQuotaPerSecond < 0 {
		c.GatewayQuotaPerSecond = 0
	}
	return c
}

var (
	_ topicclassifier.Queue  = (*Stream)(nil)
	_ topicclassifier.Stream = (*Stream)(nil)
)

// Stream is both ends of the classification queue on Redis.
type Stream struct {
	redis    redis.Cmdable
	cfg      Config
	consumer string
	now      func() time.Time

	mu     sync.Mutex
	cursor string
}

// New builds a Stream. The consumer name identifies this process in the group,
// so entries it leaves pending can be told apart and reclaimed.
func New(client redis.Cmdable, cfg Config) *Stream {
	return &Stream{
		redis:    client,
		cfg:      cfg.withDefaults(),
		consumer: consumerName(),
		now:      time.Now,
		cursor:   claimStart,
	}
}

func consumerName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "trustgate"
	}
	return host + "-" + strconv.Itoa(os.Getpid())
}

// EnsureGroup creates the consumer group, and the stream with it, when missing.
// The group starts at the beginning so entries queued before it existed are
// still classified.
func (s *Stream) EnsureGroup(ctx context.Context) error {
	err := s.redis.XGroupCreateMkStream(ctx, streamKey, groupName, "0").Err()
	if err != nil && !strings.HasPrefix(err.Error(), busyGroupErrPrefix) {
		return fmt.Errorf("topicstream: create group: %w", err)
	}
	return nil
}

// Enqueue appends req to the stream, trimming entries older than the
// retention and beyond the length cap. It returns topic.ErrQuotaExceeded when
// the gateway is over its share.
func (s *Stream) Enqueue(ctx context.Context, req topic.Request) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("topicstream: encode request: %w", err)
	}
	minID := strconv.FormatInt(s.now().Add(-s.cfg.Retention).UnixMilli(), 10)
	added, err := enqueueScript.Run(ctx, s.redis,
		[]string{streamKey, quotaKeyPrefix + req.GatewayID},
		payload, s.cfg.MaxLen, minID, s.cfg.GatewayQuotaPerSecond, quotaWindow.Milliseconds(),
	).Int()
	if err != nil {
		return fmt.Errorf("topicstream: enqueue: %w", err)
	}
	if added == 0 {
		return topic.ErrQuotaExceeded
	}
	return nil
}

// Read hands out up to count entries no consumer has seen yet, waiting at most
// block for the first one.
func (s *Stream) Read(ctx context.Context, count int, block time.Duration) ([]topicclassifier.Delivery, error) {
	streams, err := s.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    groupName,
		Consumer: s.consumer,
		Streams:  []string{streamKey, ">"},
		Count:    int64(count),
		Block:    block,
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if isNoGroup(err) {
		return nil, s.EnsureGroup(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("topicstream: read: %w", err)
	}
	var out []topicclassifier.Delivery
	for _, st := range streams {
		for _, msg := range st.Messages {
			d := decode(msg)
			d.Deliveries = 1
			out = append(out, d)
		}
	}
	return out, nil
}

// Reclaim takes over entries another consumer left pending for at least
// minIdle, typically because its process died, and reports how many times
// each was handed out so poison entries can be dropped. Each call resumes the
// scan where the previous one stopped, so a pending list longer than count is
// walked in full over successive calls.
func (s *Stream) Reclaim(ctx context.Context, minIdle time.Duration, count int) ([]topicclassifier.Delivery, error) {
	s.mu.Lock()
	start := s.cursor
	s.mu.Unlock()
	msgs, next, err := s.redis.XAutoClaim(ctx, &redis.XAutoClaimArgs{
		Stream:   streamKey,
		Group:    groupName,
		Consumer: s.consumer,
		MinIdle:  minIdle,
		Start:    start,
		Count:    int64(count),
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if isNoGroup(err) {
		s.resetCursor()
		return nil, s.EnsureGroup(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("topicstream: reclaim: %w", err)
	}
	if next == "" {
		next = claimStart
	}
	s.mu.Lock()
	s.cursor = next
	s.mu.Unlock()
	if len(msgs) == 0 {
		return nil, nil
	}
	counts, err := s.deliveryCounts(ctx, msgs)
	if err != nil {
		return nil, err
	}
	out := make([]topicclassifier.Delivery, 0, len(msgs))
	for _, msg := range msgs {
		d := decode(msg)
		d.Deliveries = counts[msg.ID]
		out = append(out, d)
	}
	return out, nil
}

func (s *Stream) resetCursor() {
	s.mu.Lock()
	s.cursor = claimStart
	s.mu.Unlock()
}

// deliveryCounts asks for each claimed entry on its own, in one round trip, so
// other entries this consumer holds in the same id range cannot push any of
// them out of the reply. An entry missing from the reply reports zero, which
// never counts as poison: it is checked again on a later claim.
func (s *Stream) deliveryCounts(ctx context.Context, msgs []redis.XMessage) (map[string]int64, error) {
	pipe := s.redis.Pipeline()
	cmds := make([]*redis.XPendingExtCmd, len(msgs))
	for i, msg := range msgs {
		cmds[i] = pipe.XPendingExt(ctx, &redis.XPendingExtArgs{
			Stream: streamKey,
			Group:  groupName,
			Start:  msg.ID,
			End:    msg.ID,
			Count:  1,
		})
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("topicstream: pending: %w", err)
	}
	counts := make(map[string]int64, len(msgs))
	for _, cmd := range cmds {
		for _, p := range cmd.Val() {
			counts[p.ID] = p.RetryCount
		}
	}
	return counts, nil
}

// Touch resets the idle time of entries this consumer is still working on, so
// no other consumer reclaims them while a slow batch waits for topic-guard. It
// does not count as a delivery.
func (s *Stream) Touch(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	err := s.redis.XClaimJustID(ctx, &redis.XClaimArgs{
		Stream:   streamKey,
		Group:    groupName,
		Consumer: s.consumer,
		MinIdle:  0,
		Messages: ids,
	}).Err()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("topicstream: touch: %w", err)
	}
	return nil
}

// Trim drops entries older than the retention. Enqueue trims too, but only
// when something new arrives; this keeps the bound when traffic stops.
func (s *Stream) Trim(ctx context.Context) error {
	minID := strconv.FormatInt(s.now().Add(-s.cfg.Retention).UnixMilli(), 10)
	if err := s.redis.XTrimMinID(ctx, streamKey, minID).Err(); err != nil {
		return fmt.Errorf("topicstream: trim: %w", err)
	}
	return nil
}

// Leave removes this consumer from the group on a clean shutdown, so every
// restart does not leave one more consumer behind. A consumer that still
// holds entries stays, so they can be reclaimed.
func (s *Stream) Leave(ctx context.Context) error {
	n, err := s.redis.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream:   streamKey,
		Group:    groupName,
		Start:    "-",
		End:      "+",
		Count:    1,
		Consumer: s.consumer,
	}).Result()
	if err != nil {
		if isNoGroup(err) {
			return nil
		}
		return fmt.Errorf("topicstream: pending: %w", err)
	}
	if len(n) > 0 {
		return nil
	}
	if err := s.redis.XGroupDelConsumer(ctx, streamKey, groupName, s.consumer).Err(); err != nil && !isNoGroup(err) {
		return fmt.Errorf("topicstream: leave group: %w", err)
	}
	return nil
}

// Stats reports how many entries the stream holds and how many were handed
// out but not acknowledged yet. A growing length means requests arrive faster
// than they are classified; a growing pending count means consumers stall.
func (s *Stream) Stats(ctx context.Context) (length, pending int64, err error) {
	pipe := s.redis.Pipeline()
	lenCmd := pipe.XLen(ctx, streamKey)
	pendingCmd := pipe.XPending(ctx, streamKey, groupName)
	_, _ = pipe.Exec(ctx)
	length, err = lenCmd.Result()
	if err != nil {
		return 0, 0, fmt.Errorf("topicstream: length: %w", err)
	}
	summary, err := pendingCmd.Result()
	if err != nil {
		if isNoGroup(err) {
			return length, 0, nil
		}
		return length, 0, fmt.Errorf("topicstream: pending: %w", err)
	}
	return length, summary.Count, nil
}

// Ack marks entries as done and deletes them, so the customer text they carry
// leaves Redis as soon as it is classified.
func (s *Stream) Ack(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	pipe := s.redis.TxPipeline()
	pipe.XAck(ctx, streamKey, groupName, ids...)
	pipe.XDel(ctx, streamKey, ids...)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("topicstream: ack: %w", err)
	}
	return nil
}

// isNoGroup reports a missing consumer group, which happens when Redis lost
// the stream (a flush, a failover without persistence). The group is simply
// created again.
func isNoGroup(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), noGroupErrPrefix)
}

func decode(msg redis.XMessage) topicclassifier.Delivery {
	d := topicclassifier.Delivery{ID: msg.ID}
	raw, ok := msg.Values[fieldRequest].(string)
	if !ok {
		d.Invalid = true
		return d
	}
	if err := json.Unmarshal([]byte(raw), &d.Request); err != nil {
		d.Invalid = true
	}
	return d
}
