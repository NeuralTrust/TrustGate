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
// is trimmed, which is also how long customer text can sit in Redis.
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
}

// New builds a Stream. The consumer name identifies this process in the group,
// so entries it leaves pending can be told apart and reclaimed.
func New(client redis.Cmdable, cfg Config) *Stream {
	return &Stream{
		redis:    client,
		cfg:      cfg.withDefaults(),
		consumer: consumerName(),
		now:      time.Now,
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
// each was handed out so poison entries can be dropped.
func (s *Stream) Reclaim(ctx context.Context, minIdle time.Duration, count int) ([]topicclassifier.Delivery, error) {
	msgs, _, err := s.redis.XAutoClaim(ctx, &redis.XAutoClaimArgs{
		Stream:   streamKey,
		Group:    groupName,
		Consumer: s.consumer,
		MinIdle:  minIdle,
		Start:    "0-0",
		Count:    int64(count),
	}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if isNoGroup(err) {
		return nil, s.EnsureGroup(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("topicstream: reclaim: %w", err)
	}
	if len(msgs) == 0 {
		return nil, nil
	}
	counts, err := s.deliveryCounts(ctx, msgs[0].ID, msgs[len(msgs)-1].ID, len(msgs))
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

func (s *Stream) deliveryCounts(ctx context.Context, first, last string, n int) (map[string]int64, error) {
	pending, err := s.redis.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream:   streamKey,
		Group:    groupName,
		Start:    first,
		End:      last,
		Count:    int64(n),
		Consumer: s.consumer,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("topicstream: pending: %w", err)
	}
	counts := make(map[string]int64, len(pending))
	for _, p := range pending {
		counts[p.ID] = p.RetryCount
	}
	return counts, nil
}

// Stats reports how many entries the stream holds and how many were handed
// out but not acknowledged yet. A growing length means requests arrive faster
// than they are classified; a growing pending count means consumers stall.
func (s *Stream) Stats(ctx context.Context) (length, pending int64, err error) {
	length, err = s.redis.XLen(ctx, streamKey).Result()
	if err != nil {
		return 0, 0, fmt.Errorf("topicstream: length: %w", err)
	}
	summary, err := s.redis.XPending(ctx, streamKey, groupName).Result()
	if err != nil {
		if isNoGroup(err) {
			return length, 0, nil
		}
		return length, 0, fmt.Errorf("topicstream: pending: %w", err)
	}
	return length, summary.Count, nil
}

// Ack marks entries as done so they are never handed out again.
func (s *Stream) Ack(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := s.redis.XAck(ctx, streamKey, groupName, ids...).Err(); err != nil {
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
