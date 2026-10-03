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

package labelstream

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

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/redis/go-redis/v9"
)

// The hash tag keeps the stream and quota keys in one cluster slot for the enqueue script.
const (
	streamKey      = "{trafficlabels}:stream"
	quotaKeyPrefix = "{trafficlabels}:quota:"
	groupName      = "traffic-labels"
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
	_ trafficlabels.Queue  = (*Stream)(nil)
	_ trafficlabels.Stream = (*Stream)(nil)
)

type Stream struct {
	redis    redis.Cmdable
	cfg      Config
	consumer string
	now      func() time.Time

	mu     sync.Mutex
	cursor string
}

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

func (s *Stream) EnsureGroup(ctx context.Context) error {
	err := s.redis.XGroupCreateMkStream(ctx, streamKey, groupName, "0").Err()
	if err != nil && !strings.HasPrefix(err.Error(), busyGroupErrPrefix) {
		return fmt.Errorf("labelstream: create group: %w", err)
	}
	return nil
}

func (s *Stream) Enqueue(ctx context.Context, req trafficlabel.Request) error {
	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("labelstream: encode request: %w", err)
	}
	minID := strconv.FormatInt(s.now().Add(-s.cfg.Retention).UnixMilli(), 10)
	added, err := enqueueScript.Run(ctx, s.redis,
		[]string{streamKey, quotaKeyPrefix + req.GatewayID},
		payload, s.cfg.MaxLen, minID, s.cfg.GatewayQuotaPerSecond, quotaWindow.Milliseconds(),
	).Int()
	if err != nil {
		return fmt.Errorf("labelstream: enqueue: %w", err)
	}
	if added == 0 {
		return trafficlabel.ErrQuotaExceeded
	}
	return nil
}

func (s *Stream) Read(ctx context.Context, count int, block time.Duration) ([]trafficlabels.Delivery, error) {
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
		return nil, fmt.Errorf("labelstream: read: %w", err)
	}
	var out []trafficlabels.Delivery
	for _, st := range streams {
		for _, msg := range st.Messages {
			d := decode(msg)
			d.Deliveries = 1
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *Stream) Reclaim(ctx context.Context, minIdle time.Duration, count int) ([]trafficlabels.Delivery, error) {
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
		return nil, fmt.Errorf("labelstream: reclaim: %w", err)
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
	out := make([]trafficlabels.Delivery, 0, len(msgs))
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
		return nil, fmt.Errorf("labelstream: pending: %w", err)
	}
	counts := make(map[string]int64, len(msgs))
	for _, cmd := range cmds {
		for _, p := range cmd.Val() {
			counts[p.ID] = p.RetryCount
		}
	}
	return counts, nil
}

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
		return fmt.Errorf("labelstream: touch: %w", err)
	}
	return nil
}

func (s *Stream) Trim(ctx context.Context) error {
	minID := strconv.FormatInt(s.now().Add(-s.cfg.Retention).UnixMilli(), 10)
	if err := s.redis.XTrimMinID(ctx, streamKey, minID).Err(); err != nil {
		return fmt.Errorf("labelstream: trim: %w", err)
	}
	return nil
}

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
		return fmt.Errorf("labelstream: pending: %w", err)
	}
	if len(n) > 0 {
		return nil
	}
	if err := s.redis.XGroupDelConsumer(ctx, streamKey, groupName, s.consumer).Err(); err != nil && !isNoGroup(err) {
		return fmt.Errorf("labelstream: leave group: %w", err)
	}
	return nil
}

func (s *Stream) Stats(ctx context.Context) (length, pending int64, err error) {
	pipe := s.redis.Pipeline()
	lenCmd := pipe.XLen(ctx, streamKey)
	pendingCmd := pipe.XPending(ctx, streamKey, groupName)
	_, _ = pipe.Exec(ctx)
	length, err = lenCmd.Result()
	if err != nil {
		return 0, 0, fmt.Errorf("labelstream: length: %w", err)
	}
	summary, err := pendingCmd.Result()
	if err != nil {
		if isNoGroup(err) {
			return length, 0, nil
		}
		return length, 0, fmt.Errorf("labelstream: pending: %w", err)
	}
	return length, summary.Count, nil
}

func (s *Stream) Ack(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	pipe := s.redis.TxPipeline()
	pipe.XAck(ctx, streamKey, groupName, ids...)
	pipe.XDel(ctx, streamKey, ids...)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("labelstream: ack: %w", err)
	}
	return nil
}

func isNoGroup(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), noGroupErrPrefix)
}

func decode(msg redis.XMessage) trafficlabels.Delivery {
	d := trafficlabels.Delivery{ID: msg.ID}
	raw, ok := msg.Values[fieldRequest].(string)
	if !ok {
		d.Invalid = true
		return d
	}
	if err := json.Unmarshal([]byte(raw), &d.Request); err != nil || len(d.Request.LabelSets) == 0 {
		// An entry without label sets has nothing to classify; it is also
		// what an entry queued by the single-label version decodes to.
		d.Invalid = true
	}
	return d
}
