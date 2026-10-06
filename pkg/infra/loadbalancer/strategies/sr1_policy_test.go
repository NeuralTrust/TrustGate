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

package strategies

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type sr1TestScorer struct {
	score float64
	err   error
	calls atomic.Int64
}

func (s *sr1TestScorer) Configured() bool { return true }
func (s *sr1TestScorer) ScoreSR1(context.Context, string, string) (float64, error) {
	s.calls.Add(1)
	return s.score, s.err
}

func sr1Fixture(t *testing.T) (*miniredis.Miniredis, *redis.Client, *RedisSR1Store) {
	t.Helper()
	mr := miniredis.RunT(t)
	mr.SetTime(time.Unix(1800000000, 0))
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client, NewRedisSR1Store(client)
}

func TestSR1RedisPolicy(t *testing.T) {
	mr, client, store := sr1Fixture(t)
	ctx := context.Background()
	ttl := time.Second
	choose := func(key, turn string, desired int, newUser bool, want int) {
		t.Helper()
		got, err := store.Choose(ctx, key, turn, desired, 3, ttl, newUser, true)
		if err != nil || got != want {
			t.Fatalf("Choose(%s,%s)=%d,%v want %d", key, turn, got, err, want)
		}
	}
	choose("cold", "a", 0, true, 0)
	choose("cold", "a", 2, true, 0)
	choose("cold", "tool", 2, false, 0)
	choose("cold", "b", 2, true, 1)
	choose("cold", "c", 2, true, 1)
	choose("cold", "d", 0, true, 1)
	if got := client.HGet(ctx, "cold", "escapes").Val(); got != "1" {
		t.Fatalf("escapes=%s", got)
	}
	choose("boundary", "a", 0, true, 0)
	mr.SetTime(time.Unix(1800000001, 0))
	choose("boundary", "tool", 2, false, 0)
	mr.SetTime(time.Unix(1800000002, 0).Add(time.Millisecond))
	choose("boundary", "b", 2, true, 2)
	if got := client.HGet(ctx, "boundary", "escapes").Val(); got != "0" {
		t.Fatalf("reset escapes=%s", got)
	}
}

func TestSR1RedisConcurrentEscape(t *testing.T) {
	_, client, store := sr1Fixture(t)
	ctx := context.Background()
	if _, err := store.Choose(ctx, "parallel", "seed", 0, 3, time.Minute, true, true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rung, err := store.Choose(ctx, "parallel", fmt.Sprint(i), 2, 3, time.Minute, true, true)
			if err != nil || rung != 1 {
				t.Errorf("rung=%d err=%v", rung, err)
			}
		}(i)
	}
	wg.Wait()
	if got := client.HGet(ctx, "parallel", "escapes").Val(); got != "1" {
		t.Fatalf("escapes=%s", got)
	}
}

func TestSR1RedisProbeAndIdleBoundary(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("escape=%t", enabled), func(t *testing.T) {
			mr, client, store := sr1Fixture(t)
			ctx := context.Background()
			const key = "probe"
			ttl := time.Second
			probe := func(turn string, newUser bool, rung int, needsScore bool) {
				t.Helper()
				got, err := store.Probe(ctx, key, turn, 3, ttl, newUser, enabled)
				if err != nil || got.Rung != rung || got.NeedsScore != needsScore {
					t.Fatalf("Probe(%s,%t)=%+v,%v want rung=%d score=%t", turn, newUser, got, err, rung, needsScore)
				}
			}
			probe("a", true, -1, true)
			if client.Exists(ctx, key).Val() != 0 {
				t.Fatal("cold probe committed a rung before scoring")
			}
			if got, err := store.Choose(ctx, key, "a", 0, 3, ttl, true, enabled); err != nil || got != 0 {
				t.Fatalf("seed=%d,%v", got, err)
			}
			probe("a", true, 0, false)
			probe("tool", false, 0, false)
			probe("b", true, 0, enabled)
			if client.HGet(ctx, key, "turn").Val() != "a" || client.HGet(ctx, key, "escapes").Val() != "0" {
				t.Fatal("probe changed turn identity or spent an escape")
			}
			mr.SetTime(time.Unix(1800000001, 0))
			probe("tool", false, 0, false)
			if got := client.HGet(ctx, key, "last").Val(); got != "1800000001000" {
				t.Fatalf("warm probe did not touch lifetime: last=%s", got)
			}
			mr.SetTime(time.Unix(1800000002, 0).Add(time.Millisecond))
			probe("c", true, -1, true)
			if got := client.HGet(ctx, key, "last").Val(); got != "1800000001000" {
				t.Fatalf("cold probe extended expired commitment: last=%s", got)
			}
			if got, err := store.Choose(ctx, key, "c", 2, 3, ttl, true, enabled); err != nil || got != 2 {
				t.Fatalf("expired cold decision=%d,%v", got, err)
			}
			probe("d", true, 2, false)
			if got := client.HGet(ctx, key, "escapes").Val(); got != "0" {
				t.Fatalf("cold decision consumed escape=%s", got)
			}
		})
	}
}

func TestSR1RedisConcurrentProbeAndChooseBothPreferences(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("escape=%t", enabled), func(t *testing.T) {
			_, client, store := sr1Fixture(t)
			ctx := context.Background()
			if _, err := store.Choose(ctx, "parallel", "seed", 0, 3, time.Minute, true, enabled); err != nil {
				t.Fatal(err)
			}
			want := 0
			if enabled {
				want = 1
			}
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					turn := fmt.Sprint(i)
					decision, err := store.Probe(ctx, "parallel", turn, 3, time.Minute, true, enabled)
					if err != nil {
						t.Error(err)
						return
					}
					rung := decision.Rung
					if decision.NeedsScore {
						rung, err = store.Choose(ctx, "parallel", turn, 2, 3, time.Minute, true, enabled)
					}
					if err != nil || rung != want {
						t.Errorf("rung=%d err=%v want=%d", rung, err, want)
					}
				}(i)
			}
			wg.Wait()
			if got := client.HGet(ctx, "parallel", "escapes").Val(); got != fmt.Sprint(want) {
				t.Fatalf("escapes=%s want=%d", got, want)
			}
		})
	}
}

func TestSR1WarmReuseSkipsScorerAndResetsAfterIdle(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("escape=%t", enabled), func(t *testing.T) {
			mr, _, store := sr1Fixture(t)
			routes := modelRoutes("low", "mid", "high")
			cfg := tiersFor(routes, 0, .187, .45)
			cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 1, EscapeHatchEnabled: &enabled}
			scorer := &sr1TestScorer{score: 0}
			s := NewSmartRoutingWithSR1(routes, cfg, scorer, store, nil)
			req := promptReq()
			req.SessionID = "conversation"
			check := func(body, model string, calls int64) {
				t.Helper()
				req.Body = []byte(body)
				got := s.Next(context.Background(), req, nil)
				if got == nil || got.Model != model || scorer.calls.Load() != calls {
					t.Fatalf("body=%s route=%v calls=%d want=%s/%d", body, got, scorer.calls.Load(), model, calls)
				}
			}
			check(`{"prompt":"hi"}`, "low", 1)
			scorer.score = 1
			check(`{"prompt":"hi"}`, "low", 1)
			check(`{"input":[{"type":"function_call_output","call_id":"a","output":"result"}]}`, "low", 1)
			model, calls := "low", int64(1)
			if enabled {
				model, calls = "mid", 2
			}
			prefill := `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"OK"},{"role":"user","content":"hard"},{"role":"assistant","content":"Here is"}]}`
			check(prefill, model, calls)
			check(prefill, model, calls)
			scorer.err = errors.New("worker unavailable")
			check(`{"prompt":"harder again"}`, model, calls)
			check(`invalid JSON`, model, calls)
			mr.SetTime(time.Unix(1800000001, 0))
			check(`{"prompt":"at exact TTL"}`, model, calls)
			mr.SetTime(time.Unix(1800000002, 0).Add(time.Millisecond))
			scorer.err = nil
			check(`{"prompt":"after idle expiry"}`, "high", calls+1)
			check(`{"prompt":"strongest is already committed"}`, "high", calls+1)
		})
	}
}

func TestSR1EligibleScorerFailurePreservesFloorAndEscape(t *testing.T) {
	_, client, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	enabled := true
	cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60, EscapeHatchEnabled: &enabled}
	scorer := &sr1TestScorer{score: .25}
	s := NewSmartRoutingWithSR1(routes, cfg, scorer, store, nil)
	req := promptReq()
	req.SessionID = "conversation"
	ctx := context.Background()
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "mid" {
		t.Fatalf("seed=%v", got)
	}
	key, err := s.sr1Key(req)
	if err != nil {
		t.Fatal(err)
	}
	scorer.err = errors.New("worker unavailable")
	req.Body = []byte(`{"prompt":"new harder turn"}`)
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
		t.Fatalf("failure fallback=%v", got)
	}
	if got := s.Next(ctx, req, excludeRoutes(routes[1], routes[2])); got != nil {
		t.Fatalf("failure downgraded below readable commitment=%v", got)
	}
	if scorer.calls.Load() != 3 || client.HGet(ctx, key, "rung").Val() != "1" || client.HGet(ctx, key, "escapes").Val() != "0" {
		t.Fatal("eligible failures skipped scoring, changed commitment or consumed escape")
	}
	scorer.err, scorer.score = nil, 1
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
		t.Fatalf("unspent escape after recovery=%v", got)
	}
	if scorer.calls.Load() != 4 || client.HGet(ctx, key, "escapes").Val() != "1" {
		t.Fatal("recovery did not use exactly one previously unspent escape")
	}
}

func TestSR1StateScopeIncludesPreferenceAndCanonicalHistoricalFlag(t *testing.T) {
	routes := modelRoutes("low", "high")
	req := promptReq()
	req.SessionID = "conversation"
	key := func(flag *bool) string {
		t.Helper()
		cfg := tiersFor(routes, 0, .45)
		cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60, EscapeHatchEnabled: flag}
		s := NewSmartRoutingWithSR1(routes, cfg, nil, nil, nil)
		got, err := s.sr1Key(req)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	off, on := false, true
	if key(&off) == key(&on) {
		t.Fatal("different hatch preferences reused the same commitment")
	}
	if key(nil) != key(&on) {
		t.Fatal("historical enabled flag did not share its canonical state scope")
	}
}

func TestSR1RedisFailures(t *testing.T) {
	mr, client, store := sr1Fixture(t)
	ctx := context.Background()
	for _, fields := range []map[string]interface{}{
		{"rung": 0},
		{"rung": 0, "escapes": 0.5, "last": 1800000000000, "turn": "a"},
		{"rung": 3, "escapes": 0, "last": 1800000000000, "turn": "a"},
		{"rung": 0, "escapes": 0, "last": 1800000000001, "turn": "a"},
	} {
		if err := client.Del(ctx, "bad").Err(); err != nil {
			t.Fatal(err)
		}
		if err := client.HSet(ctx, "bad", fields).Err(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Choose(ctx, "bad", "b", 2, 3, time.Second, true, true); err == nil {
			t.Fatal("corrupt state accepted")
		}
	}
	mr.Close()
	if _, err := store.Choose(ctx, "outage", "a", 0, 3, time.Second, true, true); err == nil {
		t.Fatal("outage accepted")
	}
}

func TestSR1ColdCuts(t *testing.T) {
	for _, n := range []int{2, 3} {
		routes := modelRoutes("low", "mid", "high")[:n]
		cuts := []float64{0, .45}
		if n == 3 {
			cuts = []float64{0, .187, .45}
		}
		for _, score := range []float64{0, .186999, .187, .3037, .449999, .45, 1} {
			cfg := tiersFor(routes, cuts...)
			cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60}
			want := 0
			for i, cut := range cuts {
				if score >= cut {
					want = i
				}
			}
			s := NewSmartRoutingWithSR1(routes, cfg, &sr1TestScorer{score: score}, nil, nil)
			req := promptReq()
			req.SessionID = ""
			got := s.Next(context.Background(), req, nil)
			if got == nil || got.Model != routes[want].Model {
				t.Fatalf("n=%d score=%g got=%v", n, score, got)
			}
		}
	}
}

func TestSR1FailurePreservesFloor(t *testing.T) {
	_, client, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60}
	scorer := &sr1TestScorer{score: 1}
	s := NewSmartRoutingWithSR1(routes, cfg, scorer, store, nil)
	req := promptReq()
	req.SessionID = "chat_1"
	ctx := context.Background()
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
		t.Fatalf("seed=%v", got)
	}
	scorer.err = errors.New("outage")
	if got := s.Next(ctx, req, excludeRoutes(routes[2])); got != nil {
		t.Fatalf("downgraded to %v", got)
	}
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
		t.Fatalf("healthy strongest=%v", got)
	}
	key, err := s.sr1Key(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.HGet(ctx, key, "escapes").Val(); got != "0" {
		t.Fatalf("failure spent escape=%s", got)
	}
	req.SessionID = "fresh"
	if got := s.Next(ctx, req, excludeRoutes(routes[2])); got == nil || got.Model != "mid" {
		t.Fatalf("cold failure=%v", got)
	}
	scorer.err = nil
	scorer.score = math.NaN()
	req.SessionID = "nan"
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
		t.Fatalf("NaN fallback=%v", got)
	}
}

func TestSR1PrefillAndToolTurnIdentity(t *testing.T) {
	_, _, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60}
	scorer := &sr1TestScorer{score: 0}
	s := NewSmartRoutingWithSR1(routes, cfg, scorer, store, nil)
	req := promptReq()
	req.SessionID = "chat_1"
	ctx := context.Background()
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "low" {
		t.Fatalf("seed=%v", got)
	}
	scorer.score = 1
	req.Body = []byte(`{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"OK"},{"role":"user","content":"hard"},{"role":"assistant","content":"Here is"}]}`)
	for i := 0; i < 2; i++ {
		if got := s.Next(ctx, req, nil); got == nil || got.Model != "mid" {
			t.Fatalf("prefill/retry=%v", got)
		}
	}
	for _, body := range []string{
		`{"messages":[{"role":"user","content":"hard"},{"role":"assistant","content":[{"type":"tool_use","id":"a"}]}]}`,
		`{"messages":[{"role":"user","content":"hard"},{"role":"assistant","tool_calls":[{"id":"a"}]},{"role":"tool","content":"result"}]}`,
		`{"messages":[{"role":"user","content":"hard"},{"role":"user","content":[{"type":"tool_result","content":"result"}]}]}`,
		`{"input":[{"type":"function_call_output","call_id":"a","output":"result"}]}`,
	} {
		_, _, newUser, err := sr1Input([]byte(body))
		if err != nil || newUser {
			t.Fatalf("continuation newUser=%v err=%v", newUser, err)
		}
	}
}

var _ SR1Scorer = (*sr1TestScorer)(nil)
