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
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type sr1TestScorer struct {
	score float64
	err   error
}

func (s *sr1TestScorer) Configured() bool { return true }
func (s *sr1TestScorer) Score(context.Context, string, string, string) (float64, error) {
	return s.score, s.err
}
func (s *sr1TestScorer) ScoreSR1(context.Context, string, string) (float64, error) {
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
		got, err := store.Choose(ctx, key, turn, desired, 3, ttl, newUser)
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
	if _, err := store.Choose(ctx, "parallel", "seed", 0, 3, time.Minute, true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rung, err := store.Choose(ctx, "parallel", fmt.Sprint(i), 2, 3, time.Minute, true)
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
		if _, err := store.Choose(ctx, "bad", "b", 2, 3, time.Second, true); err == nil {
			t.Fatal("corrupt state accepted")
		}
	}
	mr.Close()
	if _, err := store.Choose(ctx, "outage", "a", 0, 3, time.Second, true); err == nil {
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
