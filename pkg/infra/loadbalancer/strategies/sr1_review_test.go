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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestSR1ColdFailuresDoNotCommitAndRecoveryRescores(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		score float64
		err   error
		calls int64
	}{
		{name: "scorer outage", body: `{"prompt":"hi"}`, err: errors.New("worker unavailable"), calls: 1},
		{name: "revision mismatch", body: `{"prompt":"hi"}`, err: errors.New("unexpected model revision"), calls: 1},
		{name: "NaN", body: `{"prompt":"hi"}`, score: math.NaN(), calls: 1},
		{name: "infinity", body: `{"prompt":"hi"}`, score: math.Inf(1), calls: 1},
		{name: "negative score", body: `{"prompt":"hi"}`, score: -0.1, calls: 1},
		{name: "score above one", body: `{"prompt":"hi"}`, score: 1.1, calls: 1},
		{name: "invalid JSON", body: `invalid JSON`},
		{name: "OpenAI image only", body: `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com/image.png"}}]}]}`},
		{name: "Bedrock image only", body: `{"messages":[{"role":"user","content":[{"image":{"format":"png","source":{"bytes":"AA=="}}}]}]}`},
		{name: "Gemini image only", body: `{"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"AA=="}}]}]}`},
		{name: "Responses tool only", body: `{"input":[{"type":"function_call_output","call_id":"a","output":"result"}]}`},
		{name: "Gemini tool only", body: `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"result":"done"}}}]}]}`},
	}
	for _, enabled := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("escape=%t/%s", enabled, tc.name), func(t *testing.T) {
				_, client, store := sr1Fixture(t)
				routes := modelRoutes("low", "mid", "high")
				cfg := tiersFor(routes, 0, .187, .45)
				cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 60, EscapeHatchEnabled: enabled}
				scorer := &sr1TestScorer{score: tc.score, err: tc.err}
				s := NewSmartRouting(routes, cfg, scorer, store, nil)
				req := promptReq()
				req.SessionID, req.Body = "cold-failure", []byte(tc.body)
				ctx := context.Background()
				key, err := s.sr1Key(req)
				if err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
						t.Fatalf("failed cold route=%v", got)
					}
					if count, err := client.Exists(ctx, key).Result(); err != nil || count != 0 {
						t.Fatalf("failed cold request persisted state: exists=%d err=%v", count, err)
					}
				}
				if scorer.calls.Load() != 2*tc.calls {
					t.Fatalf("failed scorer calls=%d want=%d", scorer.calls.Load(), 2*tc.calls)
				}
				scorer.score, scorer.err, req.Body = 0, nil, []byte(`{"prompt":"recovered easy turn"}`)
				if got := s.Next(ctx, req, nil); got == nil || got.Model != "low" {
					t.Fatalf("recovered cold decision=%v", got)
				}
				if scorer.calls.Load() != 2*tc.calls+1 || client.HGet(ctx, key, "rung").Val() != "0" || client.HGet(ctx, key, "escapes").Val() != "0" {
					t.Fatal("recovery did not score and commit an easy turn without an escape")
				}
			})
		}
	}
}

func TestSR1UnconfiguredScorerDoesNotCommit(t *testing.T) {
	for _, scorer := range []ComplexityScorer{nil, &fakeScorer{configured: false}} {
		_, client, store := sr1Fixture(t)
		routes := modelRoutes("low", "high")
		cfg := tiersFor(routes, 0, .45)
		s := NewSmartRouting(routes, cfg, scorer, store, nil)
		req := promptReq()
		req.SessionID = "unconfigured"
		ctx := context.Background()
		if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
			t.Fatalf("unconfigured fallback=%v", got)
		}
		key, err := s.sr1Key(req)
		if err != nil {
			t.Fatal(err)
		}
		if client.Exists(ctx, key).Val() != 0 {
			t.Fatal("unconfigured scorer committed a rung")
		}
		recovered := NewSmartRouting(routes, cfg, &sr1TestScorer{score: 0}, store, nil)
		if got := recovered.Next(ctx, req, nil); got == nil || got.Model != "low" {
			t.Fatalf("scorer recovery=%v", got)
		}
	}
}

func TestSR1RedisReadNeverCreatesOrTouchesState(t *testing.T) {
	mr, client, store := sr1Fixture(t)
	ctx := context.Background()
	const key = "read-only"
	ttl := time.Second
	if got, err := store.Read(ctx, key, 3, ttl); err != nil || got != -1 {
		t.Fatalf("cold Read=%d,%v", got, err)
	}
	if client.Exists(ctx, key).Val() != 0 {
		t.Fatal("cold read created state")
	}
	if _, err := store.Choose(ctx, key, "seed", 1, 3, ttl, true, true); err != nil {
		t.Fatal(err)
	}
	before, err := client.HGetAll(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	beforeTTL, err := client.PTTL(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		elapsed time.Duration
		rung    int
	}{{time.Second, 1}, {time.Second + time.Millisecond, -1}} {
		mr.SetTime(time.Unix(1800000000, 0).Add(tc.elapsed))
		if got, err := store.Read(ctx, key, 3, ttl); err != nil || got != tc.rung {
			t.Fatalf("Read at %s=%d,%v want=%d", tc.elapsed, got, err, tc.rung)
		}
		after, err := client.HGetAll(ctx, key).Result()
		if err != nil {
			t.Fatal(err)
		}
		afterTTL, err := client.PTTL(ctx, key).Result()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) || beforeTTL != afterTTL {
			t.Fatalf("read mutated state or expiry: before=%v/%s after=%v/%s", before, beforeTTL, after, afterTTL)
		}
	}
}

func TestSR1ExpiredFailureDoesNotRewriteCommitment(t *testing.T) {
	mr, client, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	cfg.SR1.CacheTTLSeconds = 1
	scorer := &sr1TestScorer{score: .25}
	s := NewSmartRouting(routes, cfg, scorer, store, nil)
	req := promptReq()
	req.SessionID = "expired-failure"
	ctx := context.Background()
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "mid" {
		t.Fatalf("seed=%v", got)
	}
	key, err := s.sr1Key(req)
	if err != nil {
		t.Fatal(err)
	}
	before, err := client.HGetAll(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTime(time.Unix(1800000001, 0).Add(time.Millisecond))
	scorer.err = errors.New("temporary outage")
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
		t.Fatalf("expired failure=%v", got)
	}
	after, err := client.HGetAll(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("expired failure rewrote state: before=%v after=%v", before, after)
	}
	scorer.score, scorer.err = 0, nil
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "low" {
		t.Fatalf("expired recovery=%v", got)
	}
}

type sr1ReadFailureStore struct{ SR1Store }

func (s *sr1ReadFailureStore) Read(context.Context, string, int, time.Duration) (int, error) {
	return -1, errors.New("read unavailable")
}

func TestSR1FallbackRetainsProbedFloorWhenFreshReadFails(t *testing.T) {
	_, _, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	cfg.SR1.EscapeHatchEnabled = true
	scorer := &sr1TestScorer{score: .25}
	s := NewSmartRouting(routes, cfg, scorer, &sr1ReadFailureStore{SR1Store: store}, nil)
	req := promptReq()
	req.SessionID = "known-floor"
	ctx := context.Background()
	if got := s.Next(ctx, req, nil); got == nil || got.Model != "mid" {
		t.Fatalf("seed=%v", got)
	}
	scorer.err, req.Body = errors.New("scorer unavailable"), []byte(`{"prompt":"harder turn"}`)
	if got := s.Next(ctx, req, excludeRoutes(routes[1], routes[2])); got != nil {
		t.Fatalf("failed read downgraded below known commitment=%v", got)
	}
}

type sr1HookScorer struct{ onScore func() }

func (s *sr1HookScorer) Configured() bool { return true }
func (s *sr1HookScorer) ScoreSR1(context.Context, string, string) (float64, error) {
	s.onScore()
	return 0, errors.New("scorer unavailable")
}

func TestSR1FallbackReadsCommitmentCreatedDuringScoring(t *testing.T) {
	_, client, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	scorer := &sr1HookScorer{}
	s := NewSmartRouting(routes, cfg, scorer, store, nil)
	req := promptReq()
	req.SessionID = "concurrent-cold"
	ctx := context.Background()
	key, err := s.sr1Key(req)
	if err != nil {
		t.Fatal(err)
	}
	scorer.onScore = func() {
		if rung, err := store.Choose(ctx, key, "other-request", 2, 3, 300*time.Second, true, false); err != nil || rung != 2 {
			t.Fatalf("interleaved commitment=%d,%v", rung, err)
		}
	}
	if got := s.Next(ctx, req, excludeRoutes(routes[2])); got != nil {
		t.Fatalf("failure ignored commitment created while scoring=%v", got)
	}
	if client.HGet(ctx, key, "rung").Val() != "2" || client.HGet(ctx, key, "turn").Val() != "other-request" {
		t.Fatal("fallback changed the concurrent commitment")
	}
}

func TestSR1FallbackReadsEscapeSpentDuringScoring(t *testing.T) {
	_, client, store := sr1Fixture(t)
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	cfg.SR1.EscapeHatchEnabled = true
	req := promptReq()
	req.SessionID = "concurrent-warm"
	ctx := context.Background()
	seed := NewSmartRouting(routes, cfg, &sr1TestScorer{score: 0}, store, nil)
	if got := seed.Next(ctx, req, nil); got == nil || got.Model != "low" {
		t.Fatalf("seed=%v", got)
	}
	scorer := &sr1HookScorer{}
	s := NewSmartRouting(routes, cfg, scorer, store, nil)
	key, err := s.sr1Key(req)
	if err != nil {
		t.Fatal(err)
	}
	scorer.onScore = func() {
		if rung, err := store.Choose(ctx, key, "other-request", 2, 3, 300*time.Second, true, true); err != nil || rung != 1 {
			t.Fatalf("interleaved escape=%d,%v", rung, err)
		}
	}
	req.Body = []byte(`{"prompt":"harder turn"}`)
	if got := s.Next(ctx, req, excludeRoutes(routes[1], routes[2])); got != nil {
		t.Fatalf("failure ignored an escape spent while scoring=%v", got)
	}
	if client.HGet(ctx, key, "rung").Val() != "1" || client.HGet(ctx, key, "escapes").Val() != "1" || client.HGet(ctx, key, "turn").Val() != "other-request" {
		t.Fatal("fallback changed the concurrent escape")
	}
}

func TestSR1ConstructorCachesPolicyAndPreservesScopeBytes(t *testing.T) {
	routes := modelRoutes("low", "mid", "high")
	cfg := tiersFor(routes, 0, .187, .45)
	cfg.SR1.EscapeHatchEnabled = true
	s := NewSmartRouting(routes, cfg, &sr1TestScorer{score: 0}, nil, nil)
	req := promptReq()
	req.GatewayID, req.ConsumerID, req.SessionID = "<gateway>&", "consumer\"id", "session\\id"
	legacyScope, err := json.Marshal([]any{req.GatewayID, req.ConsumerID, req.SessionID, cfg})
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(legacyScope)
	want := "tg:sr1:" + hex.EncodeToString(wantHash[:])
	key, err := s.sr1Key(req)
	if err != nil || key != want {
		t.Fatalf("cached scope=%s,%v want=%s", key, err, want)
	}
	cfg.Tiers[0].Model, cfg.Tiers[0].MinScore = "mutated", .7
	cfg.SR1.CacheTTLSeconds, cfg.SR1.EscapeHatchEnabled = 1, false
	if key, err := s.sr1Key(req); err != nil || key != want {
		t.Fatalf("external mutation changed cached scope=%s,%v", key, err)
	}
	req.SessionID = ""
	if got := s.Next(context.Background(), req, nil); got == nil || got.Model != "low" {
		t.Fatalf("external mutation changed routing policy=%v", got)
	}
}
