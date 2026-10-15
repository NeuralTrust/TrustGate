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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestLegacySR1RetainsEveryColdThreshold(t *testing.T) {
	for _, n := range []int{4, 5} {
		_, client, store := sr1Fixture(t)
		routes := modelRoutes("low", "middle", "upper", "high", "highest")[:n]
		cuts := []float64{.12, .34, .55, .72, .97}[:n]
		cfg := tiersFor(routes, cuts...)
		cfg.LegacyThresholds = true
		scorer := &sr1TestScorer{}
		s := NewSmartRouting(routes, cfg, scorer, store, nil)
		for i, cut := range cuts {
			for _, score := range []float64{math.Nextafter(cut, 0), cut, math.Nextafter(cut, 1)} {
				scorer.score = score
				req := promptReq()
				req.SessionID = fmt.Sprintf("n%d/cut%d/%g", n, i, score)
				want := i
				if score < cut && i > 0 {
					want--
				}
				got := s.Next(context.Background(), req, nil)
				if got == nil || got.Model != routes[want].Model {
					t.Fatalf("n=%d score=%g route=%v want=%s", n, score, got, routes[want].Model)
				}
				key, err := s.sr1Key(req)
				if err != nil || client.HGet(context.Background(), key, "rung").Val() != fmt.Sprint(want) {
					t.Fatalf("cold rung was not committed: %v", err)
				}
			}
		}
	}
}

func TestLegacySR1SessionBoundsBothPreferences(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			_, client, store := sr1Fixture(t)
			routes := modelRoutes("low", "middle", "upper", "high")
			cfg := tiersFor(routes, .12, .34, .72, .97)
			cfg.LegacyThresholds = true
			cfg.SR1 = &registry.SR1Config{CacheTTLSeconds: 300, EscapeHatchEnabled: enabled}
			scorer := &sr1TestScorer{score: .12}
			s := NewSmartRouting(routes, cfg, scorer, store, nil)
			req := promptReq()
			req.SessionID = "legacy"
			ctx := context.Background()
			if got := s.Next(ctx, req, nil); got == nil || got.Model != "low" {
				t.Fatalf("cold=%v", got)
			}
			scorer.score = 1
			if got := s.Next(ctx, req, nil); got == nil || got.Model != "low" || scorer.calls.Load() != 1 {
				t.Fatal("duplicate turn was rescored or escaped")
			}
			req.Body = []byte(`{"prompt":"new high turn"}`)
			want := "low"
			escapes := "0"
			if enabled {
				want, escapes = "middle", "1"
			}
			if got := s.Next(ctx, req, nil); got == nil || got.Model != want {
				t.Fatalf("warm=%v want=%s", got, want)
			}
			req.Body = []byte(`{"prompt":"another high turn"}`)
			if got := s.Next(ctx, req, nil); got == nil || got.Model != want {
				t.Fatal("warm session escaped twice")
			}
			key, err := s.sr1Key(req)
			if err != nil || client.HGet(ctx, key, "escapes").Val() != escapes {
				t.Fatalf("escape accounting changed: %v", err)
			}
			req.SessionID = "highest"
			if got := s.Next(ctx, req, nil); got == nil || got.Model != "high" {
				t.Fatalf("highest cold=%v", got)
			}
			req.Body = []byte(`{"prompt":"new highest turn"}`)
			if got := s.Next(ctx, req, excludeRoutes(routes[3])); got != nil {
				t.Fatalf("highest commitment downgraded to %v", got)
			}
			key, err = s.sr1Key(req)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.sr1Fallback(ctx, req, routes[:3], key, -1, "scorer unavailable"); got != nil {
				t.Fatalf("readable highest floor was downgraded during failure: %v", got)
			}
			req.SessionID = "upper-failure"
			scorer.score = .72
			if got := s.Next(ctx, req, nil); got == nil || got.Model != "upper" {
				t.Fatalf("upper cold=%v", got)
			}
			scorer.err, req.Body = errors.New("scorer unavailable"), []byte(`{"prompt":"failed harder turn"}`)
			if got := s.Next(ctx, req, excludeRoutes(routes[2], routes[3])); got != nil {
				t.Fatalf("upper commitment downgraded during failure: %v", got)
			}
		})
	}
}
