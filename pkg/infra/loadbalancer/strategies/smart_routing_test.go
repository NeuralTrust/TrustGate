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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

type fakeScorer struct {
	score      float64
	err        error
	configured bool
	calls      int
}

func (f *fakeScorer) ScoreSR1(_ context.Context, _, _ string) (float64, error) {
	f.calls++
	return f.score, f.err
}

func (f *fakeScorer) Configured() bool { return f.configured }

func tiersFor(routes []routingdomain.Route, minScores ...float64) *registry.SmartRoutingConfig {
	cfg := &registry.SmartRoutingConfig{}
	for i, min := range minScores {
		if routes[i].Model == "" {
			routes[i].Model = routes[i].Registry.Name
		}
		cfg.Tiers = append(cfg.Tiers, registry.SmartRoutingTier{
			MinScore:   min,
			RegistryID: routes[i].RegistryID(),
			Model:      routes[i].Model,
		})
	}
	return cfg
}

func promptReq() *infracontext.RequestContext {
	return &infracontext.RequestContext{Body: []byte(`{"prompt":"hi"}`), GatewayID: "gw_1"}
}

func TestSmartRouting_Name(t *testing.T) {
	t.Parallel()
	if name := (&SmartRouting{}).Name(); name != "smart-routing" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestSmartRouting_MapsScoreToTier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		score float64
		want  string
	}{
		{"low", 0.1, "a"},
		{"mid", 0.25, "b"},
		{"high", 0.9, "c"},
		{"boundary", 0.187, "b"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			routes := makeRoutes("a", "b", "c")
			cfg := tiersFor(routes, 0.0, 0.4, 0.8)
			scorer := &fakeScorer{score: tc.score, configured: true}
			s := NewSmartRouting(routes, cfg, scorer, nil)
			got := s.Next(context.Background(), promptReq(), nil)
			if got == nil || routeName(t, got) != tc.want {
				t.Fatalf("score %g: got %+v, want %q", tc.score, got, tc.want)
			}
			if scorer.calls != 1 {
				t.Fatalf("expected exactly one score call, got %d", scorer.calls)
			}
		})
	}
}

func TestSmartRouting_MapsScoreToModelOnOneRegistry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		score float64
		want  string
	}{
		{"simple", 0.1, "gpt-4o-mini"},
		{"medium", 0.25, "gpt-4.1-mini"},
		{"complex", 0.9, "gpt-5"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			routes := modelRoutes("gpt-4o-mini", "gpt-4.1-mini", "gpt-5")
			cfg := tiersFor(routes, 0.0, 0.4, 0.8)
			scorer := &fakeScorer{score: tc.score, configured: true}
			s := NewSmartRouting(routes, cfg, scorer, nil)

			got := s.Next(context.Background(), promptReq(), nil)

			if got == nil {
				t.Fatalf("score %g: expected a route", tc.score)
				return
			}
			if got.Model != tc.want {
				t.Fatalf("score %g: model = %q, want %q", tc.score, got.Model, tc.want)
			}
			if scorer.calls != 1 {
				t.Fatalf("expected exactly one score call, got %d", scorer.calls)
			}
		})
	}
}

func TestSmartRouting_ExcludedStrongestModelExhaustsPolicy(t *testing.T) {
	t.Parallel()
	routes := modelRoutes("gpt-4o-mini", "gpt-5")
	cfg := tiersFor(routes, 0.0, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(routes, cfg, scorer, nil)

	got := s.Next(context.Background(), promptReq(), excludeRoutes(routes[1]))

	if got != nil {
		t.Fatalf("excluding the strongest mapped model must not downgrade, got %+v", got)
	}
}

func TestSmartRouting_ScoreBelowEveryThresholdUsesLowestTier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		score float64
		want  string
	}{
		{"below every threshold", 0.1, "c"},
		{"at the lowest threshold", 0, "c"},
		{"between thresholds", 0.18, "c"},
		{"middle tier", 0.3, "b"},
		{"highest tier", 0.95, "a"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			routes := makeRoutes("a", "b", "c")
			cfg := tiersFor(routes, 0.9, 0.7, 0.49)
			scorer := &fakeScorer{score: tc.score, configured: true}
			s := NewSmartRouting(routes, cfg, scorer, nil)
			req := promptReq()

			got := s.Next(context.Background(), req, nil)

			if got == nil || routeName(t, got) != tc.want {
				t.Fatalf("score %g: got %+v, want %q", tc.score, got, tc.want)
			}
			if scorer.calls != 1 {
				t.Fatalf("expected exactly one score call, got %d", scorer.calls)
			}
			if req.RoutingDecision == nil || !req.RoutingDecision.TierApplied {
				t.Fatalf("score %g: expected a tier-applied decision, got %+v", tc.score, req.RoutingDecision)
			}
		})
	}
}

func TestSmartRouting_LowestTierExcludedSelectsHigherRung(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	cfg := tiersFor(routes, 0.9, 0.7, 0.49)
	scorer := &fakeScorer{score: 0.1, configured: true}
	s := NewSmartRouting(routes, cfg, scorer, nil)
	req := promptReq()

	got := s.Next(context.Background(), req, excludeRoutes(routes[2]))

	if got == nil || routeName(t, got) != "b" {
		t.Fatalf("excluding the lowest tier must select the next higher rung, got %+v", got)
	}
	if req.RoutingDecision == nil || !req.RoutingDecision.TierApplied {
		t.Fatalf("a bounded higher-rung selection remains a tier decision, got %+v", req.RoutingDecision)
	}
}

func TestSmartRouting_NotConfiguredSelectsStrongest(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	cfg := tiersFor(routes, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: false}
	s := NewSmartRouting(routes, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), nil)
	if got == nil || routeName(t, got) != "c" {
		t.Fatalf("failure should select the strongest declared route, got %+v", got)
	}
	if scorer.calls != 0 {
		t.Fatalf("scorer must not be called when unconfigured, calls=%d", scorer.calls)
	}
}

func TestSmartRouting_ScoreErrorSelectsStrongest(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	cfg := tiersFor(routes, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{err: errors.New("boom"), configured: true}
	s := NewSmartRouting(routes, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), nil)
	if got == nil || routeName(t, got) != "c" {
		t.Fatalf("failure should select the strongest declared route, got %+v", got)
	}
}

func TestSmartRouting_EmptyBodySelectsStrongest(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	cfg := tiersFor(routes, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(routes, cfg, scorer, nil)
	got := s.Next(context.Background(), &infracontext.RequestContext{}, nil)
	if got == nil || routeName(t, got) != "c" {
		t.Fatalf("failure should select the strongest declared route, got %+v", got)
	}
	if scorer.calls != 0 {
		t.Fatalf("scorer must not be called when input cannot be extracted, calls=%d", scorer.calls)
	}
}

func TestSmartRouting_MappedStrongestRegistryExcludedExhaustsPolicy(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b", "c")
	cfg := tiersFor(routes, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(routes, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), excludeRoutes(routes[2]))
	if got != nil {
		t.Fatalf("excluded strongest registry must not downgrade, got %+v", got)
	}
}

func TestSmartRouting_UnsupportedSingleRungSkipsScorer(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("only")
	cfg := tiersFor(routes, 0.0)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(routes, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), nil)
	if got != nil {
		t.Fatalf("unsupported one-rung ladder must return no route, got %+v", got)
	}
	if scorer.calls != 0 {
		t.Fatalf("scorer must not be called with a single candidate, calls=%d", scorer.calls)
	}
}

func TestSmartRouting_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	s := NewSmartRouting(nil, nil, nil, nil)
	if s.Next(context.Background(), promptReq(), nil) != nil {
		t.Fatal("empty SmartRouting.Next must return nil")
	}
}

func TestSmartRouting_RecordsRoutingDecision(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		routes      []routingdomain.Route
		scorer      *fakeScorer
		req         *infracontext.RequestContext
		wantApplied bool
	}{
		{
			name:        "tier decision",
			routes:      makeRoutes("a", "b", "c"),
			scorer:      &fakeScorer{score: 0.9, configured: true},
			wantApplied: true,
		},
		{
			name:   "scorer unconfigured",
			routes: makeRoutes("a", "b", "c"),
			scorer: &fakeScorer{score: 0.9, configured: false},
		},
		{
			name:   "score unavailable",
			routes: makeRoutes("a", "b", "c"),
			scorer: &fakeScorer{err: errors.New("boom"), configured: true},
		},
		{
			name:   "input not extractable",
			routes: makeRoutes("a", "b", "c"),
			scorer: &fakeScorer{score: 0.9, configured: true},
			req:    &infracontext.RequestContext{},
		},
		{
			name:        "score below every threshold still lands on a tier",
			routes:      makeRoutes("a", "b", "c"),
			scorer:      &fakeScorer{score: 0.9, configured: true},
			wantApplied: true,
		},
		{
			name:   "single candidate is forced, not chosen",
			routes: makeRoutes("only"),
			scorer: &fakeScorer{score: 0.9, configured: true},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := tiersFor(tc.routes, thresholdsFor(len(tc.routes))...)
			if tc.name == "score below every threshold still lands on a tier" {
				cfg = tiersFor(tc.routes, 0.95, 0.96, 0.97)
			}
			req := tc.req
			if req == nil {
				req = promptReq()
			}
			s := NewSmartRouting(tc.routes, cfg, tc.scorer, nil)

			if got := s.Next(context.Background(), req, nil); got == nil {
				t.Fatal("expected a route")
			}

			decision := req.RoutingDecision
			if decision == nil {
				t.Fatal("expected a routing decision to be recorded")
			}
			if decision.TierApplied != tc.wantApplied {
				t.Fatalf("tier applied = %v, want %v", decision.TierApplied, tc.wantApplied)
			}
		})
	}
}

func TestSmartRouting_NilRequestRoutesWithoutPanicking(t *testing.T) {
	t.Parallel()
	routes := makeRoutes("a", "b")
	s := NewSmartRouting(routes, tiersFor(routes, 0.0, 0.5), &fakeScorer{configured: true}, nil)
	if got := s.Next(context.Background(), nil, nil); got == nil {
		t.Fatal("a nil request must still route, not panic")
	}
}

func thresholdsFor(n int) []float64 {
	out := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, float64(i)*0.4)
	}
	return out
}
