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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

type fakeScorer struct {
	score      float64
	err        error
	configured bool
	calls      int
}

func (f *fakeScorer) Score(_ context.Context, _, _, _ string) (float64, error) {
	f.calls++
	return f.score, f.err
}

func (f *fakeScorer) Configured() bool { return f.configured }

func tiersFor(backends []*registry.Registry, minScores ...float64) *registry.SmartRoutingConfig {
	cfg := &registry.SmartRoutingConfig{}
	for i, min := range minScores {
		cfg.Tiers = append(cfg.Tiers, registry.SmartRoutingTier{MinScore: min, RegistryID: backends[i].ID})
	}
	return cfg
}

func promptReq() *infracontext.RequestContext {
	return &infracontext.RequestContext{Body: []byte(`{"prompt":"hi"}`), SessionID: "chat_1", GatewayID: "gw_1"}
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
		{"mid", 0.5, "b"},
		{"high", 0.9, "c"},
		{"boundary", 0.4, "b"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			backends := makeBackends("a", "b", "c")
			cfg := tiersFor(backends, 0.0, 0.4, 0.8)
			scorer := &fakeScorer{score: tc.score, configured: true}
			s := NewSmartRouting(backends, cfg, scorer, nil)
			got := s.Next(context.Background(), promptReq(), nil)
			if got == nil || got.Name != tc.want {
				t.Fatalf("score %g: got %+v, want %q", tc.score, got, tc.want)
			}
			if scorer.calls != 1 {
				t.Fatalf("expected exactly one score call, got %d", scorer.calls)
			}
		})
	}
}

func TestSmartRouting_NotConfiguredFallsBackToRoundRobin(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b", "c")
	cfg := tiersFor(backends, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: false}
	s := NewSmartRouting(backends, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), nil)
	if got == nil || got.Name != "a" {
		t.Fatalf("unconfigured scorer should round-robin from first backend, got %+v", got)
	}
	if scorer.calls != 0 {
		t.Fatalf("scorer must not be called when unconfigured, calls=%d", scorer.calls)
	}
}

func TestSmartRouting_ScoreErrorFallsBackToRoundRobin(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b", "c")
	cfg := tiersFor(backends, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{err: errors.New("boom"), configured: true}
	s := NewSmartRouting(backends, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), nil)
	if got == nil || got.Name != "a" {
		t.Fatalf("score error should round-robin from first backend, got %+v", got)
	}
}

func TestSmartRouting_EmptyBodyFallsBackToRoundRobin(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b", "c")
	cfg := tiersFor(backends, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(backends, cfg, scorer, nil)
	got := s.Next(context.Background(), &infracontext.RequestContext{}, nil)
	if got == nil || got.Name != "a" {
		t.Fatalf("empty body should round-robin from first backend, got %+v", got)
	}
	if scorer.calls != 0 {
		t.Fatalf("scorer must not be called when input cannot be extracted, calls=%d", scorer.calls)
	}
}

func TestSmartRouting_MappedRegistryExcludedFallsBack(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b", "c")
	cfg := tiersFor(backends, 0.0, 0.4, 0.8)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(backends, cfg, scorer, nil)
	exclude := map[ids.RegistryID]struct{}{backends[2].ID: {}}
	got := s.Next(context.Background(), promptReq(), exclude)
	if got == nil || got.Name == "c" {
		t.Fatalf("excluded mapped registry must fall back to a candidate, got %+v", got)
	}
}

func TestSmartRouting_SingleCandidateSkipsScorer(t *testing.T) {
	t.Parallel()
	backends := makeBackends("only")
	cfg := tiersFor(backends, 0.0)
	scorer := &fakeScorer{score: 0.9, configured: true}
	s := NewSmartRouting(backends, cfg, scorer, nil)
	got := s.Next(context.Background(), promptReq(), nil)
	if got == nil || got.Name != "only" {
		t.Fatalf("single candidate should be returned without scoring, got %+v", got)
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
