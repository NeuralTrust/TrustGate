package strategies

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
)

func makeTargets(ids ...string) []backend.Target {
	out := make([]backend.Target, len(ids))
	for i, id := range ids {
		out[i] = backend.Target{ID: id, Weight: 1, Provider: "openai"}
	}
	return out
}

func TestRoundRobin_RotatesThroughTargets(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(makeTargets("a", "b", "c"))
	got := []string{}
	for i := 0; i < 6; i++ {
		got = append(got, rr.Next(nil).ID)
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: got %q, want %q (full sequence: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRoundRobin_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(nil)
	if rr.Next(nil) != nil {
		t.Fatal("Next on empty must return nil")
	}
}

func TestRoundRobin_Name(t *testing.T) {
	t.Parallel()
	if name := (&RoundRobin{}).Name(); name != "round-robin" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestRandom_PicksOneOfTheTargets(t *testing.T) {
	t.Parallel()
	r := NewRandom(makeTargets("a", "b", "c"))
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		t := r.Next(nil)
		if t == nil {
			break
		}
		seen[t.ID] = true
	}
	if len(seen) == 0 {
		t.Fatal("Random.Next never returned a target")
	}
	for id := range seen {
		if id != "a" && id != "b" && id != "c" {
			t.Fatalf("Random returned unexpected target id %q", id)
		}
	}
}

func TestRandom_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	if NewRandom(nil).Next(nil) != nil {
		t.Fatal("Random on empty must return nil")
	}
}

func TestRandom_Name(t *testing.T) {
	t.Parallel()
	if name := (&Random{}).Name(); name != "random" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestWeightedRoundRobin_RespectsWeights(t *testing.T) {
	t.Parallel()
	targets := []backend.Target{
		{ID: "heavy", Weight: 3, Provider: "openai"},
		{ID: "light", Weight: 1, Provider: "openai"},
	}
	wrr := NewWeightedRoundRobin(targets)
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		t := wrr.Next(nil)
		if t == nil {
			break
		}
		counts[t.ID]++
	}
	if counts["heavy"] <= counts["light"] {
		t.Fatalf("heavy=%d should outnumber light=%d", counts["heavy"], counts["light"])
	}
}

func TestWeightedRoundRobin_AllZeroWeightsEventuallyReturnsNil(t *testing.T) {
	t.Parallel()
	wrr := NewWeightedRoundRobin([]backend.Target{{ID: "a"}, {ID: "b"}})
	sawNil := false
	for i := 0; i < 10 && !sawNil; i++ {
		if wrr.Next(nil) == nil {
			sawNil = true
		}
	}
	if !sawNil {
		t.Fatal("WRR with zero weights must eventually return nil")
	}
}

func TestWeightedRoundRobin_Name(t *testing.T) {
	t.Parallel()
	if name := (&WeightedRoundRobin{}).Name(); name != "weighted-round-robin" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestLeastConnections_NameAndRotation(t *testing.T) {
	t.Parallel()
	lc := NewLeastConnections(makeTargets("a", "b", "c"))
	if lc.Name() != "least-connections" {
		t.Fatalf("Name() = %q", lc.Name())
	}
	got := []string{}
	for i := 0; i < 3; i++ {
		got = append(got, lc.Next(nil).ID)
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected a,b,c got %v", got)
	}
}

func TestSemantic_NoConfigReturnsFirstTarget(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeTargets("a", "b"), nil, nil)
	t1 := s.Next(nil)
	if t1 == nil || t1.ID != "a" {
		t.Fatalf("expected first target a, got %+v", t1)
	}
}

func TestSemantic_Name(t *testing.T) {
	t.Parallel()
	if name := (&Semantic{}).Name(); name != "semantic" {
		t.Fatalf("Name() = %q", name)
	}
}

func TestSemantic_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	if NewSemantic(nil, nil, nil, nil).Next(nil) != nil {
		t.Fatal("empty Semantic.Next must return nil")
	}
}

func TestSemantic_SingleTarget(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeTargets("only"), nil, nil)
	got := s.Next(nil)
	if got == nil || got.ID != "only" {
		t.Fatalf("expected 'only', got %+v", got)
	}
}
