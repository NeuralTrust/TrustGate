package strategies

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/google/uuid"
)

func makeBackends(names ...string) []*backend.Backend {
	out := make([]*backend.Backend, len(names))
	for i, name := range names {
		out[i] = &backend.Backend{ID: uuid.New(), Name: name, Weight: 1, Provider: "openai"}
	}
	return out
}

func TestRoundRobin_RotatesThroughBackends(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(makeBackends("a", "b", "c"))
	got := []string{}
	for i := 0; i < 6; i++ {
		got = append(got, rr.Next(nil).Name)
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

func TestRandom_PicksOneOfTheBackends(t *testing.T) {
	t.Parallel()
	r := NewRandom(makeBackends("a", "b", "c"))
	seen := map[string]bool{}
	for i := 0; i < 30; i++ {
		b := r.Next(nil)
		if b == nil {
			break
		}
		seen[b.Name] = true
	}
	if len(seen) == 0 {
		t.Fatal("Random.Next never returned a backend")
	}
	for name := range seen {
		if name != "a" && name != "b" && name != "c" {
			t.Fatalf("Random returned unexpected backend %q", name)
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
	backends := []*backend.Backend{
		{ID: uuid.New(), Name: "heavy", Weight: 3, Provider: "openai"},
		{ID: uuid.New(), Name: "light", Weight: 1, Provider: "openai"},
	}
	wrr := NewWeightedRoundRobin(backends)
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		b := wrr.Next(nil)
		if b == nil {
			break
		}
		counts[b.Name]++
	}
	if counts["heavy"] <= counts["light"] {
		t.Fatalf("heavy=%d should outnumber light=%d", counts["heavy"], counts["light"])
	}
}

func TestWeightedRoundRobin_AllZeroWeightsEventuallyReturnsNil(t *testing.T) {
	t.Parallel()
	wrr := NewWeightedRoundRobin([]*backend.Backend{
		{ID: uuid.New(), Name: "a"},
		{ID: uuid.New(), Name: "b"},
	})
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
	lc := NewLeastConnections(makeBackends("a", "b", "c"))
	if lc.Name() != "least-connections" {
		t.Fatalf("Name() = %q", lc.Name())
	}
	got := []string{}
	for i := 0; i < 3; i++ {
		got = append(got, lc.Next(nil).Name)
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected a,b,c got %v", got)
	}
}

func TestSemantic_NoConfigReturnsFirstBackend(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeBackends("a", "b"), nil, nil)
	b := s.Next(nil)
	if b == nil || b.Name != "a" {
		t.Fatalf("expected first backend a, got %+v", b)
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

func TestSemantic_SingleBackend(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeBackends("only"), nil, nil)
	got := s.Next(nil)
	if got == nil || got.Name != "only" {
		t.Fatalf("expected 'only', got %+v", got)
	}
}
