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
		got = append(got, rr.Next(nil, nil).Name)
	}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: got %q, want %q (full sequence: %v)", i, got[i], want[i], got)
		}
	}
}

func TestRoundRobin_SkipsExcluded(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b", "c")
	rr := NewRoundRobin(backends)
	exclude := map[uuid.UUID]struct{}{backends[0].ID: {}, backends[1].ID: {}}
	for i := 0; i < 4; i++ {
		b := rr.Next(nil, exclude)
		if b == nil || b.Name != "c" {
			t.Fatalf("step %d: expected only non-excluded backend 'c', got %+v", i, b)
		}
	}
}

func TestRoundRobin_AllExcludedReturnsNil(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b")
	rr := NewRoundRobin(backends)
	exclude := map[uuid.UUID]struct{}{backends[0].ID: {}, backends[1].ID: {}}
	if rr.Next(nil, exclude) != nil {
		t.Fatal("expected nil when every backend is excluded")
	}
}

func TestWeightedRoundRobin_AllExcludedReturnsNil(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b")
	wrr := NewWeightedRoundRobin(backends)
	exclude := map[uuid.UUID]struct{}{backends[0].ID: {}, backends[1].ID: {}}
	if wrr.Next(nil, exclude) != nil {
		t.Fatal("expected nil when every weighted backend is excluded")
	}
}

func TestLeastConnections_SkipsExcluded(t *testing.T) {
	t.Parallel()
	backends := makeBackends("a", "b", "c")
	lc := NewLeastConnections(backends)
	exclude := map[uuid.UUID]struct{}{backends[0].ID: {}}
	b := lc.Next(nil, exclude)
	if b == nil || b.Name == "a" {
		t.Fatalf("expected a non-excluded backend, got %+v", b)
	}
}

func TestRoundRobin_EmptyReturnsNil(t *testing.T) {
	t.Parallel()
	rr := NewRoundRobin(nil)
	if rr.Next(nil, nil) != nil {
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
		b := r.Next(nil, nil)
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
	if NewRandom(nil).Next(nil, nil) != nil {
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
		b := wrr.Next(nil, nil)
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
		if wrr.Next(nil, nil) == nil {
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
		got = append(got, lc.Next(nil, nil).Name)
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("expected a,b,c got %v", got)
	}
}

func TestSemantic_NoConfigReturnsFirstBackend(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeBackends("a", "b"), nil, nil)
	b := s.Next(nil, nil)
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
	if NewSemantic(nil, nil, nil, nil).Next(nil, nil) != nil {
		t.Fatal("empty Semantic.Next must return nil")
	}
}

func TestSemantic_SingleBackend(t *testing.T) {
	t.Parallel()
	s := NewSemantic(nil, makeBackends("only"), nil, nil)
	got := s.Next(nil, nil)
	if got == nil || got.Name != "only" {
		t.Fatalf("expected 'only', got %+v", got)
	}
}
