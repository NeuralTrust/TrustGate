package algorithm

import "testing"

func TestIsValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "round-robin", in: RoundRobin, want: true},
		{name: "random", in: Random, want: true},
		{name: "weighted-round-robin", in: WeightedRoundRobin, want: true},
		{name: "least-connections", in: LeastConnections, want: true},
		{name: "semantic", in: Semantic, want: true},
		{name: "empty", in: "", want: false},
		{name: "unknown", in: "foo", want: false},
		{name: "least-conn no s", in: "least-conn", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsValid(tc.in); got != tc.want {
				t.Fatalf("IsValid(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestNames(t *testing.T) {
	t.Parallel()
	names := Names()
	if len(names) != 5 {
		t.Fatalf("len(Names()) = %d, want 5", len(names))
	}
	for _, n := range names {
		if !IsValid(n) {
			t.Fatalf("Names() returned invalid value %q", n)
		}
	}
}
