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
		{name: "smart-routing", in: SmartRouting, want: true},
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
	if len(names) != 6 {
		t.Fatalf("len(Names()) = %d, want 6", len(names))
	}
	for _, n := range names {
		if !IsValid(n) {
			t.Fatalf("Names() returned invalid value %q", n)
		}
	}
}
