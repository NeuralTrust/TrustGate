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

package loadbalancer

import "testing"

func TestParseHealthy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		val  any
		want bool
	}{
		{name: "missing key (nil)", val: nil, want: true},
		{name: "non-string value", val: 42, want: true},
		{name: "malformed json", val: "not-json", want: true},
		{name: "healthy status", val: `{"healthy":true}`, want: true},
		{name: "unhealthy status", val: `{"healthy":false}`, want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseHealthy(tc.val); got != tc.want {
				t.Fatalf("parseHealthy(%v) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestIsHealthy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		health  map[string]bool
		backend string
		want    bool
	}{
		{name: "nil map fails open", health: nil, backend: "a", want: true},
		{name: "unknown backend fails open", health: map[string]bool{"a": false}, backend: "b", want: true},
		{name: "healthy backend", health: map[string]bool{"a": true}, backend: "a", want: true},
		{name: "unhealthy backend", health: map[string]bool{"a": false}, backend: "a", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isHealthy(tc.health, tc.backend); got != tc.want {
				t.Fatalf("isHealthy(%v, %q) = %v, want %v", tc.health, tc.backend, got, tc.want)
			}
		})
	}
}
