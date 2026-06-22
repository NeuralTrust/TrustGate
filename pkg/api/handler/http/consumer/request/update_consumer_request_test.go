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

package request

import (
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

func strPtr(v string) *string { return &v }

func TestUpdateConsumerRequest_ToType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   *string
		want *domain.Type
	}{
		{"omitted", nil, nil},
		{"empty", strPtr(""), nil},
		{"whitespace", strPtr("   "), nil},
		{"value", strPtr("MCP"), func() *domain.Type { v := domain.Type("MCP"); return &v }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UpdateConsumerRequest{Type: tc.in}.ToType()
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ToType() nilness mismatch: got=%v want=%v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("ToType() = %q, want %q", *got, *tc.want)
			}
		})
	}
}

func TestUpdateConsumerRequest_ToRoutingMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   *string
		want *domain.RoutingMode
	}{
		{"omitted", nil, nil},
		{"empty", strPtr(""), nil},
		{"whitespace", strPtr("   "), nil},
		{"value", strPtr("role_based"), func() *domain.RoutingMode { v := domain.RoutingModeRoleBased; return &v }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UpdateConsumerRequest{RoutingMode: tc.in}.ToRoutingMode()
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ToRoutingMode() nilness mismatch: got=%v want=%v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("ToRoutingMode() = %q, want %q", *got, *tc.want)
			}
		})
	}
}
