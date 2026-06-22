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

package tool_call_validation

import (
	"context"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestNotInAllowedListValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		allowed   map[string]struct{}
		toolName  string
		wantMatch bool
	}{
		{
			name:      "tool in allowed set passes",
			allowed:   map[string]struct{}{"send_email": {}},
			toolName:  "send_email",
			wantMatch: false,
		},
		{
			name:      "tool not in allowed set is blocked",
			allowed:   map[string]struct{}{"send_email": {}},
			toolName:  "delete_db",
			wantMatch: true,
		},
		{
			name:      "empty allowed set passes through",
			allowed:   map[string]struct{}{},
			toolName:  "anything",
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := notInAllowedListValidator{}.Evaluate(validatorInput{
				ctx:      context.Background(),
				toolCall: adapter.CanonicalToolCall{Name: tc.toolName},
				eval:     &evalContext{allowed: tc.allowed},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.matched != tc.wantMatch {
				t.Fatalf("matched = %v, want %v", res.matched, tc.wantMatch)
			}
			if tc.wantMatch {
				if res.rejectType != typeToolNotInList {
					t.Fatalf("rejectType = %q, want %q", res.rejectType, typeToolNotInList)
				}
				if res.status != http.StatusForbidden {
					t.Fatalf("status = %d, want %d", res.status, http.StatusForbidden)
				}
			}
		})
	}
}
