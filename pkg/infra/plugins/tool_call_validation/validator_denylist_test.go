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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestDenylistValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		denylist  []string
		path      string
		arguments string
		wantMatch bool
		wantValue string
	}{
		{
			name:      "denied substring matches",
			denylist:  []string{"rm -rf", "DROP TABLE"},
			path:      "$.code",
			arguments: `{"code":"sudo rm -rf /"}`,
			wantMatch: true,
			wantValue: "rm -rf",
		},
		{
			name:      "clean value passes",
			denylist:  []string{"rm -rf"},
			path:      "$.code",
			arguments: `{"code":"ls -la"}`,
			wantMatch: false,
		},
		{
			name:      "missing path fails open",
			denylist:  []string{"rm -rf"},
			path:      "$.code",
			arguments: `{"command":"rm -rf /"}`,
			wantMatch: false,
		},
		{
			name:      "non-string value fails open",
			denylist:  []string{"1"},
			path:      "$.count",
			arguments: `{"count":1}`,
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := denylistValidator{}.Evaluate(context.Background(), validatorInput{
				toolCall: adapter.CanonicalToolCall{Name: "run_shell", Arguments: tc.arguments},
				rule:     RuleConfig{Validator: validatorDenylist, ArgumentPath: tc.path, Denylist: tc.denylist},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.matched != tc.wantMatch {
				t.Fatalf("matched = %v, want %v", res.matched, tc.wantMatch)
			}
			if tc.wantMatch && res.matchedValue != tc.wantValue {
				t.Fatalf("matchedValue = %q, want %q", res.matchedValue, tc.wantValue)
			}
		})
	}
}
