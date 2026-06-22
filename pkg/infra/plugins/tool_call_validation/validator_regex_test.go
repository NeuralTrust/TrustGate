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

func TestRegexValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		pattern   string
		path      string
		arguments string
		wantMatch bool
		wantValue string
	}{
		{
			name:      "matching value passes",
			pattern:   `^[\w.+-]+@(company\.com|partner\.com)$`,
			path:      "$.to",
			arguments: `{"to":"alice@company.com"}`,
			wantMatch: false,
		},
		{
			name:      "non-matching value violates",
			pattern:   `^[\w.+-]+@(company\.com|partner\.com)$`,
			path:      "$.to",
			arguments: `{"to":"attacker@evil.com"}`,
			wantMatch: true,
			wantValue: "attacker@evil.com",
		},
		{
			name:      "partial match still violates because full match required",
			pattern:   `alice`,
			path:      "$.to",
			arguments: `{"to":"alice@company.com"}`,
			wantMatch: true,
			wantValue: "alice@company.com",
		},
		{
			name:      "missing path fails open",
			pattern:   `.+`,
			path:      "$.to",
			arguments: `{"subject":"hi"}`,
			wantMatch: false,
		},
		{
			name:      "non-string value fails open",
			pattern:   `.+`,
			path:      "$.count",
			arguments: `{"count":3}`,
			wantMatch: false,
		},
		{
			name:      "unparsable arguments fail open",
			pattern:   `.+`,
			path:      "$.to",
			arguments: `{not json`,
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := regexValidator{}.Evaluate(validatorInput{
				ctx:      context.Background(),
				toolCall: adapter.CanonicalToolCall{Name: "send_email", Arguments: tc.arguments},
				rule:     RuleConfig{Validator: validatorRegex, ArgumentPath: tc.path, Pattern: tc.pattern},
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
			if tc.wantMatch && (res.rejectType != "" || res.status != 0) {
				t.Fatalf("validator must not set reject type/status, got %+v", res)
			}
		})
	}
}
