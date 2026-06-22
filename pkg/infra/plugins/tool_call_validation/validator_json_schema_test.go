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

func emailSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"to": map[string]any{"type": "string"},
		},
		"required": []any{"to"},
	}
}

func TestJSONSchemaValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		tool      adapter.CanonicalTool
		toolCall  adapter.CanonicalToolCall
		wantMatch bool
	}{
		{
			name:      "valid arguments pass",
			tool:      adapter.CanonicalTool{Name: "send_email", Schema: emailSchema()},
			toolCall:  adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"to":"a@b.com"}`},
			wantMatch: false,
		},
		{
			name:      "invalid arguments are rejected",
			tool:      adapter.CanonicalTool{Name: "send_email", Schema: emailSchema()},
			toolCall:  adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"subject":"hi"}`},
			wantMatch: true,
		},
		{
			name:      "tool without schema passes",
			tool:      adapter.CanonicalTool{Name: "send_email"},
			toolCall:  adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"to":123}`},
			wantMatch: false,
		},
		{
			name:      "unresolvable schema fails open",
			tool:      adapter.CanonicalTool{Name: "send_email", Schema: map[string]any{"$ref": "https://example.com/missing.json"}},
			toolCall:  adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"to":"a@b.com"}`},
			wantMatch: false,
		},
		{
			name:      "malformed arguments fail open",
			tool:      adapter.CanonicalTool{Name: "send_email", Schema: emailSchema()},
			toolCall:  adapter.CanonicalToolCall{Name: "send_email", Arguments: `{not json`},
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eval := &evalContext{toolByName: map[string]adapter.CanonicalTool{tc.tool.Name: tc.tool}}
			res, err := jsonSchemaValidator{}.Evaluate(validatorInput{
				ctx:      context.Background(),
				toolCall: tc.toolCall,
				eval:     eval,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.matched != tc.wantMatch {
				t.Fatalf("matched = %v, want %v", res.matched, tc.wantMatch)
			}
			if tc.wantMatch {
				if res.rejectType != typeToolSchemaInvalid {
					t.Fatalf("rejectType = %q, want %q", res.rejectType, typeToolSchemaInvalid)
				}
				if res.status != http.StatusForbidden {
					t.Fatalf("status = %d, want %d", res.status, http.StatusForbidden)
				}
			}
		})
	}
}
