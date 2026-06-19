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

package role

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestOIDCMapping_Matches(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"email":  "admin@example.com",
		"groups": []any{"gateway-admin", "billing"},
		"scp":    "mcp.access openid profile",
		"realm": map[string]any{
			"roles": []any{"writer", "reader"},
		},
	}
	tests := []struct {
		name    string
		mapping OIDCMapping
		want    bool
	}{
		{
			name:    "equals string",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "email", Op: OIDCClaimEquals, Values: []string{"admin@example.com"}}}},
			want:    true,
		},
		{
			name:    "contains any",
			mapping: OIDCMapping{Match: OIDCMatchAny, Claims: []OIDCClaimRule{{Path: "groups", Op: OIDCClaimContainsAny, Values: []string{"gateway-admin"}}}},
			want:    true,
		},
		{
			name:    "contains all dot path",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "realm.roles", Op: OIDCClaimContainsAll, Values: []string{"writer", "reader"}}}},
			want:    true,
		},
		{
			name:    "missing required all",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "groups", Op: OIDCClaimContainsAll, Values: []string{"gateway-admin", "ops"}}}},
			want:    false,
		},
		{
			name:    "space delimited scope contains any",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "scp", Op: OIDCClaimContainsAny, Values: []string{"mcp.access"}}}},
			want:    true,
		},
		{
			name:    "space delimited scope contains all",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "scp", Op: OIDCClaimContainsAll, Values: []string{"mcp.access", "openid"}}}},
			want:    true,
		},
		{
			name:    "space delimited scope missing",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "scp", Op: OIDCClaimContainsAny, Values: []string{"mcp.admin"}}}},
			want:    false,
		},
		{
			name:    "scope equals requires single scope",
			mapping: OIDCMapping{Match: OIDCMatchAll, Claims: []OIDCClaimRule{{Path: "scp", Op: OIDCClaimEquals, Values: []string{"mcp.access"}}}},
			want:    false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.mapping.Matches(claims); got != tt.want {
				t.Fatalf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseOIDCMapping_Validation(t *testing.T) {
	t.Parallel()
	if mapping, err := ParseOIDCMapping(nil); err != nil || mapping != nil {
		t.Fatalf("nil mapping = %v, %v; want nil, nil", mapping, err)
	}

	valid := json.RawMessage(`{"match":"any","claims":[{"path":"groups","op":"contains_any","values":["admin"]}]}`)
	if _, err := ParseOIDCMapping(valid); err != nil {
		t.Fatalf("valid mapping error: %v", err)
	}

	invalid := json.RawMessage(`{"match":"any","claims":[{"path":"groups","op":"unknown","values":["admin"]}]}`)
	if _, err := ParseOIDCMapping(invalid); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err = %v, want ErrInvalidJSON", err)
	}
}
