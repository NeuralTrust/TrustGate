package role

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestIDPMapping_Matches(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"email":  "admin@example.com",
		"groups": []any{"gateway-admin", "billing"},
		"realm": map[string]any{
			"roles": []any{"writer", "reader"},
		},
	}
	tests := []struct {
		name    string
		mapping IDPMapping
		want    bool
	}{
		{
			name:    "equals string",
			mapping: IDPMapping{Match: IDPMatchAll, Claims: []IDPClaimRule{{Path: "email", Op: IDPClaimEquals, Values: []string{"admin@example.com"}}}},
			want:    true,
		},
		{
			name:    "contains any",
			mapping: IDPMapping{Match: IDPMatchAny, Claims: []IDPClaimRule{{Path: "groups", Op: IDPClaimContainsAny, Values: []string{"gateway-admin"}}}},
			want:    true,
		},
		{
			name:    "contains all dot path",
			mapping: IDPMapping{Match: IDPMatchAll, Claims: []IDPClaimRule{{Path: "realm.roles", Op: IDPClaimContainsAll, Values: []string{"writer", "reader"}}}},
			want:    true,
		},
		{
			name:    "missing required all",
			mapping: IDPMapping{Match: IDPMatchAll, Claims: []IDPClaimRule{{Path: "groups", Op: IDPClaimContainsAll, Values: []string{"gateway-admin", "ops"}}}},
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

func TestParseIDPMapping_Validation(t *testing.T) {
	t.Parallel()
	if mapping, err := ParseIDPMapping(nil); err != nil || mapping != nil {
		t.Fatalf("nil mapping = %v, %v; want nil, nil", mapping, err)
	}

	valid := json.RawMessage(`{"match":"any","claims":[{"path":"groups","op":"contains_any","values":["admin"]}]}`)
	if _, err := ParseIDPMapping(valid); err != nil {
		t.Fatalf("valid mapping error: %v", err)
	}

	invalid := json.RawMessage(`{"match":"any","claims":[{"path":"groups","op":"unknown","values":["admin"]}]}`)
	if _, err := ParseIDPMapping(invalid); !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err = %v, want ErrInvalidJSON", err)
	}
}
