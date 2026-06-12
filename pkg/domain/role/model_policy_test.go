package role

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestModelPolicies_Validate(t *testing.T) {
	t.Parallel()
	reg := ids.New[ids.RegistryKind]()
	known := map[ids.RegistryID]struct{}{reg: {}}

	tests := []struct {
		name     string
		policies ModelPolicies
		wantErr  bool
	}{
		{
			name:     "nil policies passthrough",
			policies: nil,
			wantErr:  false,
		},
		{
			name:     "nil allowed is passthrough",
			policies: ModelPolicies{reg: {}},
			wantErr:  false,
		},
		{
			name:     "explicit empty allowed is rejected",
			policies: ModelPolicies{reg: {Allowed: []string{}}},
			wantErr:  true,
		},
		{
			name:     "default in allowed is valid",
			policies: ModelPolicies{reg: {Allowed: []string{"gpt-4o"}, Default: "gpt-4o"}},
			wantErr:  false,
		},
		{
			name:     "default not in allowed",
			policies: ModelPolicies{reg: {Allowed: []string{"gpt-4o"}, Default: "claude-3"}},
			wantErr:  true,
		},
		{
			name:     "unknown registry",
			policies: ModelPolicies{ids.New[ids.RegistryKind](): {Allowed: []string{"gpt-4o"}}},
			wantErr:  true,
		},
		{
			name:     "duplicate model",
			policies: ModelPolicies{reg: {Allowed: []string{"gpt-4o", "gpt-4o"}}},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.policies.Validate(known)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, commonerrors.ErrValidation) {
					t.Fatalf("expected validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
