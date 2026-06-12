package consumer

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestLBConfig_Validate(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	policies := ModelPolicies{
		registryID: {Allowed: []string{"gpt-4o"}},
	}
	tests := []struct {
		name   string
		config *LBConfig
	}{
		{
			name: "member outside policy",
			config: &LBConfig{
				Enabled: true,
				Members: []LBPoolMember{
					{RegistryID: ids.New[ids.RegistryKind](), Models: []string{"gpt-4o"}},
				},
			},
		},
		{
			name: "semantic without embedding",
			config: &LBConfig{
				Enabled:   true,
				Algorithm: "semantic",
				Members: []LBPoolMember{
					{RegistryID: registryID, Models: []string{"gpt-4o"}},
				},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate(policies)
			if !errors.Is(err, ErrInvalidLBConfig) {
				t.Fatalf("err = %v, want ErrInvalidLBConfig", err)
			}
		})
	}
}
