package plugins

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_Register(t *testing.T) {
	tests := []struct {
		name    string
		plugin  Plugin
		wantErr error
	}{
		{
			name:    "valid",
			plugin:  &fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}},
			wantErr: nil,
		},
		{
			name:    "empty name",
			plugin:  &fakePlugin{name: "", stages: []policy.Stage{policy.StagePreRequest}},
			wantErr: ErrUnknownPlugin,
		},
		{
			name:    "no stages",
			plugin:  &fakePlugin{name: "rate", stages: nil},
			wantErr: ErrInvalidStages,
		},
		{
			name:    "invalid stage",
			plugin:  &fakePlugin{name: "rate", stages: []policy.Stage{"weird"}},
			wantErr: ErrInvalidStages,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewRegistry()
			err := reg.Register(tt.plugin)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRegistry_RegisterDuplicate(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}}))
	err := reg.Register(&fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}})
	require.ErrorIs(t, err, ErrDuplicatePlugin)
}

func TestRegistry_GetAndNames(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&fakePlugin{name: "cors", stages: []policy.Stage{policy.StagePreRequest}}))
	require.NoError(t, reg.Register(&fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}}))

	_, ok := reg.Get("rate")
	assert.True(t, ok)
	_, ok = reg.Get("missing")
	assert.False(t, ok)
	assert.Equal(t, []string{"cors", "rate"}, reg.Names())
}

func TestRegistry_Validate(t *testing.T) {
	sentinel := errors.New("bad config")
	reg := NewRegistry()
	require.NoError(t, reg.Register(&fakePlugin{name: "rate", stages: []policy.Stage{policy.StagePreRequest}, validErr: sentinel}))

	require.ErrorIs(t, reg.Validate("rate", map[string]any{}), sentinel)
	require.ErrorIs(t, reg.Validate("missing", map[string]any{}), ErrUnknownPlugin)
}
