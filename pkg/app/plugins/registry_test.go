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

package plugins

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stagePlugin struct {
	name      string
	mandatory []policy.Stage
	supported []policy.Stage
}

func (s *stagePlugin) Name() string                                        { return s.name }
func (s *stagePlugin) MandatoryStages() []policy.Stage                     { return s.mandatory }
func (s *stagePlugin) SupportedStages() []policy.Stage                     { return s.supported }
func (s *stagePlugin) SupportedModes() []policy.Mode                       { return []policy.Mode{policy.ModeEnforce} }
func (s *stagePlugin) ValidateConfig(map[string]any) error                 { return nil }
func (s *stagePlugin) Execute(context.Context, ExecInput) (*Result, error) { return nil, nil }
func (s *stagePlugin) MutatesRequestBody() bool                            { return false }
func (s *stagePlugin) MutatesResponseBody() bool                           { return false }
func (s *stagePlugin) MutatesMetadata() bool                               { return false }

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

func TestRegistry_Register_RejectsMandatoryOutsideSupported(t *testing.T) {
	reg := NewRegistry()
	err := reg.Register(&stagePlugin{
		name:      "weird",
		mandatory: []policy.Stage{policy.StagePostResponse},
		supported: []policy.Stage{policy.StagePreRequest},
	})
	require.ErrorIs(t, err, ErrInvalidStages)
}

func TestRegistry_ValidateStages(t *testing.T) {
	reg := NewRegistry()
	require.NoError(t, reg.Register(&stagePlugin{
		name:      "flex",
		mandatory: nil,
		supported: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
	}))
	require.NoError(t, reg.Register(&stagePlugin{
		name:      "mandatoryonly",
		mandatory: []policy.Stage{policy.StagePreRequest},
		supported: []policy.Stage{policy.StagePreRequest},
	}))

	// Case A: no selection and no mandatory stages -> empty effective set.
	require.ErrorIs(t, reg.ValidateStages("flex", nil), ErrNoEffectiveStages)
	// Valid selection within supported.
	require.NoError(t, reg.ValidateStages("flex", []policy.Stage{policy.StagePreRequest}))
	// Case B: selecting an unsupported stage is rejected.
	require.ErrorIs(t, reg.ValidateStages("mandatoryonly", []policy.Stage{policy.StagePostResponse}), ErrStageNotSupported)
	// Case C: mandatory stages make an empty selection valid.
	require.NoError(t, reg.ValidateStages("mandatoryonly", nil))
	// Unknown plugin.
	require.ErrorIs(t, reg.ValidateStages("missing", nil), ErrUnknownPlugin)
}
