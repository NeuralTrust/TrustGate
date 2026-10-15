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

package policy_test

import (
	"errors"
	"testing"

	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newStatusPlugin(t *testing.T, supported, mandatory []domain.Stage) *pluginmocks.Plugin {
	t.Helper()
	p := pluginmocks.NewPlugin(t)
	p.EXPECT().SupportedStages().Return(supported).Maybe()
	p.EXPECT().MandatoryStages().Return(mandatory).Maybe()
	return p
}

func TestStatusEvaluator_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      domain.Policy
		setup       func(t *testing.T, r *pluginmocks.Registry)
		wantStatus  apppolicy.Status
		wantMessage string
	}{
		{
			name:   "enabled and valid is active",
			policy: domain.Policy{Slug: "rl", Enabled: true, Stages: []domain.Stage{domain.StagePreRequest}},
			setup: func(t *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("rl").Return(newStatusPlugin(t, []domain.Stage{domain.StagePreRequest}, nil), true)
				r.EXPECT().Validate("rl", mock.Anything).Return(nil)
			},
			wantStatus: apppolicy.StatusActive,
		},
		{
			name:       "disabled and unknown is paused without consulting the registry",
			policy:     domain.Policy{Slug: "gone", Enabled: false},
			setup:      func(*testing.T, *pluginmocks.Registry) {},
			wantStatus: apppolicy.StatusPaused,
		},
		{
			name:   "enabled with unknown slug is error",
			policy: domain.Policy{Slug: "gone", Enabled: true},
			setup: func(_ *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("gone").Return(nil, false)
			},
			wantStatus:  apppolicy.StatusError,
			wantMessage: "unknown plugin",
		},
		{
			name:   "enabled with invalid settings is error",
			policy: domain.Policy{Slug: "rl", Enabled: true, Stages: []domain.Stage{domain.StagePreRequest}},
			setup: func(t *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("rl").Return(newStatusPlugin(t, []domain.Stage{domain.StagePreRequest}, nil), true)
				r.EXPECT().Validate("rl", mock.Anything).Return(errors.New("limit must be positive"))
			},
			wantStatus:  apppolicy.StatusError,
			wantMessage: "limit must be positive",
		},
		{
			name:   "enabled with no effective stage is error",
			policy: domain.Policy{Slug: "rl", Enabled: true, Stages: []domain.Stage{domain.StagePostResponse}},
			setup: func(t *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("rl").Return(newStatusPlugin(t, []domain.Stage{domain.StagePreRequest}, nil), true)
			},
			wantStatus:  apppolicy.StatusError,
			wantMessage: "no effective stages",
		},
		{
			name:   "partially supported stages still run so it is active",
			policy: domain.Policy{Slug: "rl", Enabled: true, Stages: []domain.Stage{domain.StagePreRequest, domain.StagePostResponse}},
			setup: func(t *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("rl").Return(newStatusPlugin(t, []domain.Stage{domain.StagePreRequest}, nil), true)
				r.EXPECT().Validate("rl", mock.Anything).Return(nil)
			},
			wantStatus: apppolicy.StatusActive,
		},
		{
			name:   "a mandatory stage makes empty stages effective",
			policy: domain.Policy{Slug: "rl", Enabled: true},
			setup: func(t *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("rl").Return(newStatusPlugin(t, []domain.Stage{domain.StagePreRequest}, []domain.Stage{domain.StagePreRequest}), true)
				r.EXPECT().Validate("rl", mock.Anything).Return(nil)
			},
			wantStatus: apppolicy.StatusActive,
		},
		{
			name:   "an unsupported mode the gateway still runs is active",
			policy: domain.Policy{Slug: "rl", Enabled: true, Mode: domain.Mode("legacy"), Stages: []domain.Stage{domain.StagePreRequest}},
			setup: func(t *testing.T, r *pluginmocks.Registry) {
				r.EXPECT().Get("rl").Return(newStatusPlugin(t, []domain.Stage{domain.StagePreRequest}, nil), true)
				r.EXPECT().Validate("rl", mock.Anything).Return(nil)
				// ValidateMode / ValidateStages / ValidateSettingsWrite have no
				// expectation: the mock fails the test if any is called.
			},
			wantStatus: apppolicy.StatusActive,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := pluginmocks.NewRegistry(t)
			tt.setup(t, reg)
			p := tt.policy

			status, msg := apppolicy.NewStatusEvaluator(reg).Evaluate(&p)

			assert.Equal(t, tt.wantStatus, status)
			if tt.wantMessage == "" {
				assert.Empty(t, msg)
			} else {
				assert.Contains(t, msg, tt.wantMessage)
			}
		})
	}
}
