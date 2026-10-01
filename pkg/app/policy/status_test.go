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

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestStatusEvaluator_Evaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		enabled     bool
		slug        string
		setup       func(r *pluginmocks.Registry)
		wantStatus  apppolicy.Status
		wantMessage string
	}{
		{
			name:    "enabled and valid is active",
			enabled: true,
			slug:    "rate_limiter",
			setup: func(r *pluginmocks.Registry) {
				r.EXPECT().ValidateStages("rate_limiter", mock.Anything).Return(nil)
				r.EXPECT().ValidateMode("rate_limiter", mock.Anything).Return(nil)
				r.EXPECT().Validate("rate_limiter", mock.Anything).Return(nil)
			},
			wantStatus: apppolicy.StatusActive,
		},
		{
			name:       "disabled and invalid is paused without validating",
			enabled:    false,
			slug:       "gone",
			setup:      func(*pluginmocks.Registry) {},
			wantStatus: apppolicy.StatusPaused,
		},
		{
			name:    "enabled with unknown slug is error",
			enabled: true,
			slug:    "gone",
			setup: func(r *pluginmocks.Registry) {
				r.EXPECT().ValidateStages("gone", mock.Anything).
					Return(errors.Join(appplugins.ErrUnknownPlugin, errors.New("gone")))
			},
			wantStatus:  apppolicy.StatusError,
			wantMessage: "unknown plugin",
		},
		{
			name:    "enabled with invalid settings is error",
			enabled: true,
			slug:    "rate_limiter",
			setup: func(r *pluginmocks.Registry) {
				r.EXPECT().ValidateStages("rate_limiter", mock.Anything).Return(nil)
				r.EXPECT().ValidateMode("rate_limiter", mock.Anything).Return(nil)
				r.EXPECT().Validate("rate_limiter", mock.Anything).Return(errors.New("limit must be positive"))
			},
			wantStatus:  apppolicy.StatusError,
			wantMessage: "limit must be positive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := pluginmocks.NewRegistry(t)
			tt.setup(reg)
			ev := apppolicy.NewStatusEvaluator(reg)

			status, msg := ev.Evaluate(&domain.Policy{Slug: tt.slug, Enabled: tt.enabled})

			assert.Equal(t, tt.wantStatus, status)
			if tt.wantMessage == "" {
				assert.Empty(t, msg)
			} else {
				assert.Contains(t, msg, tt.wantMessage)
			}
		})
	}
}

func TestStatusEvaluator_DoesNotRunWriteOnlyChecks(t *testing.T) {
	t.Parallel()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages("p", mock.Anything).Return(nil)
	reg.EXPECT().ValidateMode("p", mock.Anything).Return(nil)
	reg.EXPECT().Validate("p", mock.Anything).Return(nil)
	// ValidateSettingsWrite has no expectation: the mock fails the test if called.

	status, _ := apppolicy.NewStatusEvaluator(reg).Evaluate(&domain.Policy{Slug: "p", Enabled: true})

	assert.Equal(t, apppolicy.StatusActive, status)
}
