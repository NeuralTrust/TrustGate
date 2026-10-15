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

package policy

import (
	"fmt"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// Status tells the console whether a stored policy is doing its job.
type Status string

const (
	// StatusActive: enabled and loadable.
	StatusActive Status = "active"
	// StatusPaused: disabled. Validity is irrelevant, the gateway skips it.
	StatusPaused Status = "paused"
	// StatusError: enabled but the gateway cannot load it.
	StatusError Status = "error"
)

// StatusEvaluator computes the Status of stored policies on the read path.
type StatusEvaluator interface {
	// Evaluate returns the status and, for StatusError, the reason.
	Evaluate(p *domain.Policy) (Status, string)
}

var _ StatusEvaluator = (*statusEvaluator)(nil)

type statusEvaluator struct {
	registry appplugins.Registry
}

func NewStatusEvaluator(registry appplugins.Registry) StatusEvaluator {
	return &statusEvaluator{registry: registry}
}

// Evaluate reports whether the gateway can RUN an enabled policy, which is
// narrower than whether a write of it would be accepted. The data plane never
// calls ValidateStages, ValidateMode or ValidateSettingsWrite on a stored row
// (plan.go): it skips an unknown slug, drops unsupported stages and keeps the
// supported ones, and normalises the mode. So only what actually stops the
// policy from running is an error:
//   - unknown slug (plan.go skips the row);
//   - no effective stage left after that filtering (EffectiveStages is the same
//     rule isEffectiveStage applies), so the policy never fires;
//   - settings the plugin rejects: Execute parses them with the same parseConfig
//     ValidateConfig uses, so a row that fails here fails on every request.
func (e *statusEvaluator) Evaluate(p *domain.Policy) (Status, string) {
	if !p.Enabled {
		return StatusPaused, ""
	}
	plugin, ok := e.registry.Get(p.Slug)
	if !ok {
		return StatusError, fmt.Errorf("%w: %s", appplugins.ErrUnknownPlugin, p.Slug).Error()
	}
	if len(appplugins.EffectiveStages(plugin, p.Stages)) == 0 {
		return StatusError, appplugins.ErrNoEffectiveStages.Error()
	}
	if err := e.registry.Validate(p.Slug, p.Settings); err != nil {
		return StatusError, err.Error()
	}
	return StatusActive, ""
}
