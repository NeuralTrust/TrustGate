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

// Evaluate re-runs the write-time checks (validateStored) against the stored
// row. ValidateSettingsWrite is deliberately NOT run: it guards write
// transitions (a NEWLY introduced bad key, a consistency rule added after
// rows existed) and its plugins document that an already-saved policy keeps
// working at run time. Running it with no previous version would flag
// grandfathered rows the gateway loads and executes fine.
func (e *statusEvaluator) Evaluate(p *domain.Policy) (Status, string) {
	if !p.Enabled {
		return StatusPaused, ""
	}
	if err := validateStored(e.registry, p.Slug, p.Stages, p.Mode, p.Settings); err != nil {
		return StatusError, err.Error()
	}
	return StatusActive, ""
}
