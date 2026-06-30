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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

var ErrInvalidModes = fmt.Errorf("plugin: invalid declared modes")

func validateDeclaredModes(name string, modes []policy.Mode) error {
	if len(modes) == 0 {
		return fmt.Errorf("%w: %s declares no supported modes", ErrInvalidModes, name)
	}
	hasEnforce := false
	for _, m := range modes {
		if !m.IsValid() {
			return fmt.Errorf("%w: %s supports %q", ErrInvalidModes, name, m)
		}
		if m == policy.ModeEnforce {
			hasEnforce = true
		}
	}
	if !hasEnforce {
		return fmt.Errorf("%w: %s must support %q", ErrInvalidModes, name, policy.ModeEnforce)
	}
	return nil
}

func Blocks(mode policy.Mode) bool {
	return mode != policy.ModeObserve
}

func Throttles(mode policy.Mode) bool {
	return mode == policy.ModeThrottle
}

func DecisionForMode(mode policy.Mode) string {
	switch mode {
	case policy.ModeObserve:
		return "observe"
	case policy.ModeThrottle:
		return "throttle"
	default:
		return "block"
	}
}

func SetDecision(event *metrics.EventContext, mode policy.Mode) {
	if event == nil {
		return
	}
	event.SetDecision(DecisionForMode(mode))
}

// SetDecisionFromOutcome records the plugin's actual outcome on the metrics span.
// Unlike SetDecision(mode), this does not label enforce-mode pass-throughs as "block".
func SetDecisionFromOutcome(event *metrics.EventContext, outcome string) {
	if event == nil {
		return
	}
	event.SetDecision(SpanDecisionFromOutcome(outcome))
}

// SpanDecisionFromOutcome maps plugin-specific outcome strings to policy-chain decisions.
func SpanDecisionFromOutcome(outcome string) string {
	switch outcome {
	case "blocked", "block":
		return "block"
	case "reported", "report", "rejected":
		return "reported"
	default:
		return outcome
	}
}
