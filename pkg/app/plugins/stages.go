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
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

var ErrStageNotSupported = errors.New("plugin: stage not supported")
var ErrNoEffectiveStages = errors.New("plugin: no effective stages")

func EffectiveStages(p PluginDescriptor, selected []policy.Stage) []policy.Stage {
	supported := p.SupportedStages()
	out := make([]policy.Stage, 0, len(supported))
	for _, s := range p.MandatoryStages() {
		if !containsStage(out, s) {
			out = append(out, s)
		}
	}
	for _, s := range selected {
		if containsStage(supported, s) && !containsStage(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func ValidateStages(p PluginDescriptor, selected []policy.Stage) error {
	supported := p.SupportedStages()
	for _, s := range selected {
		if !containsStage(supported, s) {
			return fmt.Errorf("%w: %q", ErrStageNotSupported, s)
		}
	}
	if len(EffectiveStages(p, selected)) == 0 {
		return ErrNoEffectiveStages
	}
	return nil
}
