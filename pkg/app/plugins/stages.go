package plugins

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

var ErrStageNotSupported = fmt.Errorf("plugin: stage not supported")
var ErrNoEffectiveStages = fmt.Errorf("plugin: no effective stages")

func EffectiveStages(p Plugin, selected []policy.Stage) []policy.Stage {
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

func ValidateStages(p Plugin, selected []policy.Stage) error {
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
