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

package prompttemplate

import (
	"context"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
)

const PluginName = "prompt_template"

const (
	typeVariableUnresolved = "template_variable_unresolved"
	typeVariableMissing    = "template_variable_missing"
	typeVariableInvalid    = "template_variable_invalid"
	typeNotFound           = "template_not_found"
	typeRequired           = "template_required"
	typeRenderFailed       = "template_render_failed"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct{}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil {
		return okResult(), nil
	}

	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}

	rb, err := decodeBody(in.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}

	properties, hadProperties := rb.takeProperties()

	modeA := len(cfg.InjectTemplates) > 0
	modeB := len(cfg.NamedTemplates) > 0
	ctxVars, _ := resolveContextVars(cfg, in.Request)

	if !appplugins.Blocks(in.Mode) {
		aOutcome, bOutcome, _ := runModes(cfg, rb.clone(), properties, ctxVars, modeA, modeB)
		setExtras(in.Event, observeData(aOutcome, bOutcome))
		appplugins.SetDecision(in.Event, in.Mode)
		return forwardOrNoOp(rb, hadProperties, false)
	}

	aOutcome, bOutcome, runErr := runModes(cfg, rb, properties, ctxVars, modeA, modeB)
	if runErr != nil {
		setExtras(in.Event, rejectionData(aOutcome, bOutcome))
		return nil, runErr
	}

	setExtras(in.Event, enforceData(aOutcome, bOutcome))
	return forwardOrNoOp(rb, hadProperties, rb.systemDirty || rb.messagesDirty)
}

func forwardOrNoOp(rb *requestBody, hadProperties, mutated bool) (*appplugins.Result, error) {
	if !hadProperties && !mutated {
		return okResult(), nil
	}
	out, err := rb.marshal()
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: out}, nil
}

func runModes(cfg *config, rb *requestBody, properties map[string]any, ctxVars map[string]string, modeA, modeB bool) (modeAOutcome, modeBResult, error) {
	var bOutcome modeBResult
	if modeB {
		var err error
		bOutcome, err = applyModeB(cfg, rb, properties, ctxVars)
		if err != nil {
			return modeAOutcome{}, bOutcome, err
		}
	}

	var aOutcome modeAOutcome
	if modeA {
		aOutcome = applyModeA(cfg, rb, ctxVars)
		if cfg.OnMissingContextVariable == onMissingContextError && len(aOutcome.unresolved) > 0 {
			return aOutcome, bOutcome, reject(http.StatusInternalServerError, typeVariableUnresolved, "unresolved context variable")
		}
	}
	return aOutcome, bOutcome, nil
}

func buildData(decision string, a modeAOutcome, b modeBResult) PromptTemplateData {
	return PromptTemplateData{
		Decision:         decision,
		InjectedIDs:      a.injected,
		SkippedIDs:       a.skipped,
		UnresolvedIDs:    a.unresolved,
		ResolvedTemplate: b.resolvedTemplate,
	}
}

func enforceData(a modeAOutcome, b modeBResult) PromptTemplateData {
	decision := decisionNoOp
	switch {
	case a.changed:
		decision = decisionInjected
	case b.changed:
		decision = decisionRendered
	case len(a.skipped) > 0:
		decision = decisionSkipped
	}
	return buildData(decision, a, b)
}

func observeData(a modeAOutcome, b modeBResult) PromptTemplateData {
	return buildData(decisionObserved, a, b)
}

func rejectionData(a modeAOutcome, b modeBResult) PromptTemplateData {
	return buildData(decisionNoOp, a, b)
}

func reject(status int, errType, message string) error {
	return &appplugins.PluginError{
		StatusCode: status,
		Type:       errType,
		Message:    message,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
	}
}

func setExtras(event *metrics.EventContext, data PromptTemplateData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func okResult() *appplugins.Result { return &appplugins.Result{StatusCode: http.StatusOK} }
