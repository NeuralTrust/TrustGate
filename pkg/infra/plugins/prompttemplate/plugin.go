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

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

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

	if len(cfg.InjectTemplates) == 0 {
		return okResult(), nil
	}

	rb, err := decodeBody(in.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}

	ctxVars, _ := resolveContextVars(cfg, in.Request)
	outcome := applyModeA(cfg, rb, ctxVars)

	if !appplugins.Blocks(in.Mode) {
		setExtras(in.Event, observeData(outcome))
		appplugins.SetDecision(in.Event, in.Mode)
		return okResult(), nil
	}

	if cfg.OnMissingContextVariable == onMissingContextError && len(outcome.unresolved) > 0 {
		setExtras(in.Event, PromptTemplateData{Decision: decisionNoOp, UnresolvedIDs: outcome.unresolved})
		return nil, reject(http.StatusInternalServerError, typeVariableUnresolved, "unresolved context variable")
	}

	setExtras(in.Event, enforceData(outcome))

	out, err := rb.marshal()
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: out}, nil
}

func enforceData(outcome modeAOutcome) PromptTemplateData {
	decision := decisionNoOp
	switch {
	case outcome.changed:
		decision = decisionInjected
	case len(outcome.skipped) > 0:
		decision = decisionSkipped
	}
	return PromptTemplateData{
		Decision:    decision,
		InjectedIDs: outcome.injected,
		SkippedIDs:  outcome.skipped,
	}
}

func observeData(outcome modeAOutcome) PromptTemplateData {
	return PromptTemplateData{
		Decision:      decisionObserved,
		InjectedIDs:   outcome.injected,
		SkippedIDs:    outcome.skipped,
		UnresolvedIDs: outcome.unresolved,
	}
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
