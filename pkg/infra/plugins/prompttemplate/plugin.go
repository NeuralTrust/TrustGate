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
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
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

func (p *Plugin) Execute(_ context.Context, _ appplugins.ExecInput) (*appplugins.Result, error) {
	return okResult(), nil
}

func okResult() *appplugins.Result { return &appplugins.Result{StatusCode: http.StatusOK} }
