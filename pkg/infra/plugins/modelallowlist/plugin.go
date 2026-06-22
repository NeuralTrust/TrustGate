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

package modelallowlist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "model_allowlist"

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
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("model_allowlist: %w", err)
	}

	blocks := appplugins.Blocks(in.Mode)

	if in.Request == nil {
		return okResult(), nil
	}

	model, err := adapter.ExtractModel(in.Request.Body)
	if err != nil {
		setExtras(in.Event, ModelAllowlistData{Decision: decisionAllowed, Behavior: string(cfg.Behavior)})
		return okResult(), nil
	}

	if model == "" {
		if cfg.DefaultModel != "" && blocks {
			in.Request.Body = adapter.OverrideModel(in.Request.Body, cfg.DefaultModel)
			setExtras(in.Event, ModelAllowlistData{
				Decision:        decisionDefaulted,
				SubstitutedWith: cfg.DefaultModel,
				Behavior:        string(cfg.Behavior),
			})
			return okResult(), nil
		}
		setExtras(in.Event, ModelAllowlistData{Decision: decisionAllowed, Behavior: string(cfg.Behavior)})
		return okResult(), nil
	}

	if pattern, ok := matchAny(model, cfg.AllowedModels); ok {
		setExtras(in.Event, ModelAllowlistData{
			RequestedModel: model,
			Decision:       decisionAllowed,
			MatchedPattern: pattern,
			Behavior:       string(cfg.Behavior),
		})
		return okResult(), nil
	}

	if !blocks {
		setExtras(in.Event, ModelAllowlistData{
			RequestedModel: model,
			Decision:       observeDecision(cfg.Behavior),
			Behavior:       string(cfg.Behavior),
		})
		appplugins.SetDecision(in.Event, in.Mode)
		return okResult(), nil
	}

	if cfg.Behavior == behaviorSubstitute {
		in.Request.Body = adapter.OverrideModel(in.Request.Body, cfg.SubstituteWith)
		setExtras(in.Event, ModelAllowlistData{
			RequestedModel:  model,
			Decision:        decisionSubstituted,
			SubstitutedWith: cfg.SubstituteWith,
			Behavior:        string(cfg.Behavior),
		})
		return okResult(), nil
	}

	setExtras(in.Event, ModelAllowlistData{
		RequestedModel: model,
		Decision:       decisionRejected,
		Behavior:       string(cfg.Behavior),
	})
	return newRejectResult(model, cfg.AllowedModels)
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Type    string   `json:"type"`
	Model   string   `json:"model"`
	Allowed []string `json:"allowed"`
}

func newErrorBody(model string, allowed []string) errorBody {
	return errorBody{Error: errorDetail{Type: "model_not_allowed", Model: model, Allowed: allowed}}
}

func newRejectResult(model string, allowed []string) (*appplugins.Result, error) {
	body, err := json.Marshal(newErrorBody(model, allowed))
	if err != nil {
		return nil, &appplugins.PluginError{
			StatusCode: http.StatusForbidden,
			Message:    "model not allowed",
		}
	}
	return &appplugins.Result{
		StopUpstream: true,
		StatusCode:   http.StatusForbidden,
		Headers:      map[string][]string{"Content-Type": {"application/json"}},
		Body:         body,
	}, nil
}

func okResult() *appplugins.Result { return &appplugins.Result{StatusCode: http.StatusOK} }

func setExtras(event *metrics.EventContext, data ModelAllowlistData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
