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

package costcap

import (
	"context"
	"fmt"
	"net/http"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "cost_cap"

var _ appplugins.Plugin = (*Plugin)(nil)

// Plugin enforces a stateless per-request ceiling on model list price.
type Plugin struct {
	pricing appcatalog.PricingResolver
}

func New(pricing appcatalog.PricingResolver) *Plugin {
	return &Plugin{pricing: pricing}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

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

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil || in.Request.Provider == "" {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
	if in.Stage != policy.StagePreRequest {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("cost_cap: %w", err)
	}

	model := modelFor(in.Request)
	dec := llmcost.Decide(ctx, p.pricing, cfg.CustomPricing, &cfg.Cap, in.Request.Provider, model, in.Request.RequestedModel)
	data := CapData{Stage: string(in.Stage), Provider: in.Request.Provider, Model: model}
	applyTelemetry(&data, llmcost.TelemetryFrom(dec))

	if dec.Kind == llmcost.DecisionViolation {
		appplugins.SetDecision(in.Event, in.Mode)
		if appplugins.Blocks(in.Mode) && !appplugins.Throttles(in.Mode) {
			if cfg.Cap.BehaviorOnViolation == llmcost.BehaviorDowngrade {
				newModel, body, hdr, ok := llmcost.ApplyDowngrade(in.Request, model, cfg.Cap.DowngradeTo)
				if !ok {
					return nil, llmcost.CostCapError(dec)
				}
				data.Model = newModel
				data.Downgraded = true
				setExtras(in.Event, data)
				return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body, Headers: hdr}, nil
			}
			return nil, llmcost.CostCapError(dec)
		}
	}

	setExtras(in.Event, data)
	return &appplugins.Result{StatusCode: http.StatusOK}, nil
}

func modelFor(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if len(req.Body) > 0 {
		if m, err := adapter.ExtractModel(req.Body); err == nil && m != "" {
			return m
		}
	}
	return req.RequestedModel
}

func setExtras(event *metrics.EventContext, data CapData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func applyTelemetry(data *CapData, t *llmcost.Telemetry) {
	if t == nil {
		return
	}
	data.Violation = t.Violation
	data.UnknownModel = t.Unknown
	data.InputPricePer1k = t.InputPrice
	data.OutputPricePer1k = t.OutputPrice
	data.MaxInputPer1k = t.MaxInput
	data.MaxOutputPer1k = t.MaxOutput
}
