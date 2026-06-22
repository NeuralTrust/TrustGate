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

package tokenratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const costCapErrorType = "model_too_expensive"

type decisionKind int

const (
	decisionAllow decisionKind = iota
	decisionViolation
)

type decision struct {
	kind        decisionKind
	unknown     bool
	model       string
	inputPrice  float64
	outputPrice float64
	maxInput    float64
	maxOutput   float64
}

func evaluateCeiling(cc *costCapConfig, models ...string) costCeiling {
	if cc == nil {
		return costCeiling{}
	}
	for _, slug := range appcatalog.SlugCandidates(models...) {
		if c, ok := bestMatch(cc.PerModelOverrides, slug); ok {
			return c
		}
	}
	return costCeiling{
		MaxInputCostPer1k:  cc.MaxInputCostPer1k,
		MaxOutputCostPer1k: cc.MaxOutputCostPer1k,
	}
}

func exceedsCeiling(price, ceiling float64) bool {
	return ceiling > 0 && price > ceiling
}

func (p *Plugin) costCapDecision(ctx context.Context, cfg *config, provider string, models ...string) decision {
	cc := cfg.CostCap
	model := firstNonEmpty(models...)
	ceiling := evaluateCeiling(cc, models...)

	inPerToken, outPerToken, found := p.priceFor(ctx, cfg, provider, models...)
	if !found {
		d := decision{
			unknown:   true,
			model:     model,
			maxInput:  ceiling.MaxInputCostPer1k,
			maxOutput: ceiling.MaxOutputCostPer1k,
		}
		if cc.UnknownModel == unknownPassThrough {
			d.kind = decisionAllow
		} else {
			d.kind = decisionViolation
		}
		return d
	}

	inPer1k := per1k(inPerToken)
	outPer1k := per1k(outPerToken)
	d := decision{
		model:       model,
		inputPrice:  inPer1k,
		outputPrice: outPer1k,
		maxInput:    ceiling.MaxInputCostPer1k,
		maxOutput:   ceiling.MaxOutputCostPer1k,
	}
	if exceedsCeiling(inPer1k, ceiling.MaxInputCostPer1k) || exceedsCeiling(outPer1k, ceiling.MaxOutputCostPer1k) {
		d.kind = decisionViolation
	} else {
		d.kind = decisionAllow
	}
	return d
}

type costCapTelemetry struct {
	violation   bool
	unknown     bool
	inputPrice  float64
	outputPrice float64
	maxInput    float64
	maxOutput   float64
}

func costCapTelemetryFrom(dec decision) *costCapTelemetry {
	return &costCapTelemetry{
		violation:   dec.kind == decisionViolation,
		unknown:     dec.unknown,
		inputPrice:  dec.inputPrice,
		outputPrice: dec.outputPrice,
		maxInput:    dec.maxInput,
		maxOutput:   dec.maxOutput,
	}
}

func (c *costCapTelemetry) apply(data *TokenRateLimiterData) {
	if c == nil {
		return
	}
	data.CostCapViolation = c.violation
	data.UnknownModel = c.unknown
	data.InputPricePer1k = c.inputPrice
	data.OutputPricePer1k = c.outputPrice
	data.MaxInputPer1k = c.maxInput
	data.MaxOutputPer1k = c.maxOutput
}

func costCapError(dec decision) *appplugins.PluginError {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":         costCapErrorType,
			"model":        dec.model,
			"input_price":  dec.inputPrice,
			"output_price": dec.outputPrice,
			"max_input":    dec.maxInput,
			"max_output":   dec.maxOutput,
		},
	})
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Message:    fmt.Sprintf("model %q exceeds cost cap", dec.model),
		Body:       body,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
