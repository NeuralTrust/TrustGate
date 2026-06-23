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

package llmcost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

// CostCapErrorType is the error type emitted when a model exceeds its cost cap.
const CostCapErrorType = "model_too_expensive"

// Behaviors taken when a model exceeds its cost ceiling.
const (
	BehaviorReject    = "reject"
	BehaviorDowngrade = "downgrade"
)

// Policies for models whose price cannot be resolved.
const (
	UnknownReject      = "reject"
	UnknownPassThrough = "pass_through"
	UnknownAssumeMax   = "assume_max"
)

// Ceiling is a per-1k-token USD price ceiling.
type Ceiling struct {
	MaxInputCostPer1k  float64 `mapstructure:"max_input_cost_per_1k_tokens"`
	MaxOutputCostPer1k float64 `mapstructure:"max_output_cost_per_1k_tokens"`
}

// CapConfig is the stateless per-request cost cap configuration.
type CapConfig struct {
	Enabled             bool               `mapstructure:"enabled"`
	MaxInputCostPer1k   float64            `mapstructure:"max_input_cost_per_1k_tokens"`
	MaxOutputCostPer1k  float64            `mapstructure:"max_output_cost_per_1k_tokens"`
	PerModelOverrides   map[string]Ceiling `mapstructure:"per_model_overrides"`
	BehaviorOnViolation string             `mapstructure:"behavior_on_violation"`
	DowngradeTo         string             `mapstructure:"downgrade_to"`
	UnknownModel        string             `mapstructure:"unknown_model"`
}

// Validate checks an enabled cost cap configuration.
func (c *CapConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	switch c.UnknownModel {
	case "", UnknownReject, UnknownPassThrough, UnknownAssumeMax:
	default:
		return fmt.Errorf("cost_cap.unknown_model must be one of reject, pass_through, assume_max")
	}

	switch c.BehaviorOnViolation {
	case "", BehaviorReject, BehaviorDowngrade:
	default:
		return fmt.Errorf("cost_cap.behavior_on_violation must be one of reject, downgrade")
	}
	if c.BehaviorOnViolation == BehaviorDowngrade && c.DowngradeTo == "" {
		return fmt.Errorf("cost_cap.behavior_on_violation=downgrade requires downgrade_to")
	}

	if c.MaxInputCostPer1k < 0 || c.MaxOutputCostPer1k < 0 {
		return fmt.Errorf("cost_cap ceilings must be >= 0")
	}
	for k := range c.PerModelOverrides {
		if c.PerModelOverrides[k].MaxInputCostPer1k < 0 || c.PerModelOverrides[k].MaxOutputCostPer1k < 0 {
			return fmt.Errorf("cost_cap.per_model_overrides[%q] ceilings must be >= 0", k)
		}
	}
	return nil
}

// DecisionKind classifies the outcome of a cost cap evaluation.
type DecisionKind int

const (
	DecisionAllow DecisionKind = iota
	DecisionViolation
)

// Decision is the outcome of evaluating a model against its cost ceiling.
type Decision struct {
	Kind        DecisionKind
	Unknown     bool
	Model       string
	InputPrice  float64
	OutputPrice float64
	MaxInput    float64
	MaxOutput   float64
}

// EvaluateCeiling resolves the effective ceiling for a model, preferring the
// most specific per-model override before the global ceiling.
func EvaluateCeiling(cc *CapConfig, models ...string) Ceiling {
	if cc == nil {
		return Ceiling{}
	}
	for _, slug := range appcatalog.SlugCandidates(models...) {
		if c, ok := BestMatch(cc.PerModelOverrides, slug); ok {
			return c
		}
	}
	return Ceiling{
		MaxInputCostPer1k:  cc.MaxInputCostPer1k,
		MaxOutputCostPer1k: cc.MaxOutputCostPer1k,
	}
}

func exceedsCeiling(price, ceiling float64) bool {
	return ceiling > 0 && price > ceiling
}

// Decide evaluates a model against its cost cap, resolving its price first.
func Decide(ctx context.Context, resolver appcatalog.PricingResolver, custom map[string]CustomPrice, cc *CapConfig, provider string, models ...string) Decision {
	model := firstNonEmpty(models...)
	ceiling := EvaluateCeiling(cc, models...)

	inPerToken, outPerToken, found := PriceFor(ctx, resolver, custom, provider, models...)
	if !found {
		d := Decision{
			Unknown:   true,
			Model:     model,
			MaxInput:  ceiling.MaxInputCostPer1k,
			MaxOutput: ceiling.MaxOutputCostPer1k,
		}
		if cc.UnknownModel == UnknownPassThrough {
			d.Kind = DecisionAllow
		} else {
			d.Kind = DecisionViolation
		}
		return d
	}

	inPer1k := Per1k(inPerToken)
	outPer1k := Per1k(outPerToken)
	d := Decision{
		Model:       model,
		InputPrice:  inPer1k,
		OutputPrice: outPer1k,
		MaxInput:    ceiling.MaxInputCostPer1k,
		MaxOutput:   ceiling.MaxOutputCostPer1k,
	}
	if exceedsCeiling(inPer1k, ceiling.MaxInputCostPer1k) || exceedsCeiling(outPer1k, ceiling.MaxOutputCostPer1k) {
		d.Kind = DecisionViolation
	} else {
		d.Kind = DecisionAllow
	}
	return d
}

// Telemetry is a transport-neutral snapshot of a cost cap decision for metrics.
type Telemetry struct {
	Violation   bool
	Unknown     bool
	InputPrice  float64
	OutputPrice float64
	MaxInput    float64
	MaxOutput   float64
}

// TelemetryFrom projects a Decision into Telemetry.
func TelemetryFrom(dec Decision) *Telemetry {
	return &Telemetry{
		Violation:   dec.Kind == DecisionViolation,
		Unknown:     dec.Unknown,
		InputPrice:  dec.InputPrice,
		OutputPrice: dec.OutputPrice,
		MaxInput:    dec.MaxInput,
		MaxOutput:   dec.MaxOutput,
	}
}

// CostCapError builds the 403 plugin error for a cost cap violation.
func CostCapError(dec Decision) *appplugins.PluginError {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":         CostCapErrorType,
			"model":        dec.Model,
			"input_price":  dec.InputPrice,
			"output_price": dec.OutputPrice,
			"max_input":    dec.MaxInput,
			"max_output":   dec.MaxOutput,
		},
	})
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Message:    fmt.Sprintf("model %q exceeds cost cap", dec.Model),
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
