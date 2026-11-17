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

// Package limitper is the "Limit per" setting the rate limiter and the LLM
// budget share: which identity each counter belongs to.
package limitper

import (
	"fmt"
	"net/url"
	"slices"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	Shared      = "shared"
	Application = "application"
	APIKey      = "api_key"
	Group       = "group"
	Model       = "model"
	Header      = "header"

	AppliesAll      = "all"
	AppliesSelected = "selected"
)

// Spec is embedded (squashed) in a plugin config. An absent LimitPer is Shared,
// the behaviour before the setting existed.
type Spec struct {
	LimitPer  string   `mapstructure:"limit_per"`
	AppliesTo string   `mapstructure:"applies_to"`
	Selected  []string `mapstructure:"selected"`
	Models    []string `mapstructure:"models"`
}

// Mode is the effective mode: Shared when LimitPer is absent.
func (s Spec) Mode() string {
	if s.LimitPer == "" {
		return Shared
	}
	return s.LimitPer
}

// Validate checks the spec against the modes the plugin offers. groupBy is the
// plugin's parsed caller partition, which splits only a shared or header counter.
func (s Spec) Validate(plugin string, allowed []string, groupBy appplugins.GroupBy) error {
	mode := s.Mode()
	if !slices.Contains(allowed, mode) {
		return fmt.Errorf("%s: limit_per must be one of %v", plugin, allowed)
	}
	if mode == Header && groupBy.Mode != appplugins.GroupByHeader {
		return fmt.Errorf("%s: limit_per %s requires group_by_header", plugin, Header)
	}
	if groupBy.Mode != "" && mode != Header && mode != Shared {
		field := "group_by"
		if groupBy.Mode == appplugins.GroupByHeader {
			field = "group_by_header"
		}
		return fmt.Errorf("%s: %s cannot be combined with limit_per %s", plugin, field, mode)
	}
	scoped := mode == Application || mode == Group
	switch s.AppliesTo {
	case "", AppliesAll:
		if len(s.Selected) > 0 {
			return fmt.Errorf("%s: selected requires applies_to %s", plugin, AppliesSelected)
		}
	case AppliesSelected:
		if !scoped {
			return fmt.Errorf("%s: applies_to %s is only valid with limit_per %s or %s", plugin, AppliesSelected, Application, Group)
		}
		if len(s.Selected) == 0 {
			return fmt.Errorf("%s: applies_to %s requires a non-empty selected list", plugin, AppliesSelected)
		}
	default:
		return fmt.Errorf("%s: applies_to must be one of %s, %s", plugin, AppliesAll, AppliesSelected)
	}
	if len(s.Models) > 0 && mode != Model {
		return fmt.Errorf("%s: models is only valid with limit_per %s", plugin, Model)
	}
	return nil
}

// Counter says which counter a request belongs to.
type Counter struct {
	// Applies is false when the request is outside the policy's selection and
	// is not limited by it.
	Applies bool
	// Dimension replaces the scope dimension when set.
	Dimension string
	// Suffix is appended to the counter key; empty keeps the shared key.
	Suffix string
}

// Resolve picks the counter for a request. model is read only in model mode, as
// finding it can mean parsing the body. A request with no application or key to
// count under is not limited.
func (s Spec) Resolve(scope appplugins.RuntimeScope, model func() string) Counter {
	switch s.Mode() {
	case Application:
		return s.application(scope)
	case APIKey:
		kind, id, ok := scope.Key()
		if !ok {
			return Counter{}
		}
		return Counter{Applies: true, Dimension: "key", Suffix: ":key:" + kind + ":" + url.QueryEscape(id)}
	case Group:
		if scope.KeyGroupID == "" {
			// Selection filters requests that have a group; one without
			// always counts toward its application.
			return s.application(scope)
		}
		if s.AppliesTo == AppliesSelected && !slices.Contains(s.Selected, scope.KeyGroupID) {
			return Counter{}
		}
		return Counter{Applies: true, Dimension: "group", Suffix: ":grp:" + url.QueryEscape(scope.KeyGroupID)}
	case Model:
		name := model()
		if name == "" {
			return Counter{}
		}
		if len(s.Models) > 0 {
			if _, ok := modelmatch.MatchAny(name, s.Models); !ok {
				return Counter{}
			}
		}
		return Counter{Applies: true, Dimension: "model", Suffix: ":mdl:" + url.QueryEscape(name)}
	default:
		return Counter{Applies: true}
	}
}

func (s Spec) application(scope appplugins.RuntimeScope) Counter {
	if scope.ConsumerID == "" {
		return Counter{}
	}
	if s.Mode() == Application && s.AppliesTo == AppliesSelected && !slices.Contains(s.Selected, scope.ConsumerID) {
		return Counter{}
	}
	return Counter{Applies: true, Dimension: "application", Suffix: ":app:" + url.QueryEscape(scope.ConsumerID)}
}

// ExplicitModel is the model the client named in the request, ok false when it
// named none.
func ExplicitModel(req *infracontext.RequestContext) (model string, ok bool) {
	if req.IsBedrockNative() {
		// A native Bedrock call names its model in the path, never in the body.
		return req.BedrockNative.ModelID, true
	}
	if len(req.Body) > 0 {
		if m, err := adapter.ExtractModel(req.Body); err == nil && m != "" {
			return m, true
		}
	}
	return "", false
}

// RequestModel is the model a request is counted under: the ref the gateway
// already extracted, else the body's model, else the route's default model for a
// request that names none (no model, auto, a pool).
func RequestModel(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.IsBedrockNative() {
		return req.BedrockNative.ModelID
	}
	if namesModel(req.RequestedModel) {
		return req.RequestedModel
	}
	if len(req.Body) > 0 {
		if m, err := adapter.ExtractModel(req.Body); err == nil && namesModel(m) {
			return m
		}
	}
	if req.DefaultModel != "" {
		return req.DefaultModel
	}
	return ""
}

func namesModel(ref string) bool {
	intent, err := routingdomain.ParseModelRef(ref)
	return err == nil && intent.Model != ""
}
