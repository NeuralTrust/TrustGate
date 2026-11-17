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

package limitper_test

import (
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/limitper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolve_ReadsTheModelOnlyInModelMode(t *testing.T) {
	scope := appplugins.RuntimeScope{GatewayID: "gw", ConsumerID: "app", AuthID: "a", KeyGroupID: "g"}
	for _, mode := range []string{"", limitper.Shared, limitper.Application, limitper.APIKey, limitper.Group, limitper.Header} {
		t.Run("mode "+mode, func(t *testing.T) {
			spec := limitper.Spec{LimitPer: mode}
			counter := spec.Resolve(scope, func() string { t.Fatal("the model was read"); return "" })
			assert.True(t, counter.Applies)
		})
	}
	called := false
	spec := limitper.Spec{LimitPer: limitper.Model}
	spec.Resolve(scope, func() string { called = true; return "m" })
	assert.True(t, called)
}

func TestResolve_MissingApplicationIsNotLimited(t *testing.T) {
	scope := appplugins.RuntimeScope{GatewayID: "gw"}
	for _, spec := range []limitper.Spec{
		{LimitPer: limitper.Application},
		{LimitPer: limitper.Group},
	} {
		assert.False(t, spec.Resolve(scope, nil).Applies, spec.LimitPer)
	}
}

func TestValidate_AppliesTo(t *testing.T) {
	modes := []string{limitper.Shared, limitper.Application, limitper.APIKey, limitper.Group, limitper.Model, limitper.Header}
	for _, mode := range modes {
		spec := limitper.Spec{LimitPer: mode, AppliesTo: limitper.AppliesAll}
		var groupBy appplugins.GroupBy
		if mode == limitper.Header {
			groupBy = appplugins.GroupBy{Mode: appplugins.GroupByHeader, Header: "X-T"}
		}
		assert.NoError(t, spec.Validate("p", modes, groupBy), "applies_to all on %s", mode)
	}
	for _, mode := range []string{limitper.Shared, limitper.APIKey, limitper.Model} {
		spec := limitper.Spec{LimitPer: mode, AppliesTo: limitper.AppliesSelected, Selected: []string{"a"}}
		assert.Error(t, spec.Validate("p", modes, appplugins.GroupBy{}), "applies_to selected on %s", mode)
	}
}

func TestValidate_GroupBySplitsOnlyASharedOrHeaderCounter(t *testing.T) {
	modes := []string{limitper.Shared, limitper.Application, limitper.APIKey, limitper.Group, limitper.Model, limitper.Header}
	subject := appplugins.GroupBy{Mode: appplugins.GroupBySubject}
	header := appplugins.GroupBy{Mode: appplugins.GroupByHeader, Header: "X-T"}

	assert.NoError(t, limitper.Spec{}.Validate("p", modes, subject))
	assert.NoError(t, limitper.Spec{LimitPer: limitper.Header}.Validate("p", modes, header))
	assert.ErrorContains(t, limitper.Spec{LimitPer: limitper.Header}.Validate("p", modes, subject), "requires group_by_header")
	assert.ErrorContains(t, limitper.Spec{LimitPer: limitper.Application}.Validate("p", modes, subject), "group_by cannot be combined")
	assert.ErrorContains(t, limitper.Spec{LimitPer: limitper.Model}.Validate("p", modes, header), "group_by_header cannot be combined")
}

func TestRequestModel(t *testing.T) {
	tests := []struct {
		name string
		req  *infracontext.RequestContext
		want string
	}{
		{"already extracted ref wins without reading the body", &infracontext.RequestContext{RequestedModel: "@openai/gpt-6-luna", Body: []byte("not json")}, "@openai/gpt-6-luna"},
		{"body model", &infracontext.RequestContext{Body: []byte(`{"model":"gpt-a"}`)}, "gpt-a"},
		{"no model is served the route default", &infracontext.RequestContext{Body: []byte(`{}`), DefaultModel: "gpt-default"}, "gpt-default"},
		{"auto is served the route default", &infracontext.RequestContext{RequestedModel: "auto", Body: []byte(`{"model":"auto"}`), DefaultModel: "gpt-default"}, "gpt-default"},
		{"no model and no default", &infracontext.RequestContext{Body: []byte(`{}`)}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, limitper.RequestModel(tt.req))
		})
	}
}
