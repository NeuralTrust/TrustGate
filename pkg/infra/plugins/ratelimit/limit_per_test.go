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

package ratelimit

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func limitPerInput(settings map[string]any, scope appplugins.RuntimeScope, body string) appplugins.ExecInput {
	in := execInput(settings, scope)
	in.Request = &infracontext.RequestContext{Body: []byte(body)}
	return in
}

func withLimitPer(extra map[string]any) map[string]any {
	s := limitSettings(1, "1m")
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func TestPlugin_Execute_AbsentLimitPerKeepsExistingKeys(t *testing.T) {
	tests := []struct {
		name  string
		scope appplugins.RuntimeScope
		key   string
	}{
		{"consumer policy", consumerScope("app-1"), "ratelimit:plugin-1:consumer:app-1"},
		{"global policy", globalScope(), "ratelimit:plugin-1:global:gw-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, mr := newTestPlugin(t)
			_, err := p.Execute(context.Background(), execInput(limitSettings(1, "1m"), tt.scope))
			require.NoError(t, err)
			assert.Equal(t, []string{tt.key}, mr.Keys())
		})
	}
}

func TestPlugin_Execute_LimitPerCounters(t *testing.T) {
	groupScope := globalScope()
	groupScope.ConsumerID = "app-1"
	groupScope.KeyGroupID = "grp-1"
	keyScope := globalScope()
	keyScope.AuthID = "auth-1"
	ownerScope := globalScope()
	ownerScope.AuthID = "auth-1"
	ownerScope.OwnerID = "user-1"
	appScope := globalScope()
	appScope.ConsumerID = "app-1"
	noGroup := appScope
	otherGroup := groupScope
	otherGroup.KeyGroupID = "grp-2"

	tests := []struct {
		name     string
		settings map[string]any
		scope    appplugins.RuntimeScope
		body     string
		wantKey  string // empty: the request is not limited by this policy
	}{
		{"shared explicit equals absent", withLimitPer(map[string]any{"limit_per": "shared"}), globalScope(), "", "ratelimit:plugin-1:global:gw-1"},
		{"application on a global policy", withLimitPer(map[string]any{"limit_per": "application"}), appScope, "", "ratelimit:plugin-1:global:gw-1:app:app-1"},
		{"application selected, in the list", withLimitPer(map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{"app-1"}}), appScope, "", "ratelimit:plugin-1:global:gw-1:app:app-1"},
		{"application selected, outside the list", withLimitPer(map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{"app-2"}}), appScope, "", ""},
		{"api key", withLimitPer(map[string]any{"limit_per": "api_key"}), keyScope, "", "ratelimit:plugin-1:global:gw-1:key:auth:auth-1"},
		{"api key of a personal key counts its owner", withLimitPer(map[string]any{"limit_per": "api_key"}), ownerScope, "", "ratelimit:plugin-1:global:gw-1:key:owner:user-1"},
		{"api key absent", withLimitPer(map[string]any{"limit_per": "api_key"}), appScope, "", ""},
		{"group", withLimitPer(map[string]any{"limit_per": "group"}), groupScope, "", "ratelimit:plugin-1:global:gw-1:grp:grp-1"},
		{"group without a group counts toward its application", withLimitPer(map[string]any{"limit_per": "group"}), noGroup, "", "ratelimit:plugin-1:global:gw-1:app:app-1"},
		{"group selected, in the list", withLimitPer(map[string]any{"limit_per": "group", "applies_to": "selected", "selected": []string{"grp-1"}}), groupScope, "", "ratelimit:plugin-1:global:gw-1:grp:grp-1"},
		{"group selected, outside the list", withLimitPer(map[string]any{"limit_per": "group", "applies_to": "selected", "selected": []string{"grp-1"}}), otherGroup, "", ""},
		{"group selected, no group", withLimitPer(map[string]any{"limit_per": "group", "applies_to": "selected", "selected": []string{"grp-1"}}), noGroup, "", "ratelimit:plugin-1:global:gw-1:app:app-1"},
		{"application without an application", withLimitPer(map[string]any{"limit_per": "application"}), globalScope(), "", ""},
		{"group without a group or an application", withLimitPer(map[string]any{"limit_per": "group"}), globalScope(), "", ""},
		{"model", withLimitPer(map[string]any{"limit_per": "model"}), appScope, `{"model":"@openai/gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:gpt-6-luna"},
		{"model without a model", withLimitPer(map[string]any{"limit_per": "model"}), appScope, `{}`, ""},
		{"model filter glob matches", withLimitPer(map[string]any{"limit_per": "model", "models": []string{"@openai/*"}}), appScope, `{"model":"@openai/gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:gpt-6-luna"},
		{"model filter glob misses", withLimitPer(map[string]any{"limit_per": "model", "models": []string{"claude-*"}}), appScope, `{"model":"@openai/gpt-6-luna"}`, ""},
		{"model filter ignores the provider the request names", withLimitPer(map[string]any{"limit_per": "model", "models": []string{"gpt-6-luna"}}), appScope, `{"model":"@openai/gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:gpt-6-luna"},
		{"model filter ignores the provider a pattern names", withLimitPer(map[string]any{"limit_per": "model", "models": []string{"@anthropic/gpt-6-*"}}), appScope, `{"model":"gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:gpt-6-luna"},
		{"bare model shares the qualified one's counter", withLimitPer(map[string]any{"limit_per": "model"}), appScope, `{"model":"gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:gpt-6-luna"},
		{"a native provider/model id is its own model", withLimitPer(map[string]any{"limit_per": "model"}), appScope, `{"model":"openai/gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:openai%2Fgpt-6-luna"},
		{"model filter exact", withLimitPer(map[string]any{"limit_per": "model", "models": []string{"a", "@openai/gpt-6-luna"}}), appScope, `{"model":"@openai/gpt-6-luna"}`, "ratelimit:plugin-1:global:gw-1:mdl:gpt-6-luna"},
		{"header legacy through limit_per", withLimitPer(map[string]any{"limit_per": "header", "group_by_header": "X-Tenant"}), appScope, "", "ratelimit:plugin-1:global:gw-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, mr := newTestPlugin(t)
			res, err := p.Execute(context.Background(), limitPerInput(tt.settings, tt.scope, tt.body))
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, res.StatusCode)
			if tt.wantKey == "" {
				assert.Empty(t, mr.Keys())
				return
			}
			assert.Equal(t, []string{tt.wantKey}, mr.Keys())
		})
	}
}

func TestPlugin_Execute_LimitPerSeparatesIdentities(t *testing.T) {
	scopeOf := func(app string) appplugins.RuntimeScope {
		s := globalScope()
		s.ConsumerID = app
		return s
	}
	p, _ := newTestPlugin(t)
	settings := withLimitPer(map[string]any{"limit_per": "application"})
	ctx := context.Background()

	_, err := p.Execute(ctx, execInput(settings, scopeOf("app-1")))
	require.NoError(t, err)
	_, err = p.Execute(ctx, execInput(settings, scopeOf("app-2")))
	require.NoError(t, err, "another application has its own counter")
	_, err = p.Execute(ctx, execInput(settings, scopeOf("app-1")))
	require.Error(t, err)
	var perr *appplugins.PluginError
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, http.StatusTooManyRequests, perr.StatusCode)
}

func TestPlugin_ValidateConfig_LimitPer(t *testing.T) {
	tests := []struct {
		name    string
		extra   map[string]any
		wantErr bool
	}{
		{"absent", nil, false},
		{"shared", map[string]any{"limit_per": "shared"}, false},
		{"unknown", map[string]any{"limit_per": "user"}, true},
		{"tool is not offered", map[string]any{"limit_per": "tool"}, true},
		{"application all", map[string]any{"limit_per": "application", "applies_to": "all"}, false},
		{"selected with a list", map[string]any{"limit_per": "group", "applies_to": "selected", "selected": []string{"g"}}, false},
		{"selected with an empty list", map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{}}, true},
		{"selected without a list", map[string]any{"limit_per": "application", "applies_to": "selected"}, true},
		{"a list without selected", map[string]any{"limit_per": "application", "selected": []string{"a"}}, true},
		{"unknown applies_to", map[string]any{"limit_per": "application", "applies_to": "some"}, true},
		{"applies_to all on api key", map[string]any{"limit_per": "api_key", "applies_to": "all"}, false},
		{"applies_to all on shared", map[string]any{"limit_per": "shared", "applies_to": "all"}, false},
		{"applies_to selected on api key", map[string]any{"limit_per": "api_key", "applies_to": "selected", "selected": []string{"a"}}, true},
		{"models on application", map[string]any{"limit_per": "application", "models": []string{"a"}}, true},
		{"header without a name", map[string]any{"limit_per": "header"}, true},
		{"header with a name", map[string]any{"limit_per": "header", "group_by_header": "X-T"}, false},
		{"header name on application", map[string]any{"limit_per": "application", "group_by_header": "X-T"}, true},
		{"legacy group_by_header alone", map[string]any{"group_by_header": "X-T"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := New(nil).ValidateConfig(withLimitPer(tt.extra))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestPlugin_Execute_LimitPerModelCountsTheServedDefault(t *testing.T) {
	p, mr := newTestPlugin(t)
	scope := globalScope()
	in := limitPerInput(withLimitPer(map[string]any{"limit_per": "model"}), scope, `{}`)
	in.Request.DefaultModel = "gpt-default"

	_, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, []string{"ratelimit:plugin-1:global:gw-1:mdl:gpt-default"}, mr.Keys())
}
