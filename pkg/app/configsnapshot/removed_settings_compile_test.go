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

package configsnapshot_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A policy stored with the keys the guardrails lost is published without them, so
// a data plane on an older release cannot honour a stored fail_closed, a block or
// a 1ms timeout that the console no longer offers. The stored policy is untouched.
func TestCompilerStripsRemovedGuardrailSettings(t *testing.T) {
	gw := mustGatewayID(t, "11111111-1111-1111-1111-111111111111")
	stored := map[string]any{
		"collector_id":    "c-1",
		"on_error":        "fail_closed",
		"on_timeout":      "fail_closed",
		"timeout":         "1ms",
		"on_mask_failure": "block",
		"streaming":       map[string]any{"enabled": true, "on_error": "fail_closed", "guard_timeout": "1ms"},
	}
	rewriter := map[string]any{
		"target":          "response",
		"on_mask_failure": "block",
		"streaming":       map[string]any{"enabled": true, "on_error": "fail_closed"},
	}
	policies := []*policydomain.Policy{
		{ID: ids.New[ids.PolicyKind](), GatewayID: gw, Slug: "trustguard", Settings: stored},
		{ID: ids.New[ids.PolicyKind](), GatewayID: gw, Slug: "regex_replace", Settings: rewriter},
	}

	compiler := appsnapshot.NewCompiler(
		fakeGateways{items: []*gatewaydomain.Gateway{{ID: gw}}},
		fakeConsumers{byGateway: map[string][]*consumerdomain.Consumer{}},
		fakeRegistries{byGateway: map[string][]*registrydomain.Registry{}},
		fakePolicies{byGateway: map[string][]*policydomain.Policy{gw.String(): policies}},
		fakeAuths{byGateway: map[string][]*authdomain.Auth{}},
		fakeCatalog{providers: []catalogdomain.Provider{{Code: "openai"}}},
		nil,
	)

	snapshot, err := compiler.Compile(context.Background())
	require.NoError(t, err)

	got := map[string]map[string]any{}
	for _, p := range snapshot.Data().Policies {
		got[p.Slug] = p.Settings
	}
	assert.Equal(t, map[string]any{"collector_id": "c-1", "streaming": map[string]any{"enabled": true}}, got["trustguard"])
	assert.Equal(t, map[string]any{
		"target":    "response",
		"streaming": map[string]any{"enabled": true, "on_error": "fail_closed"},
	}, got["regex_replace"], "regex_replace keeps its fail-closed stream")
	assert.Equal(t, "fail_closed", stored["on_error"], "the stored policy is not edited")
}
