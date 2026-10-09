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

package proxy

import (
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/trustguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ENG-1735: regex_replace joins every response-target stream by default with
// on_error fail_closed. It sorts before trustguard here, and must not decide the
// stream's cadence. Its fail_closed holds beside the guardrail, because the
// guard resolves on_error only for an error the executor hands back, which only
// an entry that asked for fail_closed does: trustguard's own failures are
// absorbed and fail open either way.
func TestForwarder_StreamGuardOptionsBelongToTheGuardNotTheRegexRewriter(t *testing.T) {
	t.Parallel()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(regexreplace.New(adapter.NewRegistry(), nil)))
	require.NoError(t, reg.Register(trustguard.New(adapter.NewRegistry(), "http://localhost", time.Second, "id", "secret", newGuardLogger())))
	pre := []policy.Stage{policy.StagePreResponse}
	pols := []*policy.Policy{
		{
			ID: ids.New[ids.PolicyKind](), Name: regexreplace.PluginName, Slug: regexreplace.PluginName,
			Enabled: true, Priority: 1, Stages: pre, Mode: policy.ModeEnforce,
			Settings: map[string]any{
				"target": "response",
				"rules":  []map[string]any{{"pattern": `\d{16}`, "replacement": "[CARD]"}},
			},
		},
		{
			ID: ids.New[ids.PolicyKind](), Name: "trustguard", Slug: "trustguard",
			Enabled: true, Priority: 2, Stages: pre, Mode: policy.ModeEnforce,
			Settings: map[string]any{
				"collector_id": "11111111-1111-4111-8111-111111111111",
				"direction":    "response",
				"streaming":    map[string]any{"head_chars": 77, "max_hold_ms": 333},
			},
		},
	}
	plan := appplugins.NewStagePlan(reg, pols, newGuardLogger())
	fwd := &forwarder{executor: &segmentExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger()}

	guard := fwd.newStreamGuard(wiringDTO(plan), &infracontext.ResponseContext{})

	require.NotNil(t, guard)
	assert.Equal(t, streamFailClosed, guard.cfg.onError, "regex_replace's fail_closed holds beside a guardrail")
	assert.Equal(t, 77, guard.cfg.headChars)
	assert.Equal(t, 333*time.Millisecond, guard.cfg.maxHold)

	alone := fwd.newStreamGuard(wiringDTO(appplugins.NewStagePlan(reg, pols[:1], newGuardLogger())), &infracontext.ResponseContext{})
	require.NotNil(t, alone, "a regex policy alone still guards the stream")
	assert.Equal(t, streamFailClosed, alone.cfg.onError)
}
