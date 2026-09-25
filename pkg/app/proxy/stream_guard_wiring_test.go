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
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/require"
)

// plainExecutor is an executor that never grew the streaming leg, which is what
// keeps the type assertion in newStreamGuard load-bearing.
type plainExecutor struct{}

func (*plainExecutor) RunStage(
	context.Context,
	appplugins.StageInput,
) (*appplugins.StageOutcome, error) {
	return nil, nil
}

// inspectorPlugin answers StreamSettings from its policy settings, as the real
// plugin does: implementing InspectSegment is not by itself the opt-in.
type inspectorPlugin struct{}

func (inspectorPlugin) Name() string { return "guard" }
func (inspectorPlugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}

func (inspectorPlugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreResponse}
}
func (inspectorPlugin) SupportedModes() []policy.Mode { return []policy.Mode{policy.ModeEnforce} }
func (inspectorPlugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}
func (inspectorPlugin) ValidateConfig(map[string]any) error { return nil }
func (inspectorPlugin) MutatesRequestBody() bool            { return false }
func (inspectorPlugin) MutatesResponseBody() bool           { return false }
func (inspectorPlugin) MutatesMetadata() bool               { return false }
func (inspectorPlugin) Execute(context.Context, appplugins.ExecInput) (*appplugins.Result, error) {
	return &appplugins.Result{StatusCode: 200}, nil
}

func (inspectorPlugin) InspectSegment(
	context.Context,
	appplugins.ExecInput,
	appplugins.StreamSegment,
) (*appplugins.SegmentVerdict, error) {
	return nil, nil
}

func (inspectorPlugin) StreamSettings(settings map[string]any) (bool, appplugins.StreamOptions) {
	enabled, _ := settings["enabled"].(bool)
	if !enabled {
		return false, appplugins.StreamOptions{}
	}
	var opts appplugins.StreamOptions
	opts.HeadChars, _ = settings["head_chars"].(int)
	opts.OnError, _ = settings["on_error"].(string)
	return true, opts
}

// segmentExecutor is an executor that did grow the streaming leg, so the
// forwarder's type assertion succeeds and a guard can actually be built.
type segmentExecutor struct{ plainExecutor }

func (*segmentExecutor) RunStreamSegment(
	context.Context,
	appplugins.StageInput,
	appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	return nil, nil
}

func inspectorPlan(t *testing.T, settings map[string]any) *appplugins.StagePlan {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(inspectorPlugin{}))
	return appplugins.NewStagePlan(reg, []*policy.Policy{{
		ID:       ids.New[ids.PolicyKind](),
		Name:     "guard",
		Slug:     "guard",
		Enabled:  true,
		Priority: 10,
		Stages:   []policy.Stage{policy.StagePreResponse},
		Settings: settings,
	}}, newGuardLogger())
}

func wiringDTO(plan *appplugins.StagePlan) *forwardRequestDTO {
	return &forwardRequestDTO{
		request: &infracontext.RequestContext{SourceFormat: string(adapter.FormatOpenAI)},
		plan:    plan,
	}
}

// TestForwarder_StreamGuardIsNotBuiltWithoutAnEnabledInspector is the wiring
// AC: with nothing opted in there is no wrapper at all, not a wrapper that
// happens to pass through. A policy carrying the plugin but with
// streaming.enabled false is the common case — every existing trustguard
// policy is one — and it must build no guard either.
func TestForwarder_StreamGuardIsNotBuiltWithoutAnEnabledInspector(t *testing.T) {
	t.Parallel()
	resp := &infracontext.ResponseContext{}
	enabledPlan := inspectorPlan(t, map[string]any{"enabled": true})
	disabledPlan := inspectorPlan(t, map[string]any{"enabled": false, "head_chars": 32})

	tests := []struct {
		name string
		fwd  *forwarder
		dto  *forwardRequestDTO
	}{
		{
			name: "no executor",
			fwd:  &forwarder{codec: adapter.NewRegistry(), logger: newGuardLogger()},
			dto:  wiringDTO(enabledPlan),
		},
		{
			name: "no codec",
			fwd:  &forwarder{executor: &segmentExecutor{}, logger: newGuardLogger()},
			dto:  wiringDTO(enabledPlan),
		},
		{
			name: "nil plan",
			fwd:  &forwarder{executor: &segmentExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger()},
			dto:  wiringDTO(nil),
		},
		{
			name: "executor without the streaming leg",
			fwd:  &forwarder{executor: &plainExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger()},
			dto:  wiringDTO(enabledPlan),
		},
		{
			name: "policy with streaming disabled",
			fwd:  &forwarder{executor: &segmentExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger()},
			dto:  wiringDTO(disabledPlan),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Nil(t, tc.fwd.newStreamGuard(tc.dto, resp))
		})
	}
}

// TestForwarder_StreamGuardCarriesThePolicyConfig proves head_chars and
// on_error reach the guard. They are validated at policy load, so an operator
// who asks for fail_closed and is given fail_open gets a guard that releases
// text it could not verify.
func TestForwarder_StreamGuardCarriesThePolicyConfig(t *testing.T) {
	t.Parallel()
	fwd := &forwarder{executor: &segmentExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger()}
	dto := wiringDTO(inspectorPlan(t, map[string]any{
		"enabled":    true,
		"head_chars": 37,
		"on_error":   "fail_closed",
	}))

	guard := fwd.newStreamGuard(dto, &infracontext.ResponseContext{})
	require.NotNil(t, guard)
	require.Equal(t, 37, guard.cfg.headChars, "the policy's head_chars is used, not defaultHeadChars")
	require.Equal(t, streamFailClosed, guard.cfg.onError, "the policy's on_error is used, not the fail_open default")
}
