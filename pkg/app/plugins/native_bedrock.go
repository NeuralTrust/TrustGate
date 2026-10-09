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

package plugins

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// BedrockNativePassthrough is the one name of everything the gateway records for
// a native call on behalf of its passthrough: the policy-chain entry of a mask
// that could not be applied, the skip reason of a plugin that does not run, and
// the type of the refusal of a rewrite.
const BedrockNativePassthrough = "native_bedrock_passthrough"

// BedrockNativeBehavior is what a plugin does on a native Bedrock Runtime call,
// which is relayed to Bedrock as the client sent it, so a policy cannot rewrite it
// the way it rewrites a translated one. It is declared in the plugin's descriptor
// (BedrockNativeAware) and applied here and in the executor, in one place:
//
//   - runs: a plugin that only inspects runs, and any change it makes to the bytes
//     is a rewrite for enforcement (a tool filter, a model downgrade, a limit that
//     strips a tool): it cannot be carried out, and the call is refused;
//   - masks: a plugin that masks text runs, and its change is carried onto the bytes
//     the client sent; if that cannot be done safely the mask fails open, recorded with its cause;
//   - skips: a plugin that transforms the request (a template, an injected tool, a
//     compressed prompt, a cache) has nowhere to write and is not run.
type BedrockNativeBehavior string

const (
	BedrockNativeRuns  BedrockNativeBehavior = "runs"
	BedrockNativeSkips BedrockNativeBehavior = "skips"
	BedrockNativeMasks BedrockNativeBehavior = "masks"
)

// BedrockNativeAware is the opt-in a plugin declares to behave differently from
// the default on a native Bedrock call. A plugin that does not implement it runs,
// and is refused if it changes bytes: nothing is exempt by omission, and the
// registry wiring test enumerates the plugins that declare anything.
type BedrockNativeAware interface {
	BedrockNative() BedrockNativeBehavior
}

// BedrockNativeSkipReporter is the opt-in of a plugin that is skipped on native calls
// and has extras of its own that the console renders for its entries: the executor
// records what it returns instead of the generic skipped marker. It returns nil to
// fall back to the marker.
type BedrockNativeSkipReporter interface {
	BedrockNativeSkipExtras(settings map[string]any, stage string) any
}

func BedrockNativeOf(d PluginDescriptor) BedrockNativeBehavior {
	if a, ok := d.(BedrockNativeAware); ok {
		return a.BedrockNative()
	}
	return BedrockNativeRuns
}

// skippedData is the extras of a leg the plugin did not run on. The console
// renders the skipped marker without knowing which plugin wrote it; without it the
// span is dropped by the metrics builder as a no-op.
type skippedData struct {
	Stage      string `json:"stage"`
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skip_reason"`
}

func RecordBedrockNativeSkip(event *metrics.EventContext, stage string) {
	if event == nil {
		return
	}
	event.SetExtras(skippedData{Stage: stage, Skipped: true, SkipReason: BedrockNativePassthrough})
}

func recordNativeSkip(event *metrics.EventContext, entry chainEntry, stage policy.Stage) {
	if reporter, ok := entry.plugin.(BedrockNativeSkipReporter); ok {
		if extras := reporter.BedrockNativeSkipExtras(entry.config.Settings, string(stage)); extras != nil {
			if event != nil {
				event.SetExtras(extras)
			}
			return
		}
	}
	RecordBedrockNativeSkip(event, string(stage))
}

// NativeRewriteRefusal is the refusal of a change a plugin that does not mask made
// to a native call: it cannot be carried out, and forwarding the original would let
// through what the plugin removed.
func NativeRewriteRefusal(plugin string, stage policy.Stage) *PluginError {
	return &PluginError{
		StatusCode: http.StatusForbidden,
		Type:       BedrockNativePassthrough,
		Message: fmt.Sprintf("policy %s would rewrite the %s of a native Bedrock call, which is relayed as sent; the call is refused",
			plugin, rewriteSubject(stage)),
	}
}

func rewriteSubject(stage policy.Stage) string {
	if stage == policy.StagePreResponse {
		return "response"
	}
	return "request"
}

const FailureMaskNotApplicable = "mask_not_applicable"

// NativeMaskData is the extras of the policy-chain entry a mask that could not be
// applied gets. It is the shape every fail-open outcome of this codebase records:
// decision failed_open and a failure_reason.
type NativeMaskData struct {
	Decision      string `json:"decision"`
	Stage         string `json:"stage"`
	Mode          string `json:"mode"`
	FailureReason string `json:"failure_reason"`
	Streamed      bool   `json:"streamed,omitempty"`
}

func NativeMaskFailureReason(cause adapter.MaskCause) string {
	return FailureMaskNotApplicable + ":" + string(cause)
}

// RecordNativeMaskNotApplied records, as a failed-open policy outcome, that a
// native Bedrock call went through unmasked because the mask a policy asked for
// could not be applied safely. It writes one entry onto the request trace, the
// same way a failing external guardrail does, so the console shows it in the
// policy chain, and emits one Warn log. The caller decides how often it is
// called: once per kind of cause per request or stream.
func RecordNativeMaskNotApplied(
	ctx context.Context,
	logger *slog.Logger,
	stage policy.Stage,
	cause adapter.MaskCause,
	streamed bool,
) {
	reason := NativeMaskFailureReason(cause)
	if rt := trace.FromContext(ctx); rt != nil {
		span := rt.StartSpan(trace.SpanPlugin, BedrockNativePassthrough)
		span.SetStage(string(stage))
		event := metrics.NewEventContext(span)
		event.SetMode(string(policy.ModeEnforce))
		SetDecisionFromOutcome(event, DecisionFailedOpen)
		event.SetStatusCode(http.StatusOK)
		event.SetExtras(&NativeMaskData{
			Decision:      DecisionFailedOpen,
			Stage:         string(stage),
			Mode:          string(policy.ModeEnforce),
			FailureReason: reason,
			Streamed:      streamed,
		})
		event.Publish()
	}
	if logger == nil {
		return
	}
	logger.WarnContext(ctx, "native bedrock mask could not be applied; the call goes through unmasked",
		slog.String("stage", string(stage)),
		slog.String("decision", DecisionFailedOpen),
		slog.String("failure_reason", reason),
		slog.Bool("streamed", streamed))
}
