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

package prompttemplate

import (
	"context"
	"fmt"
	"net/http"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "prompt_template"

const (
	typeVariableUnresolved = "template_variable_unresolved"
	typeVariableMissing    = "template_variable_missing"
	typeVariableInvalid    = "template_variable_invalid"
	typeNotFound           = "template_not_found"
	typeRequired           = "template_required"
	typeAmbiguous          = "template_ambiguous"
	typeRenderFailed       = "template_render_failed"
	typeUnsupportedShape   = "unsupported_request_shape"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct{}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return PluginName }

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

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

// RewritesLocally opts into running ahead of the same-priority rewriters that
// send content to a third party: what this plugin rewrites never leaves the
// gateway (RUN-1745).
func (p *Plugin) RewritesLocally() bool { return true }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

func (p *Plugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil {
		return okResult(), nil
	}

	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}

	rb, err := decodeBody(in.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}

	properties, hadProperties := rb.takeProperties()

	if skip := rb.applyFormat(in.Request.Provider, in.Request.SourceFormat, in.Request.MCP, in.Request.Body); skip != nil {
		return skipRequest(in, cfg, skip, rb, hadProperties)
	}

	modeA := len(cfg.InjectTemplates) > 0
	modeB := len(cfg.NamedTemplates) > 0
	ctxVars, _ := resolveContextVars(cfg, in.Request)

	if !appplugins.Blocks(in.Mode) {
		aOutcome, bOutcome, _ := runModes(cfg, rb.clone(), properties, ctxVars, modeA, modeB)
		bOutcome.markUnscanned(modeB, in.Request.Body)
		setExtras(in.Event, observeData(aOutcome, bOutcome))
		appplugins.SetDecision(in.Event, in.Mode)
		return forwardOrNoOp(rb, hadProperties, false)
	}

	pristine := rb.clone()
	aOutcome, bOutcome, runErr := runModes(cfg, rb, properties, ctxVars, modeA, modeB)
	bOutcome.markUnscanned(modeB, in.Request.Body)
	if runErr != nil {
		if bOutcome.shapeReason != "" {
			setExtras(in.Event, PromptTemplateData{
				Decision:                   decisionSkippedShape,
				SkippedReason:              bOutcome.shapeReason,
				UnscannedTemplateReference: bOutcome.unscannedRef,
			})
			return nil, runErr
		}
		setExtras(in.Event, rejectionData(aOutcome, bOutcome))
		return nil, runErr
	}
	if reason, blocked := blockingUnapplied(aOutcome.unapplied); blocked {
		// An injection that could not be placed because of the client's own body
		// (an unreadable system field, say) is the client choosing to skip the
		// operator's prompt, so the request is refused. Reasons that come from
		// the operator's config are forwarded and reported.
		// The request is not forwarded, so the event carries no injected ids and
		// no Mode B fields: nothing was applied.
		setExtras(in.Event, PromptTemplateData{
			Decision:                   decisionSkippedShape,
			SkippedReason:              reason,
			Unapplied:                  aOutcome.unapplied,
			UnscannedTemplateReference: bOutcome.unscannedRef,
		})
		return nil, rejectUnsupportedShape(reason)
	}
	if rb.dirty() && rb.format != "" {
		// An edited body the adapter could read two ways, for example a key
		// that folds to a field this plugin wrote, would let the client's copy
		// win and drop the injection while the event reported it. Forward the
		// original instead.
		if edited, err := rb.marshal(); err == nil && adapter.HasAmbiguousKeys(rb.format, edited) {
			return skipRequest(in, cfg, &passThrough{decision: decisionSkippedShape, reason: "ambiguous_after_edit"}, pristine, hadProperties)
		}
	}

	setExtras(in.Event, enforceData(aOutcome, bOutcome))
	return forwardOrNoOp(rb, hadProperties, rb.dirty())
}

// skipRequest handles a request the plugin leaves untouched. In enforce mode a
// policy that requires a template reference rejects it, since it cannot carry
// one the plugin can read; otherwise it is forwarded as received (properties
// stripped), with the reason recorded.
func skipRequest(in appplugins.ExecInput, cfg *config, skip *passThrough, rb *requestBody, hadProperties bool) (*appplugins.Result, error) {
	data := PromptTemplateData{
		Decision:                   skip.decision,
		SkippedReason:              skip.reason,
		UnscannedTemplateReference: len(cfg.NamedTemplates) > 0 && hasTemplateReference(in.Request.Body),
	}
	if appplugins.Blocks(in.Mode) && skip.decision == decisionSkippedShape && hasTemplates(cfg) {
		// A chat request whose body the policy cannot edit would otherwise go to
		// the model without the prompt the operator configured, and a client
		// could choose that by shaping its body. The event keeps the skip
		// decision and reason rather than no_op: the policy did not run.
		setExtras(in.Event, data)
		return nil, rejectUnsupportedShape(skip.reason)
	}
	if appplugins.Blocks(in.Mode) && len(cfg.NamedTemplates) > 0 && !cfg.AllowUntemplatedRequests {
		// Refused exactly as a request with no reference is. The decision is the
		// one that rejection records (no_op); skipped_reason says why.
		data.Decision = decisionNoOp
		setExtras(in.Event, data)
		return nil, reject(http.StatusBadRequest, typeRequired, "request does not reference a template")
	}
	setExtras(in.Event, data)
	if !appplugins.Blocks(in.Mode) {
		appplugins.SetDecision(in.Event, in.Mode)
	}
	return forwardOrNoOp(rb, hadProperties, false)
}

func hasTemplates(cfg *config) bool {
	return len(cfg.InjectTemplates) > 0 || len(cfg.NamedTemplates) > 0
}

func rejectUnsupportedShape(reason string) error {
	return reject(http.StatusBadRequest, typeUnsupportedShape,
		fmt.Sprintf("request body cannot be edited by the prompt template policy (%s)", reason))
}

func forwardOrNoOp(rb *requestBody, hadProperties, mutated bool) (*appplugins.Result, error) {
	if !hadProperties && !mutated {
		return okResult(), nil
	}
	out, err := rb.marshal()
	if err != nil {
		return nil, fmt.Errorf("prompt_template: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: out}, nil
}

func runModes(cfg *config, rb *requestBody, properties map[string]any, ctxVars map[string]string, modeA, modeB bool) (modeAOutcome, modeBResult, error) {
	var bOutcome modeBResult
	if modeB {
		var err error
		bOutcome, err = applyModeB(cfg, rb, properties, ctxVars)
		if err != nil {
			return modeAOutcome{}, bOutcome, err
		}
	}

	var aOutcome modeAOutcome
	if modeA {
		aOutcome = applyModeA(cfg, rb, ctxVars)
		if cfg.OnMissingContextVariable == onMissingContextError && len(aOutcome.unresolved) > 0 {
			// The variable is missing because the caller omitted the header or the
			// claim it comes from, so this is their error to fix, as it already is
			// for a missing client variable in mode B.
			return aOutcome, bOutcome, reject(
				http.StatusBadRequest,
				typeVariableUnresolved,
				fmt.Sprintf("context variable %q could not be resolved", aOutcome.unresolved[0]),
			)
		}
	}
	return aOutcome, bOutcome, nil
}

func buildData(decision string, a modeAOutcome, b modeBResult) PromptTemplateData {
	return PromptTemplateData{
		Decision:               decision,
		InjectedIDs:            a.injected,
		Unapplied:              a.unapplied,
		SkippedIDs:             a.skipped,
		UnresolvedIDs:          a.unresolved,
		ResolvedTemplate:       b.resolvedTemplate,
		DiscardedMessages:      b.discarded,
		DroppedClientVariables: b.droppedClientVars,

		UnscannedTemplateReference: b.unscannedRef,
	}
}

func enforceData(a modeAOutcome, b modeBResult) PromptTemplateData {
	decision := decisionNoOp
	switch {
	case a.changed:
		decision = decisionInjected
	case b.changed:
		decision = decisionRendered
	case len(a.skipped) > 0:
		decision = decisionSkipped
	}
	return buildData(decision, a, b)
}

func observeData(a modeAOutcome, b modeBResult) PromptTemplateData {
	return buildData(decisionObserved, a, b)
}

func rejectionData(a modeAOutcome, b modeBResult) PromptTemplateData {
	return buildData(decisionNoOp, a, b)
}

func reject(status int, errType, message string) error {
	return &appplugins.PluginError{
		StatusCode: status,
		Type:       errType,
		Message:    message,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
	}
}

func setExtras(event *metrics.EventContext, data PromptTemplateData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

func okResult() *appplugins.Result { return &appplugins.Result{StatusCode: http.StatusOK} }
