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

package openaimoderation

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	inputTypeText = "text"

	decisionBlock    = "block"
	decisionReported = "reported"
	decisionAllowed  = "allowed"
)

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	baseURL  string
	logger   *slog.Logger
}

func New(registry *adapter.Registry, baseURL string, timeout time.Duration, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		client:   newClient(timeout),
		baseURL:  baseURL,
		logger:   logger,
	}
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *Plugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) MutatesRequestBody() bool { return false }

func (p *Plugin) MutatesResponseBody() bool { return false }

func (p *Plugin) MutatesMetadata() bool { return false }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects an explicit block_on_flagged: false with no
// thresholds. parseConfig keeps that value as sent, and evaluate() then has
// no path to a violation: the policy would call OpenAI and never act.
func (p *Plugin) ValidateSettingsWrite(settings map[string]any) error {
	cfg, err := parseConfig(settings)
	if err != nil {
		return err
	}
	if len(cfg.Thresholds) == 0 && !cfg.BlockOnFlagged {
		return fmt.Errorf(
			"openai_moderation: block_on_flagged is explicitly false with no thresholds configured; " +
				"this policy could never block or report a violation - set thresholds or block_on_flagged: true",
		)
	}
	return nil
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, appplugins.FailureConfigInvalid, "", err)
	}

	if !cfg.selectsStage(in.Stage) {
		return passThrough(), nil
	}

	// Not a policy-level failure: the gateway operator never configured an
	// OpenAI base URL for this deployment, so there is nowhere to call.
	// Left as a silent pass-through rather than routed through the failure
	// helper — see the RUN-1672 report.
	if p.baseURL == "" {
		p.warn(ctx, "openai moderation base url not configured",
			slog.String("plugin", PluginName),
			slog.String("stage", string(in.Stage)),
		)
		return passThrough(), nil
	}

	if in.Request == nil || p.registry == nil || in.Request.Provider == "" {
		return passThrough(), nil
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, appplugins.FailureDecodeFailed, "", err)
	}

	text, decErr := p.extractText(in, format)
	if decErr != nil {
		return p.externalFailure(ctx, in, cfg, appplugins.FailureDecodeFailed, "", decErr)
	}
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	req := moderationRequest{
		Model: cfg.Model,
		Input: []moderationInput{{Type: inputTypeText, Text: text}},
	}

	resp, err := p.client.Moderate(ctx, p.baseURL, cfg.APIKey, req)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, appplugins.FailureTransport, "", err)
	}
	if len(resp.Results) == 0 {
		return p.externalFailure(ctx, in, cfg, appplugins.FailureVerdictIncomplete, "",
			fmt.Errorf("moderations response carried no results"))
	}

	agg := aggregate(resp.Results)
	violations := evaluate(cfg, agg)
	topCategory, topScore := maxScore(agg)

	data := ModerationData{
		Model:             cfg.Model,
		CategoryScores:    agg.scores,
		MaxScore:          topScore,
		MaxScoreCategory:  topCategory,
		FlaggedByOpenAI:   agg.anyFlagged,
		FlaggedCategories: violations,
	}

	if len(violations) > 0 && appplugins.Blocks(in.Mode) {
		data.Decision = decisionBlock
		setExtras(in.Event, data)
		recordScore(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionBlock)
		return nil, blockError(cfg.Action.Message, violations)
	}

	if len(violations) > 0 {
		data.Decision = decisionReported
	} else {
		data.Decision = decisionAllowed
	}
	setExtras(in.Event, data)
	if len(violations) > 0 {
		recordScore(in.Event, data)
	}
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	return passThrough(), nil
}

// extractText returns the text to moderate, or a non-nil error when decoding
// the request/response body failed outright — as opposed to there simply
// being nothing to moderate (nil response, a streamed leg, an empty body, or
// a nil canonical value), which returns ("", nil): nothing to evaluate is not
// a failure.
func (p *Plugin) extractText(in appplugins.ExecInput, format adapter.Format) (string, error) {
	if in.Stage == policy.StagePreResponse {
		if in.Response == nil || in.Response.Streaming || len(in.Response.Body) == 0 {
			return "", nil
		}
		cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
		if err != nil {
			return "", err
		}
		if cresp == nil {
			return "", nil
		}
		return responseText(cresp), nil
	}
	if len(in.Request.Body) == 0 {
		return "", nil
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil {
		return "", err
	}
	if creq == nil {
		return "", nil
	}
	return joinRequestText(creq), nil
}

func (p *Plugin) warn(ctx context.Context, msg string, attrs ...any) {
	if p.logger == nil {
		return
	}
	p.logger.WarnContext(ctx, msg, attrs...)
}

// externalFailure turns a failed moderation call into a plugin outcome via
// the shared appplugins.HandleExternalFailure: fail closed (502
// guardrail_unavailable) in a blocking mode, fail open (pass through) in
// observe, or always fail open for a decode_failed reason. It builds this
// plugin's own ModerationData so failure_reason/failure_detail travel in the
// same shape as every other external guardrail.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	reason appplugins.FailureReason,
	detail string,
	err error,
) (*appplugins.Result, error) {
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:    ctx,
		Plugin: PluginName,
		Stage:  in.Stage,
		Mode:   in.Mode,
		Reason: reason,
		Detail: detail,
		Err:    err,
		Logger: p.logger,
		Event:  in.Event,
	})
	setExtras(in.Event, ModerationData{
		Model:         cfg.Model,
		Decision:      outcome.Decision,
		FailureReason: string(reason),
		FailureDetail: detail,
	})
	return outcome.Result, outcome.Err
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
