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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
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
	// warnedConfigs dedupes the load-time unknown-model/category warning: a
	// key (policy plugin config id + model + sorted unknown keys) that has
	// already logged is not logged again, so a hot policy does not spam a
	// warning on every request. A different gap on the same config id (the
	// operator edited it) is a new key, so it still warns.
	warnedConfigs sync.Map
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

// ReadsContent opts into being sequenced after any same-priority rewriter, so
// the verdict is scored on the rewritten content (RUN-1693).
func (p *Plugin) ReadsContent() bool { return true }

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects an explicit block_on_flagged: false with no
// thresholds (parseConfig keeps that value as sent, and evaluate() then has
// no path to a violation: the policy would call OpenAI and never act), plus
// an unknown model or an unknown thresholds/categories key for the
// configured model - option "b": only a NEWLY introduced unknown key is
// refused. The same rule applies to streaming.final_pass: false and
// streaming.enabled: false (pluginutil.ValidateStreamingWrite). previous is the settings as they were
// stored before this write (nil on create, or when the write also changes the
// slug: settings that belonged to a different plugin are not "previous" for
// this one). A key
// already present in previous's same field stays editable even though it is
// still not recognised, so a policy saved before this rule (or before this
// build knew a category) does not turn every future edit into a hard
// rejection; a brand new bad key is always refused, model change or not.
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
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
	if err := pluginutil.ValidateStreamingWrite(PluginName, settings, previous); err != nil {
		return err
	}

	var prevCfg Settings
	havePrev := previous != nil
	if havePrev {
		prevCfg, err = parseConfig(previous)
		// A previous version that no longer parses (should not happen: it
		// was valid under the rules current when it was saved, and validate()
		// has not tightened) is treated as no previous at all, so nothing it
		// held is grandfathered in.
		havePrev = err == nil
	}

	if err := validateKnownModel(cfg, prevCfg, havePrev); err != nil {
		return err
	}
	return validateKnownKeys(cfg, prevCfg, havePrev)
}

// validateKnownModel rejects a model this build does not recognise, unless
// it is exactly the model already stored: a saved legacy value stays
// editable rather than blocking every future write to that policy.
func validateKnownModel(cfg, prevCfg Settings, havePrev bool) error {
	if isKnownModel(cfg.Model) {
		return nil
	}
	if havePrev && prevCfg.Model == cfg.Model {
		return nil
	}
	return fmt.Errorf(
		"openai_moderation: unknown model %q; valid models are %s",
		cfg.Model, strings.Join(knownModelNames(), ", "),
	)
}

// validateKnownKeys rejects a thresholds key or categories entry that
// cfg.Model does not recognise, unless the same key already appeared in the
// same field of the previous settings (regardless of whether the model also
// changed - a key kept across a model change is still "pre-existing", not
// new). When cfg.Model is itself unknown (only allowed because it matches a
// stored legacy model), there is no known category set to check keys
// against, so this is a no-op: the model-level warning already covers it.
func validateKnownKeys(cfg, prevCfg Settings, havePrev bool) error {
	known, ok := categoriesForModel(cfg.Model)
	if !ok {
		return nil
	}
	var prevThresholds, prevCategories map[string]struct{}
	if havePrev {
		prevThresholds = make(map[string]struct{}, len(prevCfg.Thresholds))
		for k := range prevCfg.Thresholds {
			prevThresholds[k] = struct{}{}
		}
		prevCategories = make(map[string]struct{}, len(prevCfg.Categories))
		for _, c := range prevCfg.Categories {
			prevCategories[c] = struct{}{}
		}
	}

	bad := make(map[string]struct{})
	for k := range cfg.Thresholds {
		if _, isKnown := known[k]; isKnown {
			continue
		}
		if _, preExisting := prevThresholds[k]; preExisting {
			continue
		}
		bad[k] = struct{}{}
	}
	for _, c := range cfg.Categories {
		if _, isKnown := known[c]; isKnown {
			continue
		}
		if _, preExisting := prevCategories[c]; preExisting {
			continue
		}
		bad[c] = struct{}{}
	}
	if len(bad) == 0 {
		return nil
	}
	names := make([]string, 0, len(bad))
	for k := range bad {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Errorf(
		"openai_moderation: unknown categor%s %s for model %q; valid categories are %s",
		pluralSuffix(len(names)), quoteJoin(names), cfg.Model, strings.Join(sortedCategoryNames(cfg.Model), ", "),
	)
}

func pluralSuffix(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func quoteJoin(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = strconv.Quote(v)
	}
	return strings.Join(quoted, ", ")
}

// CredentialPaths declares the settings paths that hold secrets, so the policy
// API masks them on read.
func (p *Plugin) CredentialPaths() []string {
	return []string{"api_key"}
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, appplugins.FailureConfigInvalid, "", err)
	}
	p.warnUnknownConfig(ctx, in, cfg)

	if !cfg.selectsStage(in.Stage) {
		return passThrough(), nil
	}

	// A streamed response is moderated block by block by the stream guard.
	if in.Stage == policy.StagePreResponse && in.Response != nil && in.Response.Streaming {
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
	if len(violations) == 0 {
		if missing := missingKnownThreshold(cfg, agg); missing != "" {
			return p.externalFailure(ctx, in, cfg, appplugins.FailureVerdictIncomplete, missing,
				fmt.Errorf("openai_moderation: thresholded category %q missing from response", missing))
		}
	}
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

// warnUnknownConfig logs, at most once per distinct (policy plugin config
// id, model, unknown keys) combination, that a stored config names a model
// or a threshold/category key this build does not recognise. It never
// blocks anything - ValidateConfig/Execute still accept the config, exactly
// as they did before this rule - it only gives an operator a chance to
// notice a typo that write-time validation could not have caught (the
// config predates it, or the typo is grandfathered in from a previous
// version). The fingerprint folds in the unknown keys themselves, not just
// the config id, so editing a bad config into a different bad shape warns
// again instead of going silent forever after the first hit.
func (p *Plugin) warnUnknownConfig(ctx context.Context, in appplugins.ExecInput, cfg Settings) {
	if p.logger == nil {
		return
	}
	modelUnknown, badThresholds, badCategories := cfg.unknownAgainstModel()
	if !modelUnknown && len(badThresholds) == 0 && len(badCategories) == 0 {
		return
	}
	fingerprint := strings.Join([]string{
		in.Config.ID, cfg.Model,
		strings.Join(badThresholds, ","),
		strings.Join(badCategories, ","),
	}, "|")
	if _, alreadyWarned := p.warnedConfigs.LoadOrStore(fingerprint, struct{}{}); alreadyWarned {
		return
	}
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("policy_plugin_id", in.Config.ID),
		slog.String("model", cfg.Model),
		slog.Bool("unknown_model", modelUnknown),
	}
	if len(badThresholds) > 0 {
		attrs = append(attrs, slog.Any("unknown_threshold_keys", badThresholds))
	}
	if len(badCategories) > 0 {
		attrs = append(attrs, slog.Any("unknown_category_keys", badCategories))
	}
	p.logger.WarnContext(ctx, "openai moderation config names an unrecognised model or category", attrs...)
}

// externalFailure turns a failed moderation call into a plugin outcome via
// the shared appplugins.HandleExternalFailure: on the buffered leg it always
// fails open (pass through, decision failed_open), in every mode and for every
// reason (RUN-1792). It builds this plugin's own ModerationData so
// failure_reason/failure_detail travel in the same shape as every other
// external guardrail.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	reason appplugins.FailureReason,
	detail string,
	err error,
) (*appplugins.Result, error) {
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:        ctx,
		Plugin:     PluginName,
		Stage:      in.Stage,
		Mode:       in.Mode,
		FailClosed: cfg.OnError == pluginutil.OnErrorFailClosed,
		Reason:     reason,
		Detail:     detail,
		Err:        err,
		Logger:     p.logger,
		Event:      in.Event,
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
