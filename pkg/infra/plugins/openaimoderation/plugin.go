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
	"errors"
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
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	inputTypeText = "text"

	decisionBlock    = "block"
	decisionReported = "reported"
	decisionAllowed  = "allowed"
)

// The moderation endpoint documents no input size or token limit and no
// maximum array length, so a text is split into requests of chunkBytes, the
// size the stream leg sends, one text per request: what
// an array of texts yields (one combined result or one per item) is
// undocumented. Bytes are never fewer than characters or tokens. The
// overlap is 4,096 bytes, enough for a long secret (a PEM key, a service-account
// JSON of about 3.5 KB) to lie whole in one chunk; a pattern longer than it, or
// a context that a cut separates by more than it, can still be cut in two. A
// text is evaluated when its estimate, one callReserve per round of evalParallel
// requests, is at most half of the client's timeout for the whole evaluation:
// that is the ceiling, at most maxChunks, 12 at the default 15 s, and a text above
// it is refused before any call as chunk_limit. The headroom lets OpenAI answer
// up to twice as slowly as callReserve, about twice a call's usual latency, on
// every round without the budget cutting a chunk. A chunk that is not started or
// is cut by the budget is availability only when some call took longer than twice
// callReserve, and otherwise chunk_budget, input: the request's own size used the
// time. OpenAI meters tokens per minute per tier, which the gateway cannot see,
// so a rate limit on a chunk of the first round is retried once, and if it
// persists it is other traffic on the first chunk or on a single-chunk text and
// fails open, and input (throttled_oversize) on any other chunk, which the
// request's own calls beside or before it may have throttled. An exhausted
// account (insufficient_quota, billing_hard_limit_reached) is configuration, not
// a rate, and fails open.
// https://developers.openai.com/api/docs/guides/moderation
const (
	chunkBytes   = 32768
	chunkOverlap = 4096
	maxChunks    = 32
	evalParallel = 4
	callReserve  = 2 * time.Second
)

var chunkSpec = textchunk.Spec{Max: chunkBytes, Overlap: chunkOverlap, Unit: textchunk.Bytes}

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
// refused. The same rule applies to streaming.final_pass: false
// (pluginutil.ValidateFinalPassWrite). previous is the settings as they were
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
	if err := pluginutil.ValidateFinalPassWrite(PluginName, settings, previous); err != nil {
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
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, "", err)
	}
	p.warnUnknownConfig(ctx, in, cfg)

	if !cfg.selectsStage(in.Stage) {
		return passThrough(), nil
	}

	// A streamed response is moderated block by block by the stream guard when
	// streaming is enabled for this policy. When it is not, the response goes
	// out unmoderated and the trace says so, rather than omitting the policy.
	if in.Stage == policy.StagePreResponse && in.Response != nil && in.Response.Streaming {
		if !cfg.Streaming.IsEnabled() {
			pluginutil.RecordStreamingDisabled(in.Event, string(in.Stage))
		}
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
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, err)
	}

	if in.Stage == policy.StagePreResponse && pluginutil.SkipWithoutCompletion(in.Event, string(in.Stage), in.Response) {
		return passThrough(), nil
	}

	text, decErr := p.extractText(in, format)
	if decErr != nil {
		if in.Stage == policy.StagePreResponse {
			pluginutil.RecordSkipped(in.Event, string(in.Stage), pluginutil.SkipReasonUndecodableResponse)
			return passThrough(), nil
		}
		if pluginutil.SkipNonChatRoute(in.Event, string(in.Stage), in.Request.ProxyCapability, format) {
			return passThrough(), nil
		}
		if !adapter.IsRequestDecodeError(decErr) {
			return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, decErr)
		}
		return p.externalFailure(ctx, in, cfg, 0, appplugins.FailureDecodeFailed, "", decErr)
	}
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}

	limit := textchunk.MaxChunks(maxChunks, evalParallel, callReserve, p.client.timeout)
	if n := textchunk.Count(text, chunkSpec); n > limit {
		return p.externalFailure(ctx, in, cfg, n, appplugins.FailureInputTooLarge, appplugins.DetailChunkLimit,
			fmt.Errorf("openai_moderation: the text splits into %d chunks, above the %d evaluated", n, limit))
	}
	chunks := textchunk.Split(text, chunkSpec)

	budget, cancel := context.WithTimeout(ctx, p.client.timeout)
	defer cancel()
	slow := textchunk.SlowCallOf(budget, callReserve)
	verdicts := make([]chunkVerdict, len(chunks))
	outs := textchunk.Run(budget, chunks, textchunk.RunOptions{
		Parallel: evalParallel,
		Reserve:  callReserve,
		StopOn:   func(i int) bool { return appplugins.Blocks(in.Mode) && len(verdicts[i].violations) > 0 },
	}, func(ctx context.Context, i int, c textchunk.Chunk) (struct{}, error) {
		resp, err := pluginutil.RetryFirstRoundThrottle(ctx, i, evalParallel, func(ctx context.Context) (*moderationResponse, error) {
			return p.client.Moderate(ctx, p.baseURL, cfg.APIKey, moderationRequest{
				Model: cfg.Model,
				Input: []moderationInput{{Type: inputTypeText, Text: c.Text}},
			})
		})
		if err != nil {
			return struct{}{}, err
		}
		verdicts[i] = readChunk(cfg, resp)
		return struct{}{}, nil
	})

	chunkState := func(i int, _ struct{}, err error) appplugins.ChunkState {
		if err != nil {
			reason, detail := pluginutil.FailureOfError(err)
			return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{Reason: reason, Detail: detail}}
		}
		if len(verdicts[i].violations) > 0 {
			return appplugins.ChunkState{Blocks: true}
		}
		if verdicts[i].failure != nil {
			return appplugins.ChunkState{Failure: verdicts[i].failure}
		}
		return appplugins.ChunkState{}
	}
	decision := appplugins.ClassifyChunks(outs, errors.Is(ctx.Err(), context.Canceled), chunkState,
		appplugins.SlowCall(slow))
	if decision.Kind == appplugins.ChunkInputFailure || decision.Kind == appplugins.ChunkAvailabilityFailure {
		return p.externalFailure(ctx, in, cfg, len(chunks), decision.Reason, decision.Detail,
			fmt.Errorf("openai_moderation: chunk %d of %d: %s", decision.Index+1, len(chunks), failureText(decision, outs)))
	}

	var results []moderationResult
	for i, out := range outs {
		if out.Started && out.Err == nil {
			results = append(results, verdicts[i].results...)
		}
	}
	agg := aggregate(results)
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
	if len(chunks) > 1 {
		data.ChunkCount = len(chunks)
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

// chunkVerdict is what OpenAI said about one chunk: its results, the violations
// they make on their own, and the failure of an answer that cannot be read as a
// verdict.
type chunkVerdict struct {
	results    []moderationResult
	violations []violation
	failure    *appplugins.ChunkFailure
}

func readChunk(cfg Settings, resp *moderationResponse) chunkVerdict {
	if len(resp.Results) == 0 {
		return chunkVerdict{failure: &appplugins.ChunkFailure{Reason: appplugins.FailureVerdictIncomplete}}
	}
	agg := aggregate(resp.Results)
	v := chunkVerdict{results: resp.Results, violations: evaluate(cfg, agg)}
	if len(v.violations) == 0 {
		if missing := missingKnownThreshold(cfg, agg); missing != "" {
			v.failure = &appplugins.ChunkFailure{Reason: appplugins.FailureVerdictIncomplete, Detail: missing}
		}
	}
	return v
}

func failureText(d appplugins.ChunkDecision, outs []textchunk.Outcome[struct{}]) string {
	if d.Index >= 0 && d.Index < len(outs) && outs[d.Index].Err != nil {
		return outs[d.Index].Err.Error()
	}
	return d.Detail
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
// the shared appplugins.HandleExternalFailure, which owns the class and the
// mode: an availability failure passes through as failed_open, and an input
// failure is refused in a mode that blocks. It builds this plugin's own
// ModerationData so failure_reason/failure_detail/failure_class travel in the
// same shape as every other external guardrail.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	chunks int,
	reason appplugins.FailureReason,
	detail string,
	err error,
) (*appplugins.Result, error) {
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:     ctx,
		Plugin:  PluginName,
		Stage:   in.Stage,
		Mode:    in.Mode,
		Reason:  reason,
		Detail:  detail,
		Message: cfg.Action.Message,
		Err:     err,
		Logger:  p.logger,
		Event:   in.Event,
	})
	data := ModerationData{
		Model:         cfg.Model,
		Decision:      outcome.Decision,
		FailureReason: string(reason),
		FailureDetail: detail,
		FailureClass:  string(outcome.Class),
	}
	if chunks > 1 {
		data.ChunkCount = chunks
	}
	setExtras(in.Event, data)
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
