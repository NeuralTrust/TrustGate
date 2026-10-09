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

package azurecontentsafety

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "azure_content_safety"

const (
	decisionBlocked  = "blocked"
	decisionReported = "reported"
	decisionAllowed  = "allowed"
)

// The text:analyze limit is "10K characters (split longer texts as needed)".
// What a character is stays undocumented, so a chunk is capped in UTF-16 code
// units, which are never fewer than code points or characters. The overlap is
// 2,000 units, so a pattern of up to 2,000 units lies whole in one chunk. A
// secret above that, a PEM key or a service-account JSON of about 3.5 KB, can be
// cut in two (the other guardrails share 4,096 bytes and keep those whole), and
// so can a context that a cut separates by more than the overlap. A conversation
// above the ceiling is refused before any call as chunk_limit, so a padded request
// costs nothing at Azure. The ceiling is what half of one evaluationBudget admits
// at evalParallel calls at once and callReserve a round, at most maxChunks: 60 at
// the 30 s budget. The headroom lets Azure answer up to twice as slowly as
// callReserve, about twice a call's usual latency, without the budget cutting a
// chunk. A chunk that is not started or is cut by the budget is availability only
// when some call took longer than twice callReserve, and otherwise chunk_budget,
// input. The free tier (F0) allows 5 requests a second, so a long conversation
// throttles itself there. A throttle on a chunk of the first round is retried
// once; if it persists on the first chunk or on a single-chunk
// conversation it is other traffic and fails open, with every other throttle of
// the conversation, and otherwise it is input (throttled_oversize) on a later
// chunk, because the request's own calls beside or before it plausibly used the
// quota.
// https://learn.microsoft.com/en-us/azure/ai-services/content-safety/region-availability#service-limits
// https://learn.microsoft.com/en-us/azure/ai-services/content-safety/overview#query-rates
const (
	chunkUnits   = 10000
	chunkOverlap = 2000
	maxChunks    = 64
	evalParallel = 4
	callReserve  = time.Second
)

// evaluationBudget is the time one evaluation has for all of its chunks. It is
// not a call's timeout: every call keeps defaultTimeout, so a provider that
// hangs fails the evaluation open after about one call and not after the whole
// budget. It sets the ceiling (see above): 15 s of admitted estimate at one
// second a round of four calls is 60 chunks, about 490,000 UTF-16 units, or
// about 120,000 tokens.
const evaluationBudget = 30 * time.Second

var chunkSpec = textchunk.Spec{Max: chunkUnits, Overlap: chunkOverlap, Unit: textchunk.UTF16}

var _ appplugins.Plugin = (*Plugin)(nil)

type Plugin struct {
	registry *adapter.Registry
	client   *client
	logger   *slog.Logger
	budget   time.Duration
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry: registry,
		client:   newClient(),
		logger:   logger,
		budget:   evaluationBudget,
	}
}

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

// ValidateSettingsWrite rejects a category_severity key that names a
// category not requested in categories, and an endpoint that does not carry the
// api-version query parameter. Neither can live in parseConfig (run via
// ValidateConfig on every load): a policy saved before the rule existed would
// turn into a run-time config_invalid failure the moment it did.
// Execute instead requests the union of categories and category_severity's
// keys (Settings.requestCategories) so an already-saved mismatched policy
// keeps working; this only stops a new one from being saved with the same
// gap. The api-version is checked only when the endpoint is new or changed, so
// editing any other setting of a stored policy is never refused for it.
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
	cfg, err := parseConfig(settings)
	if err != nil {
		return err
	}
	if endpointChanged(cfg.Endpoint, previous) && !carriesAPIVersion(cfg.Endpoint) {
		return fmt.Errorf("azure_content_safety: endpoint must carry the api-version query parameter")
	}
	if missing := cfg.unrequestedThresholds(); len(missing) > 0 {
		return fmt.Errorf(
			"azure_content_safety: category_severity key %q is not in categories", missing[0],
		)
	}
	return nil
}

func endpointChanged(endpoint string, previous map[string]any) bool {
	before, ok := previous["endpoint"].(string)
	return !ok || before != endpoint
}

// carriesAPIVersion reports whether the endpoint's query names an api-version
// with a value; the parameter name is matched without regard to case.
func carriesAPIVersion(endpoint string) bool {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	for key, values := range parsed.Query() {
		if !strings.EqualFold(key, "api-version") {
			continue
		}
		for _, v := range values {
			if v != "" {
				return true
			}
		}
	}
	return false
}

// CredentialPaths declares the settings paths that hold secrets, so the policy
// API masks them on read.
func (p *Plugin) CredentialPaths() []string {
	return []string{"api_key"}
}

// CredentialDestinations binds api_key to the endpoint it is sent to
// (Ocp-Apim-Subscription-Key on a request to cfg.Endpoint): changing the
// endpoint requires re-entering the key.
func (p *Plugin) CredentialDestinations() []string {
	return []string{"endpoint"}
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, "", err)
	}

	if in.Stage != policy.StagePreRequest {
		return passThrough(), nil
	}
	if in.Request == nil || p.registry == nil || in.Request.Provider == "" || len(in.Request.Body) == 0 {
		return passThrough(), nil
	}

	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, err)
	}
	creq, decErr := p.registry.DecodeRequestFor(in.Request.Body, format)
	if decErr != nil {
		if pluginutil.SkipNonChatRoute(in.Event, string(in.Stage), in.Request.ProxyCapability, format) {
			return passThrough(), nil
		}
		if !adapter.IsRequestDecodeError(decErr) {
			return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, decErr)
		}
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureDecodeFailed, "", decErr)
	}
	if creq == nil {
		return passThrough(), nil
	}
	text := conversationText(creq)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}
	limit := textchunk.MaxChunks(maxChunks, evalParallel, callReserve, p.budget)
	if n := textchunk.Count(text, chunkSpec); n > limit {
		return p.externalFailure(ctx, in, cfg, 0, n, appplugins.FailureInputTooLarge, appplugins.DetailChunkLimit,
			fmt.Errorf("azure_content_safety: the conversation splits into %d chunks, above the %d evaluated", n, limit))
	}
	chunks := textchunk.Split(text, chunkSpec)

	start := time.Now()
	budget, cancel := context.WithTimeout(ctx, p.budget)
	defer cancel()
	slow := textchunk.SlowCallOf(budget, callReserve)
	evals := make([]chunkEval, len(chunks))
	outs := textchunk.Run(budget, chunks, textchunk.RunOptions{
		Parallel: evalParallel,
		Reserve:  callReserve,
		StopOn:   func(i int) bool { return appplugins.Blocks(in.Mode) && len(evals[i].breaches) > 0 },
	}, func(ctx context.Context, i int, c textchunk.Chunk) (struct{}, error) {
		resp, err := pluginutil.RetryFirstRoundThrottle(ctx, i, evalParallel, func(ctx context.Context) (*analyzeResponse, error) {
			return p.client.Analyze(ctx, cfg.Endpoint, cfg.APIKey, analyzeRequest{
				Text:       c.Text,
				Categories: cfg.requestCategories(),
				OutputType: cfg.OutputType,
			})
		})
		if err != nil {
			return struct{}{}, err
		}
		evals[i].severities, evals[i].breaches, evals[i].missing = evaluate(resp, cfg)
		return struct{}{}, nil
	})
	latency := time.Since(start).Milliseconds()
	count := len(chunks)

	chunkState := func(i int, _ struct{}, err error) appplugins.ChunkState {
		if err != nil {
			reason, detail := pluginutil.FailureOfError(err)
			return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{Reason: reason, Detail: detail}}
		}
		if len(evals[i].breaches) > 0 {
			return appplugins.ChunkState{Blocks: true}
		}
		if evals[i].missing != "" {
			return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{
				Reason: appplugins.FailureVerdictIncomplete, Detail: evals[i].missing,
			}}
		}
		return appplugins.ChunkState{}
	}
	decision := appplugins.ClassifyChunks(outs, errors.Is(ctx.Err(), context.Canceled), chunkState,
		appplugins.SlowCall(slow))
	if decision.Kind == appplugins.ChunkInputFailure || decision.Kind == appplugins.ChunkAvailabilityFailure {
		return p.externalFailure(ctx, in, cfg, latency, count, decision.Reason, decision.Detail,
			fmt.Errorf("azure_content_safety: chunk %d of %d: %s", decision.Index+1, count, failureText(decision, outs)))
	}

	severities, breaches := mergeEvals(evals, outs)
	data := &Data{
		Endpoint:   cfg.Endpoint,
		OutputType: cfg.OutputType,
		Severities: severities,
		Mode:       string(in.Mode),
		LatencyMS:  latency,
	}
	if count > 1 {
		data.ChunkCount = count
	}

	if len(breaches) > 0 && appplugins.Blocks(in.Mode) {
		data.Decision = decisionBlocked
		data.Breached = breachedNames(breaches)
		setExtras(in.Event, data)
		recordScore(in.Event, breaches)
		appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
		return nil, blockError(cfg.Message, breaches)
	}

	if len(breaches) > 0 {
		data.Decision = decisionReported
		data.Breached = breachedNames(breaches)
	} else {
		data.Decision = decisionAllowed
	}
	setExtras(in.Event, data)
	if len(breaches) > 0 {
		recordScore(in.Event, breaches)
	}
	appplugins.SetDecisionFromOutcome(in.Event, data.Decision)
	return passThrough(), nil
}

// chunkEval is what Azure said about one chunk.
type chunkEval struct {
	severities map[string]int
	breaches   []breachedCategory
	missing    string
}

// mergeEvals is the highest severity Azure gave each category in any chunk, and
// each breached category once, at its highest severity.
func mergeEvals(evals []chunkEval, outs []textchunk.Outcome[struct{}]) (map[string]int, []breachedCategory) {
	severities := map[string]int{}
	worst := map[string]breachedCategory{}
	for i, ev := range evals {
		if !outs[i].Started || outs[i].Err != nil {
			continue
		}
		for category, severity := range ev.severities {
			if cur, ok := severities[category]; !ok || severity > cur {
				severities[category] = severity
			}
		}
		for _, b := range ev.breaches {
			if cur, ok := worst[b.Category]; !ok || b.Severity > cur.Severity {
				worst[b.Category] = b
			}
		}
	}
	if len(severities) == 0 {
		severities = nil
	}
	breaches := make([]breachedCategory, 0, len(worst))
	for _, b := range worst {
		breaches = append(breaches, b)
	}
	sort.Slice(breaches, func(i, j int) bool { return breaches[i].Category < breaches[j].Category })
	return severities, breaches
}

func failureText(d appplugins.ChunkDecision, outs []textchunk.Outcome[struct{}]) string {
	if d.Index >= 0 && d.Index < len(outs) && outs[d.Index].Err != nil {
		return outs[d.Index].Err.Error()
	}
	return d.Detail
}

// externalFailure turns a failed guardrail call into a plugin outcome via
// the shared appplugins.HandleExternalFailure, which owns the class and the
// mode: an availability failure passes through as failed_open, and an input
// failure is refused in a mode that blocks. It builds this plugin's own Data so
// failure_reason/failure_detail/failure_class travel with every other external
// guardrail's telemetry in the same shape.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	latencyMS int64,
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
		Message: cfg.Message,
		Err:     err,
		Logger:  p.logger,
		Event:   in.Event,
	})
	data := &Data{
		Endpoint:      cfg.Endpoint,
		OutputType:    cfg.OutputType,
		Mode:          string(in.Mode),
		LatencyMS:     latencyMS,
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

// evaluate reports every breached category plus, when none breached, the
// first (sorted) thresholded category Azure's response said nothing about.
// requestCategories already asks Azure to analyze every category_severity
// key, so a category still missing from CategoriesAnalysis means Azure could
// not or did not evaluate it — a silent gap this call must not read as a
// clean pass.
func evaluate(resp *analyzeResponse, cfg Settings) (severities map[string]int, breaches []breachedCategory, missingThreshold string) {
	if resp == nil {
		return nil, nil, ""
	}
	severities = make(map[string]int, len(resp.CategoriesAnalysis))
	present := make(map[string]struct{}, len(resp.CategoriesAnalysis))
	for _, analysis := range resp.CategoriesAnalysis {
		severities[analysis.Category] = analysis.Severity
		present[analysis.Category] = struct{}{}
		threshold, ok := cfg.CategorySeverity[analysis.Category]
		if !ok {
			continue
		}
		if analysis.Severity >= threshold {
			breaches = append(breaches, breachedCategory{
				Category:  analysis.Category,
				Severity:  analysis.Severity,
				Threshold: threshold,
			})
		}
	}
	names := make([]string, 0, len(cfg.CategorySeverity))
	for c := range cfg.CategorySeverity {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		if _, ok := present[c]; !ok {
			missingThreshold = c
			break
		}
	}
	return severities, breaches, missingThreshold
}

func breachedNames(breaches []breachedCategory) []string {
	names := make([]string, 0, len(breaches))
	for _, breach := range breaches {
		names = append(names, breach.Category)
	}
	return names
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
