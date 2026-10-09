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

package bedrockguardrail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

const PluginName = "bedrock_guardrail"

const (
	decisionBlocked    = "blocked"
	decisionAnonymized = "anonymized"
	decisionReported   = "reported"
	decisionAllowed    = "allowed"
)

const (
	reasonAnonymizeNoOutput          = appplugins.DetailAnonymizeNoOutput
	reasonAnonymizeUnsupportedFormat = appplugins.DetailAnonymizeUnsupportedFmt
	reasonAnonymizeEncodeFailed      = appplugins.DetailAnonymizeEncodeFailed
)

const roleUser = "user"

var _ appplugins.Plugin = (*Plugin)(nil)

type rewriteSpan struct {
	format     adapter.Format
	isResponse bool
	rewrite    func(masked string) ([]byte, bool)
}

func (s rewriteSpan) result(body []byte) *appplugins.Result {
	if s.isResponse {
		return &appplugins.Result{StatusCode: http.StatusOK, Body: body, StopUpstream: true}
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}
}

type Plugin struct {
	registry   *adapter.Registry
	guardrails *cachedGuardrailClient
	logger     *slog.Logger
	// throttledStreams maps the streams that have had a throttled block to when
	// the last one was, so a sustained throttle does not add a backoff to every
	// later block. A stream's closing segment removes its entry, and one a
	// closing never reached expires after throttledStreamTTL, swept at most once
	// a minute by any read or write of the map.
	throttledStreams sync.Map
	throttledSweptAt atomic.Int64
	// budget is the time one buffered evaluation has for all of its chunks;
	// zero means bufferedBudget.
	budget time.Duration
	// reserve is the time one buffered call is reserved; zero means callReserve.
	reserve time.Duration
	// callTimeout is how long one buffered chunk's call may take; zero means
	// bufferedCallTimeout.
	callTimeout time.Duration
}

func (p *Plugin) bufferedCallTimeout() time.Duration {
	if p.callTimeout > 0 {
		return p.callTimeout
	}
	return bufferedCallTimeout
}

func New(registry *adapter.Registry, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry:   registry,
		guardrails: newCachedGuardrailClient(),
		logger:     logger,
	}
}

func (p *Plugin) evaluationBudget() time.Duration {
	if p.budget > 0 {
		return p.budget
	}
	return bufferedBudget
}

// callReserveFor is the reserve of one call within this plugin's budget: the
// reserve a Run holds back, which a short budget shrinks.
func (p *Plugin) callReserveFor() time.Duration {
	r := p.reserve
	if r <= 0 {
		r = callReserve
	}
	return textchunk.EffectiveReserve(r, p.evaluationBudget())
}

// maxChunks is the most chunks a text may split into: the ones whose estimate
// keeps the headroom of half the budget (textchunk.Admits), which is the same
// bound the estimate applies, so chunk_limit is the refusal a text above it
// meets.
func (p *Plugin) maxChunks() int {
	return textchunk.MaxChunks(1<<30, chunkParallel, p.callReserveFor(), p.evaluationBudget())
}

func (p *Plugin) Name() string { return PluginName }

func (p *Plugin) MutatesRequestBody() bool { return true }

func (p *Plugin) MutatesResponseBody() bool { return true }

func (p *Plugin) MutatesMetadata() bool { return false }

// BedrockNative declares what the plugin does on a native Amazon Bedrock Runtime
// call (see appplugins.BedrockNativeAware).
func (p *Plugin) BedrockNative() appplugins.BedrockNativeBehavior {
	return appplugins.BedrockNativeMasks
}

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

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	_, err := parseConfig(settings)
	return err
}

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects a new streaming.final_pass: false, which the
// block loop cannot honour (pluginutil.ValidateFinalPassWrite).
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
	return pluginutil.ValidateFinalPassWrite(PluginName, settings, previous)
}

// CredentialPaths declares the settings paths that hold secrets, so the policy
// API masks them on read: the AWS credentials nested under "credentials".
func (p *Plugin) CredentialPaths() []string {
	return []string{
		"credentials.access_key_id",
		"credentials.secret_access_key",
		"credentials.session_token",
	}
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, "", err)
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.executePreRequest(ctx, in, cfg)
	case policy.StagePreResponse:
		return p.executePreResponse(ctx, in, cfg)
	default:
		return passThrough(), nil
	}
}

func (p *Plugin) executePreRequest(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 || in.Request.Provider == "" || p.registry == nil {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, err)
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil {
		if pluginutil.SkipNonChatRoute(in.Event, string(in.Stage), in.Request.ProxyCapability, format) {
			return passThrough(), nil
		}
		if !adapter.IsRequestDecodeError(err) {
			return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, err)
		}
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureDecodeFailed, "", err)
	}
	if creq == nil {
		return passThrough(), nil
	}
	text, idx := lastUserText(creq)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}
	span := rewriteSpan{
		format: format,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteRequest(p.registry, format, in.Request.Body, creq, idx, masked)
		},
	}
	return p.runGuardrail(ctx, in, cfg, text, types.GuardrailContentSourceInput, span)
}

func (p *Plugin) executePreResponse(ctx context.Context, in appplugins.ExecInput, cfg Settings) (*appplugins.Result, error) {
	if in.Request == nil || in.Response == nil {
		return passThrough(), nil
	}
	// A streamed response is inspected block by block by the stream guard when
	// streaming is enabled for this policy. When it is not, the response goes
	// out uninspected and the trace says so, rather than omitting the policy.
	if in.Response.Streaming {
		if !cfg.Streaming.IsEnabled() {
			pluginutil.RecordStreamingDisabled(in.Event, string(in.Stage))
		}
		return passThrough(), nil
	}
	if p.registry == nil || in.Request.Provider == "" || len(in.Response.Body) == 0 {
		return passThrough(), nil
	}
	if pluginutil.SkipWithoutCompletion(in.Event, string(in.Stage), in.Response) {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, 0, appplugins.FailureConfigInvalid, appplugins.DetailUnsupportedFormat, err)
	}
	cresp, err := p.registry.DecodeResponseFor(in.Response.Body, format)
	if err != nil {
		pluginutil.RecordSkipped(in.Event, string(in.Stage), pluginutil.SkipReasonUndecodableResponse)
		return passThrough(), nil
	}
	if cresp == nil {
		return passThrough(), nil
	}
	text := responseText(cresp)
	if strings.TrimSpace(text) == "" {
		return passThrough(), nil
	}
	span := rewriteSpan{
		format:     format,
		isResponse: true,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteResponse(p.registry, format, cresp, masked)
		},
	}
	return p.runGuardrail(ctx, in, cfg, text, types.GuardrailContentSourceOutput, span)
}

// A buffered text is split into chunks of chunkBytes. The smallest per-call
// burst of any region is 25 text units (every other supported region), and a
// text unit is up to 1,000 characters (a partial unit is billed whole), so 24
// units per chunk fits it whatever the region. Bytes are never fewer than
// characters, and AWS does not say whether its characters are code points or
// UTF-16 units, which bytes bound both. The overlap is 4,096 bytes, enough that
// a long secret (a PEM key, a service-account JSON of about 3.5 KB) lies whole
// in one chunk; it re-bills about 17%. A pattern longer than the overlap, or a
// context that a cut separates by more than it, can still be cut in two.
//
// Only the last user message of a request (or the whole response) is sent.
//
// The chunks are sent one at a time, spaced at the region's quota floor
// (spacing.go), inside bufferedBudget for the whole evaluation, and every call
// is reserved callReserve. A text is admitted when its estimate (the chunks
// times callReserve, plus any wait the quota adds) is at most half of the
// budget, which is maxBufferedChunks chunks at the defaults: chunkBytes plus
// (maxBufferedChunks-1) steps of chunkBytes-chunkOverlap bytes, about 203 KB. A
// text above that is refused before any call as chunk_limit, or as chunk_budget
// when the quota's waits are what push its estimate over. The same ceiling holds
// in every region: in the smallest quota the refill during a call (37 units in
// 1.5 s against 24 a chunk) covers a chunk. The headroom lets AWS answer up to
// twice as slowly as the reserve on every chunk without the budget cutting
// one. After admission a chunk that the budget cuts or that has too little time
// left to start fails open as availability only when some call took longer than
// twice callReserve; otherwise the request's own size used the budget and the
// chunk is chunk_budget, input. Since the request's own calls stay under the
// floor, a throttle AWS still returns is other traffic and is availability too,
// unlike on the guardrails that cannot space their calls.
// https://aws.amazon.com/blogs/machine-learning/use-the-applyguardrail-api-with-long-context-inputs-and-streaming-outputs-in-amazon-bedrock/
const (
	chunkBytes     = 24000
	chunkOverlap   = 4096
	chunkParallel  = 1
	bufferedBudget = 30 * time.Second
	// bufferedCallTimeout is how long one chunk's call, with its throttle
	// retries, may take. It is not the evaluation's budget: a provider that
	// hangs fails the evaluation open after about one call.
	bufferedCallTimeout = 15 * time.Second
	callReserve         = 1500 * time.Millisecond
	maxBufferedChunks   = int(bufferedBudget / 2 / callReserve)
)

var chunkSpec = textchunk.Spec{Max: chunkBytes, Overlap: chunkOverlap, Unit: textchunk.Bytes}

// chunkEval is what ApplyGuardrail said about one chunk.
type chunkEval struct {
	out *bedrockruntime.ApplyGuardrailOutput
	res assessmentResult
}

func (p *Plugin) runGuardrail(ctx context.Context, in appplugins.ExecInput, cfg Settings, text string, source types.GuardrailContentSource, span rewriteSpan) (*appplugins.Result, error) {
	creds := credentialsFromConfig(cfg.Credentials)
	n := textchunk.Count(text, chunkSpec)
	if limit := p.maxChunks(); n > limit {
		return p.externalFailure(ctx, in, cfg, 0, n, appplugins.FailureInputTooLarge, appplugins.DetailChunkLimit,
			fmt.Errorf("bedrock_guardrail: the text splits into %d chunks, above the %d evaluated", n, limit))
	}
	chunks := textchunk.Split(text, chunkSpec)
	quota := floorFor(creds.region)
	reserve := p.callReserveFor()
	if need := estimateDuration(chunks, quota, reserve); len(chunks) > 1 && need > p.evaluationBudget()/2 {
		return p.externalFailure(ctx, in, cfg, 0, len(chunks), appplugins.FailureInputTooLarge, appplugins.DetailChunkBudget,
			fmt.Errorf("bedrock_guardrail: %d chunks need about %s with the region's quota and half of the budget is %s", len(chunks), need.Round(time.Millisecond), p.evaluationBudget()/2))
	}
	pace := newSpacer(quota)

	start := time.Now()
	budget, cancel := context.WithTimeout(ctx, p.evaluationBudget())
	defer cancel()
	slow := textchunk.SlowCallOf(budget, reserve)
	evals := make([]chunkEval, len(chunks))
	outs := textchunk.Run(budget, chunks, textchunk.RunOptions{
		Parallel: chunkParallel,
		Reserve:  reserve,
		StopOn:   func(i int) bool { return appplugins.Blocks(in.Mode) && evals[i].res.block != nil },
		Before:   func(ctx context.Context, _ int, c textchunk.Chunk) error { return pace.wait(ctx, len(c.Text)) },
	}, func(ctx context.Context, i int, c textchunk.Chunk) (struct{}, error) {
		ctx, cancelCall := context.WithTimeout(ctx, p.bufferedCallTimeout())
		defer cancelCall()
		out, err := p.guardrails.ApplyWithBackoff(ctx, creds, buildApplyInput(cfg, c.Text, source), callLimitsFor(len(c.Text)))
		if err != nil {
			return struct{}{}, err
		}
		evals[i] = chunkEval{out: out, res: inspect(out, cfg.PIIAction)}
		return struct{}{}, nil
	})
	latency := time.Since(start).Milliseconds()
	count := len(chunks)
	chunkState := func(i int, _ struct{}, err error) appplugins.ChunkState {
		if err != nil {
			reason, detail := classifyApplyErr(err)
			return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{Reason: reason, Detail: detail, OtherTraffic: true}}
		}
		return evals[i].state()
	}
	decision := appplugins.ClassifyChunks(outs, errors.Is(ctx.Err(), context.Canceled), chunkState, appplugins.SlowCall(slow))

	var gap *appplugins.ChunkDecision
	switch decision.Kind {
	case appplugins.ChunkInputFailure, appplugins.ChunkAvailabilityFailure:
		if decision.Kind == appplugins.ChunkAvailabilityFailure && decision.Masked && appplugins.Blocks(in.Mode) {
			gap = &decision
			break
		}
		return p.failedChunk(ctx, in, cfg, latency, count, decision, evals, outs)
	}

	var finding *finding
	switch {
	case decision.Kind == appplugins.ChunkBlocked:
		finding = evals[decision.Index].res.block
	case decision.Masked:
		if i := pluginutil.FirstMaskedChunk(outs, func(i int) bool { return evals[i].res.anonymize != nil }); i >= 0 {
			finding = evals[i].res.anonymize
		}
	}

	data := newData(in, cfg, latency)
	if count > 1 {
		data.ChunkCount = count
	}

	if decision.Kind == appplugins.ChunkBlocked {
		applyFinding(data, finding)
		recordScore(in.Event, data)
		if appplugins.Blocks(in.Mode) {
			data.Decision = decisionBlocked
			setExtras(in.Event, data)
			appplugins.SetDecisionFromOutcome(in.Event, decisionBlocked)
			return nil, blockError(cfg.Message, *finding)
		}
		data.Decision = decisionReported
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionReported)
		return passThrough(), nil
	}

	if finding != nil {
		applyFinding(data, finding)
		recordScore(in.Event, data)
		if appplugins.Blocks(in.Mode) {
			if gap != nil {
				data.FailureReason = string(gap.Reason)
				data.FailureDetail = gap.Detail
				data.FailureClass = string(appplugins.FailureClassAvailability)
			}
			masked, failed := mergedMask(text, chunks, evals, outs)
			return p.anonymizeEnforceMasked(ctx, in, data, cfg.Message, masked, failed, span, finding)
		}
		data.Decision = decisionReported
		setExtras(in.Event, data)
		appplugins.SetDecisionFromOutcome(in.Event, decisionReported)
		return passThrough(), nil
	}

	data.Decision = decisionAllowed
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionAllowed)
	return passThrough(), nil
}

// state reads one chunk's answer as the shared verdict: a finding that blocks, a
// gap in what the guardrail judged (coverage, or an intervention nothing here
// explains), or a mask to apply.
func (e chunkEval) state() appplugins.ChunkState {
	switch {
	case e.res.block != nil:
		return appplugins.ChunkState{Blocks: true}
	case e.res.judgedOnlyInPart():
		return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{
			Reason: appplugins.FailureVerdictIncomplete, Detail: appplugins.DetailCoveragePartial,
		}}
	case e.res.intervened && e.res.anonymize == nil:
		return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{
			Reason: appplugins.FailureVerdictIncomplete, Detail: appplugins.DetailInterventionUnparsed,
		}}
	case e.res.anonymize != nil:
		return appplugins.ChunkState{Mask: true}
	}
	return appplugins.ChunkState{}
}

func (p *Plugin) failedChunk(
	ctx context.Context, in appplugins.ExecInput, cfg Settings, latency int64, count int,
	d appplugins.ChunkDecision, evals []chunkEval, outs []textchunk.Outcome[struct{}],
) (*appplugins.Result, error) {
	var cause error
	switch {
	case d.Index >= 0 && d.Index < len(outs) && outs[d.Index].Err != nil:
		cause = fmt.Errorf("apply guardrail: %w", outs[d.Index].Err)
	case d.Detail == appplugins.DetailCoveragePartial:
		cause = fmt.Errorf("guardrail covered only part of the text")
	case d.Detail == appplugins.DetailInterventionUnparsed:
		cause = fmt.Errorf("guardrail intervened with no block or anonymize finding")
	default:
		cause = fmt.Errorf("chunk %d of %d was not evaluated: %s", d.Index+1, count, d.Detail)
	}
	policies := ""
	if d.Detail == appplugins.DetailInterventionUnparsed {
		policies = unparsedPolicies(evals[d.Index].out.Assessments)
	}
	return p.externalFailureWithPolicies(ctx, in, cfg, latency, count, d.Reason, d.Detail, policies, cause)
}

// mergedMask is the masked text the chunks that asked for a mask add up to (see
// pluginutil.MergeChunkMasks).
func mergedMask(text string, chunks []textchunk.Chunk, evals []chunkEval, outs []textchunk.Outcome[struct{}]) (masked string, failed string) {
	return pluginutil.MergeChunkMasks(text, chunks, outs,
		func(i int) bool { return evals[i].res.anonymize != nil },
		func(i int) (string, bool) { return maskedText(evals[i].out) })
}

func (p *Plugin) anonymizeEnforce(ctx context.Context, in appplugins.ExecInput, data *Data, message string, out *bedrockruntime.ApplyGuardrailOutput, span rewriteSpan, f *finding) (*appplugins.Result, error) {
	masked, ok := maskedText(out)
	reason := ""
	if !ok {
		reason = reasonAnonymizeNoOutput
	}
	return p.anonymizeEnforceMasked(ctx, in, data, message, masked, reason, span, f)
}

// anonymizeEnforceMasked applies a mask the guardrail asked for, already read
// from its output, or refuses in a mode that blocks when it cannot be applied:
// failedReason is why there is no masked text, and empty when there is.
func (p *Plugin) anonymizeEnforceMasked(ctx context.Context, in appplugins.ExecInput, data *Data, message string, masked string, failedReason string, span rewriteSpan, f *finding) (*appplugins.Result, error) {
	if failedReason != "" {
		return p.anonymizeDegraded(ctx, in, data, message, failedReason, f)
	}
	if !supportsReencode(p.registry, span.format) {
		return p.anonymizeDegraded(ctx, in, data, message, reasonAnonymizeUnsupportedFormat, f)
	}
	body, ok := span.rewrite(masked)
	if !ok {
		return p.anonymizeDegraded(ctx, in, data, message, reasonAnonymizeEncodeFailed, f)
	}
	data.Decision = decisionAnonymized
	setExtras(in.Event, data)
	appplugins.SetDecisionFromOutcome(in.Event, decisionAnonymized)
	return span.result(body), nil
}

// anonymizeDegraded is the provider confirming a finding and asking to
// anonymise while the masked text cannot be applied. Forwarding the original
// would send the very data the policy ruled out, so a mode that blocks refuses
// the call with the finding's own block, recorded blocked and degraded.
func (p *Plugin) anonymizeDegraded(ctx context.Context, in appplugins.ExecInput, data *Data, message string, reason string, f *finding) (*appplugins.Result, error) {
	data.Degraded = true
	data.DegradedReason = reason
	data.FailureReason = string(appplugins.FailureVerdictIncomplete)
	data.FailureDetail = reason
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:     ctx,
		Plugin:  PluginName,
		Stage:   in.Stage,
		Mode:    in.Mode,
		Reason:  appplugins.FailureVerdictIncomplete,
		Detail:  reason,
		Message: message,
		Finding: blockError(message, *f),
		Err:     fmt.Errorf("guardrail masking could not be applied: %s", reason),
		Logger:  p.logger,
		Event:   in.Event,
	})
	data.Decision = outcome.Decision
	data.FailureClass = string(outcome.Class)
	setExtras(in.Event, data)
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
}

// externalFailure turns a failed guardrail call into a plugin outcome via the
// shared appplugins.HandleExternalFailure, which owns the class and the mode:
// an availability failure passes through as failed_open, and an input failure
// is refused in a mode that blocks. It builds this plugin's own Data so
// failure_reason/failure_detail/failure_class travel in the same shape as every
// other external guardrail.
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
	return p.externalFailureWithPolicies(ctx, in, cfg, latencyMS, chunks, reason, detail, "", err)
}

func (p *Plugin) externalFailureWithPolicies(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	latencyMS int64,
	chunks int,
	reason appplugins.FailureReason,
	detail string,
	policies string,
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
	data := newData(in, cfg, latencyMS)
	if chunks > 1 {
		data.ChunkCount = chunks
	}
	data.Decision = outcome.Decision
	data.FailureReason = string(reason)
	data.FailureDetail = detail
	data.FailurePolicies = policies
	data.FailureClass = string(outcome.Class)
	setExtras(in.Event, data)
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
}

func newData(in appplugins.ExecInput, cfg Settings, latency int64) *Data {
	return &Data{
		GuardrailID: cfg.GuardrailID,
		Version:     cfg.Version,
		Region:      cfg.Credentials.AWSRegion,
		Stage:       string(in.Stage),
		Mode:        string(in.Mode),
		LatencyMS:   latency,
	}
}

func applyFinding(data *Data, f *finding) {
	data.Policy = f.policy
	data.MatchType = f.matchType
	data.Action = f.action
	data.Name = f.name
}

func lastUserText(creq *adapter.CanonicalRequest) (string, int) {
	if creq == nil {
		return "", -1
	}
	for i := len(creq.Messages) - 1; i >= 0; i-- {
		msg := creq.Messages[i]
		if msg.Role == roleUser && strings.TrimSpace(msg.Content) != "" {
			return msg.Content, i
		}
	}
	return "", -1
}

func responseText(cresp *adapter.CanonicalResponse) string {
	if cresp == nil {
		return ""
	}
	return cresp.Content
}

func passThrough() *appplugins.Result {
	return &appplugins.Result{StatusCode: http.StatusOK}
}
