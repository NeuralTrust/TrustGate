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

package googlemodelarmor

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/common/gcpkey"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const PluginName = "google_model_armor"

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

// rewriteSpan carries what runGuardrail needs to reinject masked text into
// either leg of the exchange without knowing which one it is.
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

// Plugin is the google_model_armor guardrail: a single Model Armor sanitize
// call per stage, with block_on picking which of its orthogonal findings
// (sdp, rai, pi_and_jailbreak, malicious_uris, csam) blocks the request.
// Multimodal content is out of scope: the REST v1 API this client speaks has
// no DataItem support for these endpoints. Streamed responses are inspected per
// block through StreamInspector, which needs no streaming sanitize method — a
// block is an ordinary sanitize call over the prefix produced so far.
type Plugin struct {
	registry *adapter.Registry
	clients  *clientCache
	logger   *slog.Logger
	// allowAmbientIdentity mirrors MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY. False
	// (the zero value, so a Plugin built without New is safe) refuses every
	// credential path that acts as the gateway pod's shared identity.
	allowAmbientIdentity bool
}

// New builds the plugin. baseURL and timeout come from cfg.ModelArmor
// (pkg/config); baseURL is normally empty so the client derives the regional
// host from each call's own location. Authentication is per policy: a
// *client (and the token source it wraps) is built lazily, at most once per
// distinct credentials fingerprint, the first time a policy using that
// credential set runs — see clientFor and Settings.Credentials.
//
// allowAmbientIdentity comes from cfg.ModelArmor.AllowAmbientIdentity. When
// false, policies that would act as the pod identity (no credentials, or
// impersonate_service_account) are rejected on write and refused at run time.
func New(registry *adapter.Registry, baseURL string, timeout time.Duration, allowAmbientIdentity bool, logger *slog.Logger) *Plugin {
	return &Plugin{
		registry:             registry,
		clients:              newModelArmorClientCache(baseURL, timeout, newCredentialSources()),
		logger:               logger,
		allowAmbientIdentity: allowAmbientIdentity,
	}
}

// clientFor resolves the *client for cfg's credentials, reusing the cached
// client for that credential fingerprint when one already exists.
func (p *Plugin) clientFor(cfg Settings) (*client, error) {
	if p.clients == nil {
		return nil, fmt.Errorf("google_model_armor: plugin has no client cache configured")
	}
	return p.clients.get(credentialsFromConfig(cfg.Credentials))
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

var _ appplugins.SettingsWriteValidator = (*Plugin)(nil)

// ValidateSettingsWrite rejects a service_account_json that names a non-Google
// token endpoint, a custom universe or a non-service_account type, and a new
// streaming.final_pass: false (pluginutil.ValidateFinalPassWrite). This cannot
// live in parseConfig, which runs on every request: a policy stored before the
// rule existed would turn into a run-time config_invalid failure. The runtime
// instead pins the token endpoint (gcpauth.ServiceAccountCache), so an
// already-stored key keeps working and can never redirect the assertion.
func (p *Plugin) ValidateSettingsWrite(settings, previous map[string]any) error {
	cfg, err := parseConfig(settings)
	if err != nil {
		return err
	}
	if sa := strings.TrimSpace(cfg.Credentials.ServiceAccountJSON); sa != "" {
		if err := gcpkey.Validate(sa); err != nil {
			return fmt.Errorf("google_model_armor: credentials.service_account_json: %s", err.Error())
		}
	}
	return pluginutil.ValidateFinalPassWrite(PluginName, settings, previous)
}

func (p *Plugin) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (p *Plugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

func (p *Plugin) ValidateConfig(settings map[string]any) error {
	cfg, err := parseConfig(settings)
	if err != nil {
		return err
	}
	return p.checkIdentity(cfg)
}

// checkIdentity refuses the credential paths that act as the gateway pod's own
// identity unless the operator enabled MODEL_ARMOR_ALLOW_AMBIENT_IDENTITY. The
// pod identity is shared by every tenant, so impersonating a tenant-named
// service account through it, or calling Model Armor as the pod directly, lets
// one tenant spend another's trust: only service_account_json proves the tenant
// controls the identity. The error names the field, never a value.
func (p *Plugin) checkIdentity(cfg Settings) error {
	if p.allowAmbientIdentity {
		return nil
	}
	creds := credentialsFromConfig(cfg.Credentials)
	switch {
	case creds.impersonateServiceAccount != "":
		return fmt.Errorf(
			"google_model_armor: credentials.impersonate_service_account is not allowed on this gateway: " +
				"a service account key (credentials.service_account_json) is required")
	case strings.TrimSpace(creds.serviceAccountJSON) == "":
		return fmt.Errorf(
			"google_model_armor: credentials.service_account_json is required on this gateway: " +
				"a service account key is required, the gateway's own identity is not available")
	}
	return nil
}

// CredentialPaths declares the settings paths that hold secrets, so the policy
// API masks them on read. impersonate_service_account is deliberately absent:
// it is an email, useless without the customer's own IAM grant.
func (p *Plugin) CredentialPaths() []string {
	return []string{"credentials.service_account_json"}
}

// CredentialDestinations binds the service account key to what builds the
// request URL: the location is the host and the project is part of the path.
// bedrock_guardrail, openai_moderation and semantic_cache declare none: their
// requests go to a fixed vendor URL or are SigV4-signed for AWS hosts, so no
// settings field can redirect the secret.
func (p *Plugin) CredentialDestinations() []string {
	return []string{"location", "project"}
}

func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureConfigInvalid, err: err})
	}
	if err := p.checkIdentity(cfg); err != nil {
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureConfigInvalid, err: err})
	}
	cl, err := p.clientFor(cfg)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureConfigInvalid, err: err})
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return p.executePreRequest(ctx, in, cfg, cl)
	case policy.StagePreResponse:
		return p.executePreResponse(ctx, in, cfg, cl)
	default:
		return passThrough(), nil
	}
}

// executePreRequest sends only the last user message, like bedrock: Model
// Armor bills per request, so replaying the whole conversation on every turn
// would grow the bill linearly with conversation length.
func (p *Plugin) executePreRequest(ctx context.Context, in appplugins.ExecInput, cfg Settings, cl *client) (*appplugins.Result, error) {
	if in.Request == nil || len(in.Request.Body) == 0 || in.Request.Provider == "" || p.registry == nil {
		return passThrough(), nil
	}
	format, err := adapter.ResolveAgentFormat(in.Request.Provider, in.Request.SourceFormat, nil)
	if err != nil {
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureConfigInvalid, armorReason: appplugins.DetailUnsupportedFormat, err: err})
	}
	creq, err := p.registry.DecodeRequestFor(in.Request.Body, format)
	if err != nil {
		if pluginutil.SkipNonChatRoute(in.Event, string(in.Stage), in.Request.ProxyCapability, format) {
			return passThrough(), nil
		}
		if !adapter.IsRequestDecodeError(err) {
			return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureConfigInvalid, armorReason: appplugins.DetailUnsupportedFormat, err: err})
		}
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureDecodeFailed, err: err})
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
	sanitize := func(ctx context.Context, chunk string) (*SanitizationResult, error) {
		return cl.SanitizeUserPrompt(ctx, cfg.Project, cfg.Location, cfg.Template, chunk)
	}
	return p.runGuardrail(ctx, in, cfg, text, cl.timeout, sanitize, span)
}

// executePreResponse sanitizes the completion in its own call, separate from
// pre_request, again to keep Model Armor billing to one call per turn per
// stage rather than resending history.
func (p *Plugin) executePreResponse(ctx context.Context, in appplugins.ExecInput, cfg Settings, cl *client) (*appplugins.Result, error) {
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
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{reason: appplugins.FailureConfigInvalid, armorReason: appplugins.DetailUnsupportedFormat, err: err})
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
	userPrompt := correlationPrompt(p.registry, format, in.Request.Body)
	span := rewriteSpan{
		format:     format,
		isResponse: true,
		rewrite: func(masked string) ([]byte, bool) {
			return rewriteResponse(p.registry, format, cresp, masked)
		},
	}
	sanitize := func(ctx context.Context, chunk string) (*SanitizationResult, error) {
		return cl.SanitizeModelResponse(ctx, cfg.Project, cfg.Location, cfg.Template, chunk, userPrompt)
	}
	return p.runGuardrail(ctx, in, cfg, text, cl.timeout, sanitize, span)
}

// A buffered text is split into chunks of chunkBytes. Model Armor screens at
// most 65,536 tokens with the prompt injection, Responsible AI and CSAM filters
// and 130,000 with Sensitive Data Protection, and skips a filter above its
// limit (https://docs.cloud.google.com/model-armor/quotas). A token covers at
// least one byte, which Google does not document and is an assumption of this
// plugin, so a call of at most 65,536 bytes is within every limit: the chunk
// plus the correlation prompt a response carries (maxCorrelationPromptBytes)
// fills exactly that. The overlap keeps a pattern that straddles a cut whole in
// one chunk. A text that splits into more than maxBufferedChunks is refused
// before any call, and at most chunkParallel run at once inside the client's
// timeout for the whole evaluation. The project's quota is 1,200 requests a
// minute, which maxBufferedChunks calls cannot exhaust alone.
const (
	chunkBytes        = maxSanitizeBytes
	chunkOverlap      = 2048
	maxBufferedChunks = 16
	chunkParallel     = 4
	// callReserve is the budget a chunk that has to wait for a slot needs left
	// to be started, about twice a call's usual latency. A chunk queued behind
	// the request's own chunks that finds less is refused as chunk_budget: the
	// request's size used the time, the provider was not slow.
	callReserve = 1500 * time.Millisecond
)

var chunkSpec = textchunk.Spec{Max: chunkBytes, Overlap: chunkOverlap, Unit: textchunk.Bytes}

// maxCorrelationPromptBytes bounds the user prompt sent along with a response.
// It is context for the filters, not content to inspect (the prompt was
// inspected on pre_request), and it counts against the same token limit as the
// response: unbounded, a padded prompt would push the response call past it and
// make Model Armor skip its filters on the response.
const maxCorrelationPromptBytes = 8 << 10

// correlationPrompt best-effort decodes the original request's last user
// message to pass as SanitizeModelResponse's optional userPrompt context,
// keeping its last maxCorrelationPromptBytes.
// Any failure here just omits the correlation; it never blocks the response.
func correlationPrompt(reg *adapter.Registry, format adapter.Format, requestBody []byte) string {
	if reg == nil || len(requestBody) == 0 {
		return ""
	}
	creq, err := reg.DecodeRequestFor(requestBody, format)
	if err != nil || creq == nil {
		return ""
	}
	text, _ := lastUserText(creq)
	return tailOnRuneBoundary(text, maxCorrelationPromptBytes)
}

// tailOnRuneBoundary keeps the last limit bytes of s, advanced to the next rune
// start so it never begins inside a character.
func tailOnRuneBoundary(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	tail := s[len(s)-limit:]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	return tail
}

// chunkEval is what Model Armor said about one chunk, read the way a single
// call is read: a failure that is the call's (failure), a verdict (res), and
// the gap a mask was kept despite (keptGap).
type chunkEval struct {
	result  *SanitizationResult
	res     assessmentResult
	failure *failureInfo
	keptGap string
}

func (p *Plugin) evaluateChunk(in appplugins.ExecInput, cfg Settings, result *SanitizationResult) chunkEval {
	ev := chunkEval{result: result}
	if result.InvocationResult == invocationResultFailure {
		ev.failure = &failureInfo{
			reason:        appplugins.FailureTransport,
			filterVersion: result.filterVersion(),
			err:           fmt.Errorf("invocationResult FAILURE"),
		}
		return ev
	}
	ev.res = inspect(result, cfg)
	// A filter we were told to block on that did not actually run reports no
	// match, exactly like a filter that ran and found nothing, and the
	// envelope can still say SUCCESS overall. It takes the same path as an
	// outright failure rather than mistake silence for safety. A filter that
	// did run and matched still wins: it is a real verdict, and naming it is
	// more useful than naming the one that was missing.
	//
	// A filter that was skipped (EXECUTION_SKIPPED) is the content's doing, since
	// padding a request is what skips one, so a mode that blocks refuses it,
	// usable mask or not: the other filters did not judge this content. An
	// invocation that came back PARTIAL while every block_on filter ran says
	// nothing about what was asked, so it is recorded and fails open. A filter
	// the template never enabled is the customer's configuration, not anything
	// the request did, and keeps its usable mask: Model Armor already handed us
	// the de-identified text, and failing open would forward the ORIGINAL prompt
	// with the raw PII. The mask is applied and the incomplete verdict recorded
	// on the same Data instead.
	if ev.res.block != nil {
		return ev
	}
	if f, reason := unevaluatedFilter(result, cfg.blockOnSet()); f != "" {
		if keepsMaskDespiteGap(ev.res, in.Mode, reason) {
			ev.keptGap = reason
			return ev
		}
		ev.failure = &failureInfo{
			reason:        appplugins.FailureVerdictIncomplete,
			filter:        f,
			armorReason:   reason,
			filterVersion: result.filterVersion(),
			err:           fmt.Errorf("filter %q selected in block_on produced no verdict (%s)", f, reason),
		}
		return ev
	}
	if result.InvocationResult == invocationResultPartial {
		ev.failure = &failureInfo{
			reason:        appplugins.FailureVerdictIncomplete,
			armorReason:   appplugins.DetailInvocationPartial,
			filterVersion: result.filterVersion(),
			err:           fmt.Errorf("invocationResult PARTIAL"),
		}
	}
	return ev
}

func (e chunkEval) state() appplugins.ChunkState {
	switch {
	case e.failure != nil:
		return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{Reason: e.failure.reason, Detail: e.failure.armorReason}}
	case e.res.block != nil:
		return appplugins.ChunkState{Blocks: true}
	case e.res.anonymize != nil:
		return appplugins.ChunkState{Mask: true}
	}
	return appplugins.ChunkState{}
}

func (p *Plugin) runGuardrail(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	text string,
	budget time.Duration,
	sanitize func(ctx context.Context, chunk string) (*SanitizationResult, error),
	span rewriteSpan,
) (*appplugins.Result, error) {
	if n := textchunk.Count(text, chunkSpec); n > maxBufferedChunks {
		return p.externalFailure(ctx, in, cfg, 0, failureInfo{
			reason:      appplugins.FailureInputTooLarge,
			armorReason: appplugins.DetailChunkLimit,
			chunks:      n,
			err:         fmt.Errorf("model_armor: the text splits into %d chunks, above the %d evaluated", n, maxBufferedChunks),
		})
	}
	chunks := textchunk.Split(text, chunkSpec)
	count := len(chunks)

	start := time.Now()
	runCtx := ctx
	if budget > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	evals := make([]chunkEval, count)
	outs := textchunk.Run(runCtx, chunks, textchunk.RunOptions{
		Parallel: chunkParallel,
		Reserve:  callReserve,
		StopOn:   func(i int) bool { return appplugins.Blocks(in.Mode) && evals[i].res.block != nil },
	}, func(ctx context.Context, i int, c textchunk.Chunk) (struct{}, error) {
		result, err := sanitize(ctx, c.Text)
		if err != nil {
			return struct{}{}, err
		}
		evals[i] = p.evaluateChunk(in, cfg, result)
		return struct{}{}, nil
	})
	latency := time.Since(start).Milliseconds()
	chunkState := func(i int, _ struct{}, err error) appplugins.ChunkState {
		if err != nil {
			reason, detail := pluginutil.FailureOfError(err)
			return appplugins.ChunkState{Failure: &appplugins.ChunkFailure{Reason: reason, Detail: detail}}
		}
		return evals[i].state()
	}
	decision := appplugins.ClassifyChunks(outs, ctx.Err() != nil, chunkState)

	var gap *appplugins.ChunkDecision
	switch decision.Kind {
	case appplugins.ChunkInputFailure, appplugins.ChunkAvailabilityFailure:
		if decision.Kind == appplugins.ChunkAvailabilityFailure && decision.Masked && appplugins.Blocks(in.Mode) {
			gap = &decision
			break
		}
		return p.externalFailure(ctx, in, cfg, latency, failureOfChunk(decision, evals, outs, count))
	}

	data := newData(in, cfg, latency)
	if count > 1 {
		data.ChunkCount = count
	}

	var finding *finding
	var from int
	switch {
	case decision.Kind == appplugins.ChunkBlocked:
		from, finding = decision.Index, evals[decision.Index].res.block
	case decision.Masked:
		for i, ev := range evals {
			if outs[i].Started && outs[i].Err == nil && ev.res.anonymize != nil {
				from, finding = i, ev.res.anonymize
				break
			}
		}
	}
	data.FilterVersion = filterVersionOf(evals, outs, from, finding != nil)
	for i, ev := range evals {
		if outs[i].Started && outs[i].Err == nil && ev.keptGap != "" {
			data.FailureReason = string(appplugins.FailureVerdictIncomplete)
			data.FailureDetail = ev.keptGap
			data.FailureClass = string(appplugins.FailureClassAvailability)
			break
		}
	}
	if gap != nil {
		data.FailureReason = string(gap.Reason)
		data.FailureDetail = gap.Detail
		data.FailureClass = string(appplugins.FailureClassAvailability)
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

// filterVersionOf is the filter version behind a chunked evaluation's verdict:
// the chunk that produced the finding when there is one, else the first chunk
// that was sent and answered, so an evaluation that found nothing still says
// which filter version judged it.
func filterVersionOf(evals []chunkEval, outs []textchunk.Outcome[struct{}], from int, hasFinding bool) string {
	if hasFinding {
		return evals[from].result.filterVersion()
	}
	for i, ev := range evals {
		if outs[i].Started && outs[i].Err == nil && ev.result != nil {
			return ev.result.filterVersion()
		}
	}
	return ""
}

// failureOfChunk is the failure that decided a chunked evaluation: the filter
// and version Model Armor named for the chunk, or, when its call failed, the
// error of that call.
func failureOfChunk(d appplugins.ChunkDecision, evals []chunkEval, outs []textchunk.Outcome[struct{}], count int) failureInfo {
	fi := failureInfo{reason: d.Reason, armorReason: d.Detail, chunks: count}
	switch {
	case d.Index >= 0 && d.Index < len(outs) && outs[d.Index].Err != nil:
		fi.err = fmt.Errorf("sanitize: %w", outs[d.Index].Err)
	case d.Index >= 0 && d.Index < len(evals) && evals[d.Index].failure != nil:
		orig := evals[d.Index].failure
		fi.filter, fi.filterVersion, fi.err = orig.filter, orig.filterVersion, orig.err
	default:
		fi.err = fmt.Errorf("chunk %d of %d was not evaluated: %s", d.Index+1, count, d.Detail)
	}
	return fi
}

// mergedMask is the masked text the chunks that asked for a mask add up to. A
// single chunk's text is Model Armor's own de-identified output. With several,
// each chunk's output is mapped back onto the original, so the overlap does not
// apply a mask twice and no byte a chunk masked is left in the clear. failed is
// the reason there is no masked text.
func mergedMask(text string, chunks []textchunk.Chunk, evals []chunkEval, outs []textchunk.Outcome[struct{}]) (masked string, failed string) {
	if len(chunks) == 1 {
		m, ok := maskedText(evals[0].result)
		if !ok {
			return "", reasonAnonymizeNoOutput
		}
		return m, ""
	}
	perChunk := make([]string, len(chunks))
	for i, c := range chunks {
		perChunk[i] = c.Text
		if !outs[i].Started || outs[i].Err != nil || evals[i].res.anonymize == nil {
			continue
		}
		m, ok := maskedText(evals[i].result)
		if !ok {
			return "", reasonAnonymizeNoOutput
		}
		perChunk[i] = m
	}
	merged, ok := textchunk.MergeMasks(text, chunks, perChunk)
	if !ok {
		return "", reasonAnonymizeEncodeFailed
	}
	return merged, ""
}

func (p *Plugin) anonymizeEnforce(
	ctx context.Context,
	in appplugins.ExecInput,
	data *Data,
	message string,
	result *SanitizationResult,
	span rewriteSpan,
	f *finding,
) (*appplugins.Result, error) {
	masked, ok := maskedText(result)
	reason := ""
	if !ok {
		reason = reasonAnonymizeNoOutput
	}
	return p.anonymizeEnforceMasked(ctx, in, data, message, masked, reason, span, f)
}

// anonymizeEnforceMasked applies a mask Model Armor produced, or refuses in a
// mode that blocks when it cannot be applied: failedReason is why there is no
// masked text, and empty when there is.
func (p *Plugin) anonymizeEnforceMasked(
	ctx context.Context,
	in appplugins.ExecInput,
	data *Data,
	message string,
	masked string,
	failedReason string,
	span rewriteSpan,
	f *finding,
) (*appplugins.Result, error) {
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
	if data.FailureDetail != "" && data.FailureDetail != reason {
		data.EarlierFailureDetail = data.FailureDetail
	}
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

// failureInfo is what one externalFailure call needs beyond the shared
// appplugins.ExternalFailure fields: which Model Armor filter (if any) is
// involved, that filter's own why-it-did-not-run reason (kept in
// Data.FailureDetail; see the comment on Data.FailureDetail for why this is
// distinct from the generic FailureReason), and the filter version the
// response carried, when there was a response to read one from.
type failureInfo struct {
	reason        appplugins.FailureReason
	filter        string
	armorReason   string
	filterVersion string
	// chunks is how many calls the evaluation was split into, when it was.
	chunks int
	err    error
}

// externalFailure turns a failed guardrail call into a plugin outcome via the
// shared appplugins.HandleExternalFailure, which owns the class and the mode:
// an availability failure passes through as failed_open, and an input failure
// is refused in a mode that blocks. It builds this plugin's own Data so
// failure_reason/failure_detail/failure_class travel in the same shape as every
// other external guardrail, while keeping filter and filter_version, which are
// specific to this plugin.
func (p *Plugin) externalFailure(
	ctx context.Context,
	in appplugins.ExecInput,
	cfg Settings,
	latencyMS int64,
	fi failureInfo,
) (*appplugins.Result, error) {
	outcome := appplugins.HandleExternalFailure(appplugins.ExternalFailure{
		Ctx:     ctx,
		Plugin:  PluginName,
		Stage:   in.Stage,
		Mode:    in.Mode,
		Reason:  fi.reason,
		Detail:  fi.armorReason,
		Message: cfg.Message,
		Err:     fi.err,
		Logger:  p.logger,
		Event:   in.Event,
	})
	data := newData(in, cfg, latencyMS)
	data.Decision = outcome.Decision
	data.FailureReason = string(fi.reason)
	data.FailureDetail = fi.armorReason
	data.FailureClass = string(outcome.Class)
	data.Filter = fi.filter
	data.FilterVersion = fi.filterVersion
	if fi.chunks > 1 {
		data.ChunkCount = fi.chunks
	}
	setExtras(in.Event, data)
	if outcome.Err != nil {
		return nil, outcome.Err
	}
	return outcome.Result, nil
}

func newData(in appplugins.ExecInput, cfg Settings, latency int64) *Data {
	return &Data{
		Project:   cfg.Project,
		Location:  cfg.Location,
		Template:  cfg.Template,
		Stage:     string(in.Stage),
		Mode:      string(in.Mode),
		LatencyMS: latency,
	}
}

func applyFinding(data *Data, f *finding) {
	data.Filter = f.filter
	data.InfoTypes = f.infoTypes
	data.Confidence = f.confidence
	data.Category = f.category
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

// keepsMaskDespiteGap reports whether a block_on filter that produced no
// verdict leaves a mask to apply in a mode that blocks. It does when the gap is
// availability (the template never enabled the filter, or its state is
// unspecified): the de-identified text is already in hand and releasing the
// original would send the raw data. A gap that is the content's (a skipped
// filter) refuses instead, since the other filters did not judge this content.
func keepsMaskDespiteGap(res assessmentResult, mode policy.Mode, reason string) bool {
	return res.anonymize != nil && appplugins.Blocks(mode) &&
		appplugins.ClassOf(appplugins.FailureVerdictIncomplete, reason) == appplugins.FailureClassAvailability
}
