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
	"maps"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"golang.org/x/sync/errgroup"
)

//go:generate mockery --name=Executor --dir=. --output=./mocks --filename=executor_mock.go --case=underscore --with-expecter
type Executor interface {
	RunStage(ctx context.Context, in StageInput) (*StageOutcome, error)
}

type StageInput struct {
	Stage    policy.Stage
	Policies []*policy.Policy
	Plan     *StagePlan
	Request  *infracontext.RequestContext
	Response *infracontext.ResponseContext
}

func (e *executor) batchesFor(in StageInput) [][]chainEntry {
	if in.Plan != nil {
		return in.Plan.batchesFor(in.Stage)
	}
	return groupBatches(buildStageChain(e.registry, in.Policies, in.Stage, false), in.Stage, e.logger)
}

type StageOutcome struct {
	ShortCircuit bool
	StatusCode   int
	Body         []byte
	Headers      map[string][]string
}

var _ Executor = (*executor)(nil)

type executor struct {
	registry Registry
	logger   *slog.Logger
	now      func() time.Time
}

func NewExecutor(registry Registry, logger *slog.Logger) Executor {
	return &executor{registry: registry, logger: logger, now: time.Now}
}

func (e *executor) clock() time.Time {
	if e.now == nil {
		return time.Now()
	}
	return e.now()
}

func (e *executor) RunStage(ctx context.Context, in StageInput) (*StageOutcome, error) {
	batches := e.batchesFor(in)
	outcome := &StageOutcome{}
	if len(batches) == 0 {
		return outcome, nil
	}

	for _, batch := range batches {
		results, err := e.runBatch(ctx, in.Stage, in.Request, in.Response, batch)
		if err != nil {
			return nil, err
		}
		if e.applyResults(in.Stage, in.Request, in.Response, outcome, results) && !handsOnResponse(in, outcome) {
			return outcome, nil
		}
	}
	return outcome, nil
}

// handsOnResponse reports whether a short-circuit at this stage is a response
// rewrite the rest of the chain must still judge. At pre_response a plugin
// rewrites the upstream body by short-circuiting with the new one and a 2xx
// status (a mask, a de-identification, an injected tool error), and
// applyResults has already written it to the response. Stopping there would
// skip every later guard, across priorities, whenever an earlier plugin masked
// something, and would drop the masks of every later rewriter. So the chain
// goes on over the rewritten body, the way a streamed segment hands its
// transform on; the outcome still ends the response, with the last body
// written (RUN-1745).
//
// A non-2xx short-circuit is a denial, as the MCP runner reads it
// (replacesPayload), and still ends the stage: nothing after it may overwrite
// a block.
func handsOnResponse(in StageInput, outcome *StageOutcome) bool {
	if in.Stage != policy.StagePreResponse || in.Response == nil {
		return false
	}
	return outcome.StatusCode == 0 || (outcome.StatusCode >= 200 && outcome.StatusCode < 300)
}

// RunStreamSegment runs the pre_response entries that implement StreamInspector
// against one block of a streaming response and consolidates their verdicts. It
// stays off the Executor interface on purpose: the stream guard consumes it
// through a narrow interface of its own, so RunStage, the MCP callers and the
// generated mocks keep a contract that has no notion of streaming.
//
// The chain stops at the first blocking verdict — with a single call in flight
// there is nothing left to cancel, and every later call would rediscover the
// same finding over the same cumulative text.
//
// A closing segment is the exception: it asks for no verdict, so every entry is
// visited whatever the ones before it answered, and an error from one is
// recorded on its own span rather than denying the rest of the chain the only
// point at which it can publish.
//
// StageInput.Stage is ignored: a stream is a pre_response concern, so the chain
// is always the pre_response one and ExecInput.Stage is always
// policy.StagePreResponse whatever the caller passed.
func (e *executor) RunStreamSegment(ctx context.Context, in StageInput, seg StreamSegment) (*SegmentOutcome, error) {
	outcome := &SegmentOutcome{}
	entries := e.streamEntries(in)
	if len(entries) == 0 {
		return outcome, nil
	}

	spans := streamSpansFrom(ctx)
	var reporters map[string]bool
	if seg.Closing {
		// Finality and closure are mutually exclusive, and only one caller
		// builds both flags: a segment that carries no text cannot also be the
		// block that covered the end of the response.
		seg.Final = false
		reporters = spans.reporters(seg, entries)
		defer spans.publish()
	}

	// current is the segment the next entry is handed. It starts as the raw
	// segment and, after an enforcing entry rewrites it, carries the masked
	// text, so a later entry (a reader above all) never sends the unmasked
	// text to its third party (RUN-1744).
	current := seg
	// cutKeys names the entries that would author a cut on THIS segment. The
	// stored list is replaced at the end of every evaluated segment, because a
	// cut can only happen on the last one: a mask an earlier block landed is not
	// to be blamed for a later block's failure.
	var cutKeys []string
	var failedKey string
	if !seg.Closing {
		defer func() { spans.setCut(seg, cutKeys, failedKey, !outcome.Block) }()
	}
	for _, entry := range entries {
		inspector, ok := streamInspector(entry.plugin)
		if !ok {
			continue
		}
		event := spans.eventFor(ctx, current, entry)
		call := current
		if seg.Closing {
			call.Report = spans.entryReport(seg, entry)
			call.Findings = entryFindings(seg.Findings, entry)
			call.ReportsStream = reporters[spanKey(seg, entry)]
		}
		started := e.clock()
		verdict, err := inspector.InspectSegment(ctx, ExecInput{
			Stage:    policy.StagePreResponse,
			Mode:     entry.mode,
			Config:   entry.config,
			Scope:    scopeFromRequest(in.Request, entry.global),
			Request:  in.Request,
			Response: in.Response,
			Event:    event,
		}, call)
		if !seg.Closing {
			spans.charge(seg, entry, e.clock().Sub(started))
		}
		if err != nil {
			event.SetError(err)
			if seg.Closing {
				continue
			}
			// Observe never blocks, and streaming.on_error is the stream's
			// answer for entries that can: an observe entry that could not
			// inspect a segment records that it failed open and lets the
			// rest of the chain carry on, as its buffered leg does.
			if !Blocks(entry.mode) {
				SetDecisionFromOutcome(event, decisionFailedOpen)
				continue
			}
			failedKey = spanKey(seg, entry)
			failure := fmt.Errorf("plugins: inspecting stream segment %d with %s: %w", seg.Seq, entry.plugin.Name(), err)
			// An earlier enforcing entry may already have masked this segment.
			// Hand that mask back with the error: a caller that resolves the
			// failure as fail_open releases the held text, and it must release
			// the masked text, never the raw text a mask already covered.
			if outcome.HasTransform {
				return outcome, failure
			}
			return nil, failure
		}
		if seg.Closing || verdict == nil {
			continue
		}
		stop := e.mergeVerdict(outcome, verdict, entry)
		// Hand-off mirrors mergeVerdict: only a transform from an entry that
		// blocks is applied to what the client receives, so only that one
		// changes what the entries behind it see. An observe transform is
		// never applied, and the entries behind must judge what is released.
		if !stop && verdict.HasTransform && Blocks(entry.mode) {
			current = segmentAfterTransform(current, verdict.Transformed)
		}
		switch {
		case stop:
			// A block is the cut's one author: the transforms of the same
			// segment are discarded with it, so their entries do not share it.
			cutKeys = []string{spanKey(seg, entry)}
		case verdict.HasTransform && Blocks(entry.mode):
			// Every entry whose transform ends up in the final mask is a
			// candidate for the rewrite that could not be applied.
			if key := spanKey(seg, entry); !slices.Contains(cutKeys, key) {
				cutKeys = append(cutKeys, key)
			}
		}
		if stop {
			break
		}
	}
	return outcome, nil
}

func (e *executor) streamEntries(in StageInput) []chainEntry {
	if in.Plan != nil {
		return in.Plan.streamEntriesFor()
	}
	return streamParticipants(OrderStreamEntries(buildStageChain(e.registry, in.Policies, policy.StagePreResponse, false)))
}

// segmentAfterTransform is the segment the entries behind a rewriter receive.
// Transformed replaces the whole of Accumulated (SegmentVerdict), so it becomes
// the new Accumulated. Text is the delta of the block: the tail of the masked
// text from where the block began, or from where the mask first diverged from
// the raw text when that is earlier, so masked text is never left out of it.
// Reasoning and ToolCalls are unchanged: the guard refuses a transform over a
// block that carries either.
func segmentAfterTransform(seg StreamSegment, transformed string) StreamSegment {
	start := len(seg.Accumulated) - len(seg.Text)
	if start < 0 {
		start = 0
	}
	common := 0
	for common < len(seg.Accumulated) && common < len(transformed) && seg.Accumulated[common] == transformed[common] {
		common++
	}
	from := min(start, common)
	for from > 0 && from < len(transformed) && !utf8.RuneStart(transformed[from]) {
		from--
	}
	seg.Accumulated = transformed
	seg.Text = transformed[from:]
	return seg
}

// mergeVerdict folds one verdict into the consolidated outcome and reports
// whether the chain must stop. Both the cut and the rewrite are gated on
// Blocks(entry.mode): an observe-mode entry contributes its findings and its
// fingerprints, but never cuts the stream and never rewrites text the client is
// about to read.
//
// Fingerprints are tagged with the entry here because here is where the entry
// is known. The guard holds one set for the whole stream and a plugin answers
// only for itself, so the tag is what lets the set be narrowed back to the
// entry that reported each key.
func (e *executor) mergeVerdict(outcome *SegmentOutcome, verdict *SegmentVerdict, entry chainEntry) bool {
	for _, fp := range verdict.Fingerprints {
		outcome.Fingerprints = append(outcome.Fingerprints, StreamFinding{Entry: entry.config.ID, Fingerprint: fp})
	}
	if outcome.Type == "" && verdict.Type != "" {
		outcome.Type = verdict.Type
		outcome.Message = verdict.Message
	}
	if !Blocks(entry.mode) {
		return false
	}
	if verdict.Block {
		outcome.Block = true
		outcome.Type = verdict.Type
		outcome.Message = verdict.Message
		outcome.HasTransform = false
		outcome.Transformed = ""
		return true
	}
	if verdict.HasTransform {
		// The last transform wins: each entry is handed the text the previous
		// rewriter produced (segmentAfterTransform), so the last one already
		// carries every earlier mask.
		outcome.HasTransform = true
		outcome.Transformed = verdict.Transformed
		// Type and Message describe the entry whose transform is kept.
		if verdict.Type != "" {
			outcome.Type = verdict.Type
			outcome.Message = verdict.Message
		}
	}
	return false
}

func (e *executor) runBatch(
	ctx context.Context,
	stage policy.Stage,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	batch []chainEntry,
) ([]*Result, error) {
	if len(batch) == 1 {
		res, err := e.runOne(ctx, stage, req, resp, batch[0])
		if err != nil {
			return nil, err
		}
		return []*Result{res}, nil
	}

	results := make([]*Result, len(batch))
	reqs := make([]*infracontext.RequestContext, len(batch))
	resps := make([]*infracontext.ResponseContext, len(batch))
	g, gctx := errgroup.WithContext(ctx)
	for idx := range batch {
		reqs[idx] = isolateRequest(req)
		resps[idx] = isolateResponse(resp)
		g.Go(func() error {
			res, err := e.runOne(gctx, stage, reqs[idx], resps[idx], batch[idx])
			if err != nil {
				return err
			}
			results[idx] = res
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for idx := range batch {
		mergeIsolated(req, reqs[idx], resp, resps[idx])
	}
	return results, nil
}

func (e *executor) runOne(
	ctx context.Context,
	stage policy.Stage,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	entry chainEntry,
) (*Result, error) {
	var event *metrics.EventContext
	if rt := trace.FromContext(ctx); rt != nil {
		span := rt.StartSpan(trace.SpanPlugin, entry.plugin.Name())
		span.SetStage(string(stage))
		event = metrics.NewEventContext(span)
		// Guarantee the span is closed even if Execute panics.
		defer event.Publish()
	}

	if event != nil {
		event.SetMode(string(entry.mode))
	}

	start := time.Now()
	res, err := entry.plugin.Execute(ctx, ExecInput{
		Stage:    stage,
		Mode:     entry.mode,
		Config:   entry.config,
		Scope:    scopeFromRequest(req, entry.global),
		Request:  req,
		Response: resp,
		Event:    event,
	})

	if err != nil {
		if _, ok := AsPluginError(err); !ok && !Blocks(entry.mode) && ctx.Err() == nil {
			// Observe never blocks, and a plugin that could not run at all —
			// a counter-store outage that slipped past its own fail-open
			// handling, a transport error, anything that is not a deliberate
			// PluginError verdict — must not stop the chain or bubble up as a
			// 502 either. This mirrors what RunStreamSegment already does for
			// observe-mode stream entries: fail open, record it, move on.
			//
			// ctx.Err() != nil is excluded on purpose: the caller's own
			// cancellation (a client disconnect, an upstream deadline
			// unwinding the whole chain, a sibling in the same parallel
			// batch blocking and canceling gctx) is not this plugin failing
			// on its own, and treating it as failed_open would misreport
			// every abandoned request as an infrastructure incident.
			origErr := err
			if event != nil {
				event.SetError(origErr)
				SetDecisionFromOutcome(event, decisionFailedOpen)
			}
			e.warnFailedOpen(entry, stage, origErr)
			res, err = &Result{StatusCode: http.StatusOK}, nil
		}
	}

	if event != nil {
		event.SetSLatency(time.Since(start))
		switch {
		case err != nil:
			event.SetError(err)
			if pe, ok := AsPluginError(err); ok {
				event.SetStatusCode(pe.StatusCode)
			}
		case res != nil:
			event.SetStatusCode(res.StatusCode)
		}
	}

	if err != nil && e.logger != nil {
		e.logger.Debug("plugin returned error",
			slog.String("plugin", entry.plugin.Name()),
			slog.String("stage", string(stage)),
			slog.String("error", err.Error()))
	}
	return res, err
}

func scopeFromRequest(req *infracontext.RequestContext, global bool) RuntimeScope {
	scope := RuntimeScope{Global: global}
	if req != nil {
		scope.GatewayID = req.GatewayID
		scope.ConsumerID = req.ConsumerID
	}
	return scope
}

func isolateRequest(src *infracontext.RequestContext) *infracontext.RequestContext {
	if src == nil {
		return nil
	}
	clone := *src
	clone.Headers = cloneHeaders(src.Headers)
	clone.Metadata = maps.Clone(src.Metadata)
	return &clone
}

func isolateResponse(src *infracontext.ResponseContext) *infracontext.ResponseContext {
	if src == nil {
		return nil
	}
	clone := *src
	clone.Headers = cloneHeaders(src.Headers)
	clone.Metadata = maps.Clone(src.Metadata)
	return &clone
}

func mergeIsolated(
	req, isoReq *infracontext.RequestContext,
	resp, isoResp *infracontext.ResponseContext,
) {
	if req != nil && isoReq != nil {
		req.Metadata = mergeAnyMap(req.Metadata, isoReq.Metadata)
		req.Headers = mergeHeaderMap(req.Headers, isoReq.Headers)
	}
	if resp != nil && isoResp != nil {
		resp.Metadata = mergeAnyMap(resp.Metadata, isoResp.Metadata)
		resp.Headers = mergeHeaderMap(resp.Headers, isoResp.Headers)
	}
}

func mergeAnyMap(dst, src map[string]interface{}) map[string]interface{} {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]interface{}, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func mergeHeaderMap(dst, src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string][]string, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (e *executor) applyResults(
	stage policy.Stage,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	outcome *StageOutcome,
	results []*Result,
) bool {
	var reqBodyApplied, stopApplied bool
	for _, res := range results {
		if res == nil {
			continue
		}
		if stopApplied {
			if res.StopUpstream {
				e.warnExcessWriter(stage, "stop_upstream")
			}
			if res.RequestBody != nil {
				e.warnExcessWriter(stage, "request_body")
			}
			continue
		}
		if len(res.Headers) > 0 && resp != nil {
			mergeHeaders(resp, res.Headers)
		}
		if res.RequestBody != nil && req != nil {
			if reqBodyApplied {
				e.warnExcessWriter(stage, "request_body")
			} else {
				req.Body = res.RequestBody
				reqBodyApplied = true
			}
		}
		if !res.StopUpstream {
			continue
		}
		stopApplied = true
		outcome.ShortCircuit = true
		outcome.StatusCode = res.StatusCode
		outcome.Body = res.Body
		if resp != nil {
			resp.StatusCode = res.StatusCode
			resp.Body = res.Body
			outcome.Headers = cloneHeaders(resp.Headers)
		} else {
			outcome.Headers = cloneHeaders(res.Headers)
		}
	}
	return stopApplied
}

// warnFailedOpen logs the one Warn line a buffered-path entry gets when it
// failed open in a non-blocking mode: same shape as warnExcessWriter, kept
// next to it since both are runOne/runBatch's own diagnostics rather than
// something the plugin logged itself.
func (e *executor) warnFailedOpen(entry chainEntry, stage policy.Stage, err error) {
	if e.logger == nil {
		return
	}
	e.logger.Warn("plugin failed open on a non-blocking mode",
		slog.String("plugin", entry.plugin.Name()),
		slog.String("stage", string(stage)),
		slog.String("mode", string(entry.mode)),
		slog.String("decision", decisionFailedOpen),
		slog.Any("error", err))
}

func (e *executor) warnExcessWriter(stage policy.Stage, capability string) {
	if e.logger == nil {
		return
	}
	e.logger.Warn("parallel batch produced multiple writers; keeping first in deterministic order",
		slog.String("stage", string(stage)),
		slog.String("capability", capability))
}

func mergeHeaders(resp *infracontext.ResponseContext, headers map[string][]string) {
	if resp.Headers == nil {
		resp.Headers = make(map[string][]string, len(headers))
	}
	for name, values := range headers {
		resp.Headers[name] = append(resp.Headers[name], values...)
	}
}

func cloneHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for name, values := range headers {
		out[name] = append([]string(nil), values...)
	}
	return out
}
