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
	"time"

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
}

func NewExecutor(registry Registry, logger *slog.Logger) Executor {
	return &executor{registry: registry, logger: logger}
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
		if e.applyResults(in.Stage, in.Request, in.Response, outcome, results) {
			return outcome, nil
		}
	}
	return outcome, nil
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
	if seg.Final {
		defer spans.publish()
	}

	for _, entry := range entries {
		inspector, ok := entry.plugin.(StreamInspector)
		if !ok {
			continue
		}
		event := spans.eventFor(ctx, seg, entry)
		verdict, err := inspector.InspectSegment(ctx, ExecInput{
			Stage:    policy.StagePreResponse,
			Mode:     entry.mode,
			Config:   entry.config,
			Scope:    scopeFromRequest(in.Request, entry.global),
			Request:  in.Request,
			Response: in.Response,
			Event:    event,
		}, seg)
		if err != nil {
			event.SetError(err)
			return nil, fmt.Errorf("plugins: inspecting stream segment %d with %s: %w", seg.Seq, entry.plugin.Name(), err)
		}
		if verdict == nil {
			continue
		}
		if e.mergeVerdict(outcome, verdict, entry) {
			break
		}
	}
	return outcome, nil
}

func (e *executor) streamEntries(in StageInput) []chainEntry {
	if in.Plan != nil {
		return in.Plan.entriesFor(policy.StagePreResponse)
	}
	return buildStageChain(e.registry, in.Policies, policy.StagePreResponse, false)
}

// mergeVerdict folds one verdict into the consolidated outcome and reports
// whether the chain must stop. Both the cut and the rewrite are gated on
// Blocks(entry.mode): an observe-mode entry contributes its findings and its
// fingerprints, but never cuts the stream and never rewrites text the client is
// about to read.
func (e *executor) mergeVerdict(outcome *SegmentOutcome, verdict *SegmentVerdict, entry chainEntry) bool {
	outcome.Fingerprints = append(outcome.Fingerprints, verdict.Fingerprints...)
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
		if outcome.HasTransform {
			e.warnExcessStreamTransform(entry)
			return false
		}
		outcome.HasTransform = true
		outcome.Transformed = verdict.Transformed
	}
	return false
}

func (e *executor) warnExcessStreamTransform(entry chainEntry) {
	if e.logger == nil {
		return
	}
	e.logger.Warn("stream segment produced multiple transforms; keeping first in chain order",
		slog.String("stage", string(policy.StagePreResponse)),
		slog.String("slug", entry.config.Slug))
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
