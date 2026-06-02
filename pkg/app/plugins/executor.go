package plugins

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"golang.org/x/sync/errgroup"
)

// Executor runs the plugin chain for a single stage against a request/response
// pair, applying every plugin Result deterministically and surfacing the first
// rejection (PluginError) or short-circuit (StopUpstream).
//
//go:generate mockery --name=Executor --dir=. --output=./mocks --filename=executor_mock.go --case=underscore --with-expecter
type Executor interface {
	RunStage(ctx context.Context, in StageInput) (*StageOutcome, error)
}

// StageInput is the per-stage execution request.
type StageInput struct {
	Stage    policy.Stage
	Policies []*policy.Policy
	Request  *infracontext.RequestContext
	Response *infracontext.ResponseContext
}

// StageOutcome reports whether the stage short-circuited and the synthetic
// response to relay when it did.
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
	entries := buildStageChain(e.registry, in.Policies, in.Stage)
	outcome := &StageOutcome{}
	if len(entries) == 0 {
		return outcome, nil
	}

	for i := 0; i < len(entries); {
		batch := parallelBatch(entries, i)
		results, err := e.runBatch(ctx, in, batch)
		if err != nil {
			return nil, err
		}
		for _, res := range results {
			if e.applyResult(in.Response, outcome, res) {
				return outcome, nil
			}
		}
		i += len(batch)
	}
	return outcome, nil
}

func (e *executor) runBatch(ctx context.Context, in StageInput, batch []chainEntry) ([]*Result, error) {
	if len(batch) == 1 {
		res, err := e.runOne(ctx, in, batch[0])
		if err != nil {
			return nil, err
		}
		return []*Result{res}, nil
	}

	results := make([]*Result, len(batch))
	g, gctx := errgroup.WithContext(ctx)
	for idx := range batch {
		g.Go(func() error {
			res, err := e.runOne(gctx, in, batch[idx])
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
	return results, nil
}

func (e *executor) runOne(ctx context.Context, in StageInput, entry chainEntry) (*Result, error) {
	var event *metrics.EventContext
	if rt := trace.FromContext(ctx); rt != nil {
		span := rt.StartSpan(trace.SpanPlugin, entry.plugin.Name())
		span.SetStage(string(in.Stage))
		event = metrics.NewEventContext(span)
		// Guarantee the span is closed even if Execute panics.
		defer event.Publish()
	}

	start := time.Now()
	res, err := entry.plugin.Execute(ctx, ExecInput{
		Stage:    in.Stage,
		Config:   entry.config,
		Request:  in.Request,
		Response: in.Response,
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
			slog.String("stage", string(in.Stage)),
			slog.String("error", err.Error()))
	}
	return res, err
}

func (e *executor) applyResult(resp *infracontext.ResponseContext, outcome *StageOutcome, res *Result) bool {
	if res == nil {
		return false
	}
	if len(res.Headers) > 0 && resp != nil {
		mergeHeaders(resp, res.Headers)
	}
	if !res.StopUpstream {
		return false
	}

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
	return true
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
