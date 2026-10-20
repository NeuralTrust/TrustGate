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

package usage

import (
	"context"
	"net/http"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	usagedomain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

//go:generate mockery --name=RequestRecorder --dir=. --output=./mocks --filename=usage_request_recorder_mock.go --case=underscore --with-expecter

// RequestRecorder emits the usage record of a finished LLM or MCP request.
type RequestRecorder interface {
	// Enabled reports whether usage records are emitted at all.
	Enabled() bool
	// Record emits the record of the request traced by rt when it is billable.
	// statusCode is the status the client got and startTime the instant the
	// request event records as its occurred on.
	Record(ctx context.Context, rt *trace.RequestTrace, statusCode int, startTime time.Time)
}

type requestRecorder struct {
	enabled  bool
	emitter  usagedomain.Emitter
	outcomes usagedomain.OutcomeRecorder
}

// NewRequestRecorder returns a recorder that emits through emitter when
// enabled is set and does nothing otherwise.
func NewRequestRecorder(enabled bool, emitter usagedomain.Emitter, outcomes usagedomain.OutcomeRecorder) RequestRecorder {
	return &requestRecorder{enabled: enabled && emitter != nil, emitter: emitter, outcomes: outcomes}
}

func (r *requestRecorder) Enabled() bool { return r.enabled }

func (r *requestRecorder) Record(ctx context.Context, rt *trace.RequestTrace, statusCode int, startTime time.Time) {
	if !r.enabled || rt == nil {
		return
	}
	meta := rt.Metadata()
	var smartRouting int64
	if meta.Kind == events.KindMCP {
		if rt.IsMetaTool() {
			return
		}
		if mcp, ok := lastMCPAttrs(rt); ok {
			if int64(mcp.RPCErrorCode) == appmcp.CodeRateLimited {
				return
			}
			if mcp.UpstreamStatus != 0 {
				statusCode = mcp.UpstreamStatus
			}
		}
	} else if served, ok := lastLLMAttrs(rt); ok && served.TierApplied {
		smartRouting = 1
	}
	if !BillableStatus(statusCode) {
		return
	}
	record, err := usagedomain.NewRecord(usagedomain.Record{
		EventID:                usagedomain.RequestEventID(rt.TraceID()),
		TenantID:               meta.TenantID,
		OccurredOn:             startTime,
		TraceID:                rt.TraceID(),
		GatewayID:              meta.GatewayID,
		ConsumerID:             meta.ConsumerID,
		Requests:               1,
		SmartRoutingExecutions: smartRouting,
	})
	if err != nil {
		r.skip()
		return
	}
	r.emitter.Emit(ctx, record)
}

func (r *requestRecorder) skip() {
	if r.outcomes != nil {
		r.outcomes.Outcome(usagedomain.OutcomeSkipped, 1)
	}
}

// BillableStatus reports whether a request that ended with code is billed:
// refused credentials, exhausted usage, rate limits and server errors are not.
func BillableStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusTooManyRequests:
		return false
	}
	return code < http.StatusInternalServerError
}

func lastLLMAttrs(rt *trace.RequestTrace) (trace.LLMAttrs, bool) {
	var (
		last  trace.LLMAttrs
		found bool
	)
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanLLM {
			continue
		}
		if attrs, ok := span.LLMAttrsCopy(); ok {
			last, found = attrs, true
		}
	}
	return last, found
}

func lastMCPAttrs(rt *trace.RequestTrace) (trace.MCPAttrs, bool) {
	var (
		last  trace.MCPAttrs
		found bool
	)
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanMCP {
			continue
		}
		if attrs, ok := span.MCPAttrsCopy(); ok {
			last, found = attrs, true
		}
	}
	return last, found
}
