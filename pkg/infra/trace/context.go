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

package trace

import "context"

type contextKey string

const traceContextKey contextKey = "__request_trace"
const spanContextKey contextKey = "__active_span"

func NewContext(ctx context.Context, t *RequestTrace) context.Context {
	return context.WithValue(ctx, traceContextKey, t)
}

func FromContext(ctx context.Context) *RequestTrace {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(traceContextKey).(*RequestTrace)
	return t
}

// NewSpanContext carries an active span so downstream code (e.g. the MCP
// composer) can annotate it without re-discovering it from the trace.
func NewSpanContext(ctx context.Context, s *Span) context.Context {
	return context.WithValue(ctx, spanContextKey, s)
}

func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(spanContextKey).(*Span)
	return s
}
