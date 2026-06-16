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
