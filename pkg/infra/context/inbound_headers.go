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

package context

import (
	"context"
	"strings"
)

// WithInboundHeaders stores a clone of the real inbound HTTP request headers
// on ctx. Callers on a fiber handler (without Immutable: true, which this
// gateway does not set) get back strings that alias a buffer fasthttp reuses
// once the handler returns, so every value is cloned here before it can
// outlive that frame.
func WithInboundHeaders(ctx context.Context, headers map[string][]string) context.Context {
	return context.WithValue(ctx, InboundHeadersContextKey, cloneHeaderStrings(headers))
}

// InboundHeadersFromContext returns the headers WithInboundHeaders stored, or
// nil when none were set (any plane that builds its RequestContext straight
// from a real HTTP request already has its own Headers and never needs this).
func InboundHeadersFromContext(ctx context.Context) map[string][]string {
	headers, _ := ctx.Value(InboundHeadersContextKey).(map[string][]string)
	return headers
}

func cloneHeaderStrings(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for key, values := range headers {
		cloned := make([]string, len(values))
		for i, v := range values {
			cloned[i] = strings.Clone(v)
		}
		out[strings.Clone(key)] = cloned
	}
	return out
}
