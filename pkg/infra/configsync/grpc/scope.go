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

package grpc

import "context"

type scopeContextKeyType struct{}

var scopeContextKey scopeContextKeyType

// WithScope returns a context carrying the config-sync partition scope key. An
// empty scope denotes the whole, unpartitioned config, which preserves the
// single-tenant behavior.
func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeContextKey, scope)
}

// ScopeFromContext returns the partition scope key set upstream by the auth
// interceptor, or "" when none is present (unpartitioned / single-tenant).
func ScopeFromContext(ctx context.Context) string {
	scope, _ := ctx.Value(scopeContextKey).(string)
	return scope
}
