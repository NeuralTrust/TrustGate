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

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
)

type scopeContextKeyType struct{}

var scopeContextKey scopeContextKeyType

func WithScope(ctx context.Context, scope string) context.Context {
	return context.WithValue(ctx, scopeContextKey, scope)
}

func ScopeFromContext(ctx context.Context) string {
	scope, _ := ctx.Value(scopeContextKey).(string)
	return scope
}

type identityContextKeyType struct{}

var identityContextKey identityContextKeyType

// WithIdentity returns a copy of ctx carrying the verified config-sync token
// identity.
func WithIdentity(ctx context.Context, id configsyncrevocation.Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// IdentityFromContext returns the verified config-sync token identity and
// whether the context carries one.
func IdentityFromContext(ctx context.Context) (configsyncrevocation.Identity, bool) {
	id, ok := ctx.Value(identityContextKey).(configsyncrevocation.Identity)
	return id, ok
}
