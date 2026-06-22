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

package auth

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type Method string

const (
	MethodAPIKey     Method = "api_key"
	MethodOAuth2     Method = "oauth2"
	MethodOIDC       Method = "oidc"
	MethodPlayground Method = "playground"
)

type AuthContext struct {
	Method      Method
	GatewayID   ids.GatewayID
	GatewaySlug string
	ConsumerID  ids.ConsumerID
	AuthID      ids.AuthID
	Subject     string
	Claims      map[string]any
	Scopes      []string
	RoleIDs     []ids.RoleID
}

type authContextKey struct{}

func WithAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey{}, authCtx)
}

func AuthContextFromContext(ctx context.Context) (*AuthContext, bool) {
	authCtx, ok := ctx.Value(authContextKey{}).(*AuthContext)
	return authCtx, ok && authCtx != nil
}
