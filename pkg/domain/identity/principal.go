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

package identity

import (
	"context"
	"strings"
)

type Method string

const (
	MethodAPIKey        Method = "api_key"
	MethodJWT           Method = "jwt"
	MethodIntrospection Method = "introspection"
	MethodMTLS          Method = "mtls"
)

type Principal struct {
	Subject  string         `json:"subject"`
	Method   Method         `json:"method"`
	Issuer   string         `json:"issuer,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	RawToken string         `json:"-"`
}

var protocolScopes = map[string]struct{}{
	"openid":         {},
	"profile":        {},
	"email":          {},
	"offline_access": {},
}

func IsProtocolScope(scope string) bool {
	_, ok := protocolScopes[scope]
	return ok
}

func (p *Principal) HasScopes(required []string) bool {
	if len(required) == 0 {
		return true
	}
	if p == nil {
		return false
	}
	held := make(map[string]struct{}, len(p.Scopes))
	for _, s := range p.Scopes {
		held[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := protocolScopes[r]; ok {
			continue
		}
		if _, ok := held[r]; ok {
			continue
		}
		if leaf, found := resourceURILeaf(r); found {
			if _, ok := held[leaf]; ok {
				continue
			}
		}
		return false
	}
	return true
}

func resourceURILeaf(scope string) (string, bool) {
	if !strings.HasPrefix(scope, "api://") {
		return "", false
	}
	idx := strings.LastIndex(scope, "/")
	if idx < 0 || idx == len(scope)-1 {
		return "", false
	}
	return scope[idx+1:], true
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(contextKey{}).(*Principal)
	return p
}
