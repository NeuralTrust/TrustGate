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

// unverifiedOnMCP is the deny list of headers the LLM plane only ever hands to
// a plugin AFTER a resolver or auth middleware verified them — never their raw
// client-supplied value — so a plugin trusting one is trusting that upstream
// verification, not the header. MCP has no equivalent gate for any of these,
// so WithInboundHeaders strips them before a plugin can see them at all: a
// client authenticated on the MCP plane (mTLS/bearer/API key via
// MCPAuthMiddleware, pkg/api/middleware/mcp_auth.go — no playground concept)
// can freely set any of these itself.
//
//   - X-AG-Playground-Token (resolver.HeaderPlaygroundToken,
//     pkg/api/resolver/playground_resolver.go:29): on the proxy/LLM plane,
//     ChainedIdentityResolver.Resolve (pkg/api/resolver/chained_resolver.go:55)
//     routes a request carrying this header EXCLUSIVELY through
//     PlaygroundIdentityResolver, which requires the value to verify as a
//     "playground"-purpose JWT (signature + consumer-slug binding) or the
//     whole request is rejected before any plugin runs. So a plugin that only
//     checks presence — trustguard/plugin.go:691 requestHasPlaygroundToken,
//     which does exactly that to decide whether to send
//     X-AG-Playground: 1 (trustguard/client.go:34) toward the TrustGuard
//     collector — is safe there only because presence implies verified.
//     MCPAuthMiddleware's resolver chain (mTLS > bearer > API key) never
//     touches this header, so on MCP presence proves nothing: an
//     authenticated MCP client could set it to any string and forge the
//     playground marker. Stripped here rather than fixing
//     requestHasPlaygroundToken itself, because the same presence-only
//     pattern could reappear in a future plugin; removing the header at its
//     one entry point closes the class, not just this instance.
//
// Authorization is deliberately NOT on this list: the only plugin that reads
// it, prompttemplate's bearerToken/unverifiedClaim
// (pkg/infra/plugins/prompttemplate/jwt.go:26-73), decodes it without
// signature verification by design and says so in its own comment — the
// result feeds a prompt template variable, never an authorization decision —
// and the LLM plane already hands plugins the raw Authorization header
// verbatim (pkg/api/handler/http/proxy/proxy_handler.go:489-502 copies every
// header with no filtering at all), so propagating it to MCP too is parity
// with an already-accepted risk, not a new one.
var unverifiedOnMCP = map[string]struct{}{
	"x-ag-playground-token": {},
}

// WithInboundHeaders stores a clone of the real inbound HTTP request headers
// on ctx, minus unverifiedOnMCP. Callers on a fiber handler (without
// Immutable: true, which this gateway does not set) get back strings that
// alias a buffer fasthttp reuses once the handler returns, so every value is
// cloned here before it can outlive that frame.
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
		if _, denied := unverifiedOnMCP[strings.ToLower(key)]; denied {
			continue
		}
		cloned := make([]string, len(values))
		for i, v := range values {
			cloned[i] = strings.Clone(v)
		}
		out[strings.Clone(key)] = cloned
	}
	return out
}
