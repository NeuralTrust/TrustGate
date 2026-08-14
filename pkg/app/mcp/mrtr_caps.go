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

package mcp

import (
	"context"
	"strings"
)

// MetaKeyClientCapabilities is the request metadata key carrying the client's
// declared capabilities.
const MetaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"

var mrtrCapabilityKinds = []string{"elicitation", "sampling", "roots"}

type clientCapabilitiesKey struct{}

// WithClientCapabilities stores the allowlisted client capabilities on the
// request context for the southbound call to forward.
func WithClientCapabilities(ctx context.Context, caps map[string]any) context.Context {
	return context.WithValue(ctx, clientCapabilitiesKey{}, AllowlistedClientCapabilities(caps))
}

// ClientCapabilitiesFromContext returns the capabilities the northbound client
// declared, or nil.
func ClientCapabilitiesFromContext(ctx context.Context) map[string]any {
	caps, _ := ctx.Value(clientCapabilitiesKey{}).(map[string]any)
	return caps
}

// AllowlistedClientCapabilities keeps only elicitation, sampling, and roots.
func AllowlistedClientCapabilities(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]any, len(mrtrCapabilityKinds))
	for _, kind := range mrtrCapabilityKinds {
		if value, ok := raw[kind]; ok {
			out[kind] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DeclaredCapability reports whether the client declared the given kind.
func DeclaredCapability(caps map[string]any, kind string) bool {
	if len(caps) == 0 {
		return false
	}
	_, ok := caps[kind]
	return ok
}

// InputRequestKind maps an input request method to its capability kind, or ""
// when the method is not one the gateway mediates.
func InputRequestKind(method string) string {
	switch {
	case strings.HasPrefix(method, "elicitation"):
		return "elicitation"
	case strings.HasPrefix(method, "sampling"):
		return "sampling"
	case strings.HasPrefix(method, "roots"):
		return "roots"
	default:
		return ""
	}
}
