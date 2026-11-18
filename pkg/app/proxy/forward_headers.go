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

package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// withForwardedClientHeaders puts on ctx the client headers the registry lists
// in provider_options.forward_client_headers, so the provider client pool adds
// them to the request it sends this backend. Each attempt reads its own
// backend's list: a fallback to another registry forwards what that registry
// allows, not what the first one did.
func withForwardedClientHeaders(ctx context.Context, bk *registry.Registry, req *infracontext.RequestContext) context.Context {
	return providers.WithForwardedHeaders(ctx, forwardedClientHeaders(bk, req))
}

func forwardedClientHeaders(bk *registry.Registry, req *infracontext.RequestContext) http.Header {
	if bk == nil || req == nil || len(req.Headers) == 0 {
		return nil
	}
	names := registry.ForwardClientHeaders(bk.ProviderOptions())
	if len(names) == 0 {
		return nil
	}
	out := make(http.Header, len(names))
	for _, name := range names {
		for header, values := range req.Headers {
			if !strings.EqualFold(header, name) {
				continue
			}
			for _, v := range values {
				if v != "" {
					out.Add(name, v)
				}
			}
		}
	}
	return out
}
