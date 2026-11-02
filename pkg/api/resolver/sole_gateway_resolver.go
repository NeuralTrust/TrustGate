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

package resolver

import (
	"strings"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

// soleGatewayResolver serves the only gateway a plane holds when the request
// names none. A plane that runs for one gateway answers on a host that does not
// carry the slug, and many MCP clients can only be given a URL, not a header.
type soleGatewayResolver struct {
	next   GatewayResolver
	finder appgateway.Finder
}

// WithSoleGatewayFallback wraps next so that a request naming no gateway, by
// header or by host, resolves to the plane's gateway when its configuration
// holds exactly one. A slug the request does name is never overridden, and a
// plane holding several gateways keeps failing as before.
func WithSoleGatewayFallback(next GatewayResolver, finder appgateway.Finder) GatewayResolver {
	return &soleGatewayResolver{next: next, finder: finder}
}

func (r *soleGatewayResolver) Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	gw, err := r.next.Resolve(c)
	if err == nil || strings.TrimSpace(c.Get(HeaderGatewaySlug)) != "" {
		return gw, err
	}
	gateways, total, listErr := r.finder.List(c.UserContext(), gatewaydomain.ListFilter{Page: 1, Size: 2})
	if listErr != nil || total != 1 || len(gateways) != 1 {
		return nil, err
	}
	return gateways[0], nil
}
