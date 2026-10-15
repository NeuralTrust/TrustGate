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

package oauth

import (
	"context"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ErrUpstreamSetupRequired is returned when a server's address is a template
// whose values this principal has not given yet ({region}, {domain}): there is
// no upstream to discover an OAuth server at until they do.
var ErrUpstreamSetupRequired = fmt.Errorf(
	"oauth connect: this server's address is not complete: finish its setup before connecting: %w",
	commonerrors.ErrValidation)

// discover finds the upstream's OAuth server at the URL the principal will
// actually dial. A templated URL was handed to discovery as-is, so every
// {variable} server failed with "bad upstream url" even after its values were
// given (RUN-1636).
func (s *connectService) discover(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (*UpstreamAuthServer, error) {
	upstream, err := s.upstreamURL(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	return s.registrar.Discover(ctx, upstream)
}

// upstreamURL resolves a registry's URL for one principal with the values the
// dial path uses, and holds the result to the dial path's SSRF gate: discovery
// fetches from that host, so a URL assembled from per-user values must be public
// here as well. A URL with no placeholders is returned unchanged.
func (s *connectService) upstreamURL(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (string, error) {
	target := reg.MCPTarget
	if target == nil || !target.HasURLVariables() {
		if target == nil {
			return "", nil
		}
		return target.URL, nil
	}
	values := target.InstanceConfig
	if s.urlValues != nil && principalSub != "" {
		v, err := s.urlValues.Values(ctx, gatewayID, principalSub, reg)
		if err != nil {
			return "", err
		}
		values = v
	}
	resolved, err := registrydomain.ResolveURL(target.URL, target.URLVariables, values)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUpstreamSetupRequired, err)
	}
	if err := registrydomain.ValidateResolvedUpstreamHost(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}
