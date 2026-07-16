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

package ratelimit

import (
	"context"
	"strings"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type gatewayTierLoader struct {
	finder appgateway.Finder
}

// NewGatewayTierLoader adapts the gateway Finder to the rate-limit port. It
// prefers the gateway already resolved onto the request context (stamped by
// the auth middleware) over an extra Finder round trip.
func NewGatewayTierLoader(finder appgateway.Finder) GatewayTierLoader {
	return &gatewayTierLoader{finder: finder}
}

func (l *gatewayTierLoader) Tier(ctx context.Context, gatewayID ids.GatewayID) (string, error) {
	if gw, ok := appgateway.FromContext(ctx); ok {
		if gw == nil {
			return "", gatewaydomain.ErrNotFound
		}
		return strings.TrimSpace(gw.Entitlements.Tier), nil
	}
	gw, err := l.finder.FindByID(ctx, gatewayID)
	if err != nil {
		return "", err
	}
	if gw == nil {
		return "", gatewaydomain.ErrNotFound
	}
	return strings.TrimSpace(gw.Entitlements.Tier), nil
}
