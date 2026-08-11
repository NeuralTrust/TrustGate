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

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
)

type gatewayTierLoader struct {
	finder appgateway.Finder
}

// NewGatewayTierLoader prefers the gateway on ctx over Finder.
func NewGatewayTierLoader(finder appgateway.Finder) GatewayTierLoader {
	return &gatewayTierLoader{finder: finder}
}

func (l *gatewayTierLoader) Limits(ctx context.Context, gatewayID ids.GatewayID) (domain.Limits, error) {
	if gw, ok := appgateway.FromContext(ctx); ok {
		if gw == nil {
			return domain.Limits{}, gatewaydomain.ErrNotFound
		}
		return limitsOrDefault(gw)
	}
	gw, err := l.finder.FindByID(ctx, gatewayID)
	if err != nil {
		return domain.Limits{}, err
	}
	if gw == nil {
		return domain.Limits{}, gatewaydomain.ErrNotFound
	}
	return limitsOrDefault(gw)
}

func limitsOrDefault(gw *gatewaydomain.Gateway) (domain.Limits, error) {
	limits, ok := gw.Entitlements.ResolveLimits()
	if !ok {
		return domain.Limits{}, ErrUnmetered
	}
	return limits, nil
}
