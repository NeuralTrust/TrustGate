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
	"errors"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

type gatewayTierLoader struct {
	finder appgateway.Finder
	caps   TenantCapsSource
}

// NewGatewayTierLoader resolves gateways through the finder and the tenant's caps
// through caps. A plane that answers from the config snapshot passes a source
// over the snapshot; a plane that reads Postgres passes its TenantCapsCache so
// the per-request cost stays at the single gateway lookup.
func NewGatewayTierLoader(finder appgateway.Finder, caps TenantCapsSource) GatewayTierLoader {
	return &gatewayTierLoader{finder: finder, caps: caps}
}

// Resolve maps a gateway to its counting subject and caps.
//
// The subject is the gateway's tenant. A gateway with no tenant is not metered:
// there is nobody to bill, and OSS installs have no tenant at all.
//
// The tenant's own caps win. A tenant with none stored, which is every tenant
// until the control plane has published them, is metered on the caps stamped on
// the gateway, but still against the tenant's counter: the counter is shared
// from the first request, and only the number it is compared with is a fallback.
// A tenant with neither is not metered.
func (l *gatewayTierLoader) Resolve(ctx context.Context, gatewayID ids.GatewayID) (Resolved, error) {
	gw, err := l.gateway(ctx, gatewayID)
	if err != nil {
		return Resolved{}, err
	}
	tenant := gw.TenantID()
	if tenant == "" {
		return Resolved{}, ErrUnmetered
	}
	if l.caps != nil {
		caps, err := l.caps.FindTenantCaps(ctx, tenant)
		switch {
		case err == nil && caps != nil:
			return Resolved{Subject: tenant, Limits: caps.Limits()}, nil
		case err != nil && !errors.Is(err, commonerrors.ErrNotFound):
			return Resolved{}, err
		}
	}
	limits, ok := gw.Entitlements.ResolveLimits()
	if !ok {
		return Resolved{}, ErrUnmetered
	}
	return Resolved{Subject: tenant, Limits: limits}, nil
}

func (l *gatewayTierLoader) gateway(ctx context.Context, gatewayID ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if gw, ok := appgateway.FromContext(ctx); ok {
		if gw == nil {
			return nil, gatewaydomain.ErrNotFound
		}
		return gw, nil
	}
	gw, err := l.finder.FindByID(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	if gw == nil {
		return nil, gatewaydomain.ErrNotFound
	}
	return gw, nil
}
