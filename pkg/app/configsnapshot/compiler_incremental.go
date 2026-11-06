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

package configsnapshot

import (
	"context"
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

// IncrementalSource is what an incremental compile reads: everything at once
// for a full rebuild, or one gateway, the catalog and the shared inputs on
// their own.
type IncrementalSource interface {
	// CollectAll reads every gateway and its configuration, the way a full
	// compile does. A gateway skipped for corrupt persisted config has no
	// entry in data.
	CollectAll(ctx context.Context) (gateways []gatewaydomain.Gateway, data map[ids.GatewayID]*readmodel.Data, catalog readmodel.Data, err error)
	// CollectGateway reads one gateway and its configuration. A nil gateway
	// means it no longer exists.
	CollectGateway(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, *readmodel.Data, error)
	// CollectCatalog reads the shared provider and model catalog.
	CollectCatalog(ctx context.Context) (readmodel.Data, error)
	// ListShared reads the inputs every snapshot flavor is stamped with.
	ListShared(ctx context.Context) (SharedInputs, error)
}

// GatewayFinder is implemented by gateway readers that load one gateway by id.
// Without it, CollectGateway finds the gateway in the full listing.
type GatewayFinder interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

var _ IncrementalSource = (*Compiler)(nil)

// CollectAll reads every gateway's configuration and the catalog, with the
// same bulk read and corrupt-row fallback as CompileAll.
func (c *Compiler) CollectAll(ctx context.Context) ([]gatewaydomain.Gateway, map[ids.GatewayID]*readmodel.Data, readmodel.Data, error) {
	gateways, err := c.listGateways(ctx)
	if err != nil {
		return nil, nil, readmodel.Data{}, err
	}
	collected, err := c.collectGateways(ctx, gateways)
	if err != nil {
		return nil, nil, readmodel.Data{}, err
	}
	data := make(map[ids.GatewayID]*readmodel.Data, len(gateways))
	for i := range gateways {
		if collected[i] != nil {
			data[gateways[i].ID] = collected[i]
		}
	}
	catalog, err := c.collectCatalogData(ctx)
	if err != nil {
		return nil, nil, readmodel.Data{}, err
	}
	return gateways, data, catalog, nil
}

// CollectGateway reads one gateway and its configuration. Its policies go
// through the unreadable-row breaker on their own, since the whole-table check
// of the bulk path does not run; a corrupt gateway fails with ErrCorruptData.
func (c *Compiler) CollectGateway(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, *readmodel.Data, error) {
	gateway, err := c.findGateway(ctx, id)
	if err != nil || gateway == nil {
		return nil, nil, err
	}
	var data readmodel.Data
	if err := c.collectGatewayData(ctx, id, &data, true); err != nil {
		return nil, nil, err
	}
	return gateway, &data, nil
}

// CollectCatalog reads the provider and model catalog.
func (c *Compiler) CollectCatalog(ctx context.Context) (readmodel.Data, error) {
	return c.collectCatalogData(ctx)
}

// ListShared reads the tenant caps and session revocations, with the same
// fallbacks a full compile applies, plus the static playground keys and usage
// switch.
func (c *Compiler) ListShared(ctx context.Context) (SharedInputs, error) {
	caps := c.listTenantCaps(ctx)
	revocations, err := c.listSessionRevocations(ctx)
	if err != nil {
		return SharedInputs{}, err
	}
	return SharedInputs{
		TenantCaps:         caps,
		SessionRevocations: revocations,
		PlaygroundKeys:     c.playgroundTokenKeys,
		UsageEnforcement:   c.usageEnforcement,
	}, nil
}

func (c *Compiler) findGateway(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if finder, ok := c.gateways.(GatewayFinder); ok {
		gateway, err := finder.FindByID(ctx, id)
		if errors.Is(err, commonerrors.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: find gateway %s: %w", id, err)
		}
		return gateway, nil
	}
	gateways, err := c.listGateways(ctx)
	if err != nil {
		return nil, err
	}
	for i := range gateways {
		if gateways[i].ID == id {
			return &gateways[i], nil
		}
	}
	return nil, nil
}
