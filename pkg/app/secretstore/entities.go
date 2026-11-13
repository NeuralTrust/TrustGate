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

package secretstore

import (
	"context"
	"fmt"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

const entitiesPageSize = 200

// NamedRefs is the reference-bearing state of one stored entity and the name
// it is listed under.
type NamedRefs struct {
	appsecretref.EntityRefs
	Name string
}

// EntityLister reads, as references, the stored entities of one kind that a
// gateway holds. Registries are not one: they are listed by RegistryLister.
type EntityLister func(ctx context.Context, gatewayID ids.GatewayID) ([]NamedRefs, error)

// GatewayLister pages through every gateway.
type GatewayLister interface {
	List(ctx context.Context, filter gateway.ListFilter) ([]*gateway.Gateway, int, error)
}

// ConsumerReader lists a gateway's consumers.
type ConsumerReader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*consumer.Consumer, error)
}

// ConsumerLister lists the embedding credentials of a gateway's consumers.
func ConsumerLister(repo ConsumerReader) EntityLister {
	return func(ctx context.Context, gatewayID ids.GatewayID) ([]NamedRefs, error) {
		consumers, err := repo.ListByGateway(ctx, gatewayID)
		if err != nil {
			return nil, fmt.Errorf("list consumers: %w", err)
		}
		out := make([]NamedRefs, 0, len(consumers))
		for _, c := range consumers {
			out = append(out, NamedRefs{EntityRefs: appsecretref.ConsumerRefs(c), Name: c.Name})
		}
		return out, nil
	}
}

// PolicyReader lists a gateway's policies.
type PolicyReader interface {
	ListByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*policy.Policy, error)
}

// PolicyLister lists the plugin credentials of a gateway's policies; refs
// reads one policy at its plugin's declared paths.
func PolicyLister(repo PolicyReader, refs func(*policy.Policy) appsecretref.EntityRefs) EntityLister {
	return func(ctx context.Context, gatewayID ids.GatewayID) ([]NamedRefs, error) {
		policies, err := repo.ListByGateway(ctx, gatewayID)
		if err != nil {
			return nil, fmt.Errorf("list policies: %w", err)
		}
		out := make([]NamedRefs, 0, len(policies))
		for _, p := range policies {
			out = append(out, NamedRefs{EntityRefs: refs(p), Name: p.Name})
		}
		return out, nil
	}
}

// AuthReader pages through a gateway's auths.
type AuthReader interface {
	List(ctx context.Context, filter auth.ListFilter) ([]*auth.Auth, int, error)
}

// AuthLister lists the identity provider secrets of a gateway's auths,
// enabled or not: a disabled one is enabled again with what it stores.
func AuthLister(repo AuthReader) EntityLister {
	return func(ctx context.Context, gatewayID ids.GatewayID) ([]NamedRefs, error) {
		var out []NamedRefs
		for page := 1; ; page++ {
			batch, total, err := repo.List(ctx, auth.ListFilter{GatewayID: gatewayID, Page: listing.Page{Number: page, Size: entitiesPageSize}})
			if err != nil {
				return nil, fmt.Errorf("list auths: %w", err)
			}
			for _, a := range batch {
				out = append(out, NamedRefs{EntityRefs: appsecretref.AuthRefs(a), Name: a.Name})
			}
			if len(batch) == 0 || len(out) >= total {
				return out, nil
			}
		}
	}
}

// EnabledAuthReader lists a gateway's enabled auths of one type; a DB-less
// data plane's snapshot repository serves it, while it cannot page.
type EnabledAuthReader interface {
	ListEnabledByGatewayAndType(ctx context.Context, gatewayID ids.GatewayID, authType auth.Type) ([]*auth.Auth, error)
}

// EnabledAuthLister lists the identity provider secrets of a gateway's
// enabled OAuth 2.0 auths: what a plane that serves traffic resolves.
func EnabledAuthLister(repo EnabledAuthReader) EntityLister {
	return func(ctx context.Context, gatewayID ids.GatewayID) ([]NamedRefs, error) {
		auths, err := repo.ListEnabledByGatewayAndType(ctx, gatewayID, auth.TypeOAuth2)
		if err != nil {
			return nil, fmt.Errorf("list auths: %w", err)
		}
		out := make([]NamedRefs, 0, len(auths))
		for _, a := range auths {
			out = append(out, NamedRefs{EntityRefs: appsecretref.AuthRefs(a), Name: a.Name})
		}
		return out, nil
	}
}

// GatewayReaderLister lists the gateway's own telemetry credentials.
func GatewayReaderLister(repo GatewayReader) EntityLister {
	return func(ctx context.Context, gatewayID ids.GatewayID) ([]NamedRefs, error) {
		gw, err := repo.FindByID(ctx, gatewayID)
		if err != nil {
			return nil, fmt.Errorf("find gateway: %w", err)
		}
		return []NamedRefs{{EntityRefs: appsecretref.GatewayRefs(gw), Name: gw.Slug}}, nil
	}
}
