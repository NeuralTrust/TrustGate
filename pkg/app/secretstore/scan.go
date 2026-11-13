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
	"strings"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

const scanPageSize = 500

// Finding kinds.
const (
	// FindingReference is a credential value that is entirely a reference.
	FindingReference = "reference"
	// FindingEmbedded is a credential value that holds a reference inside a
	// longer value, which is never resolved.
	FindingEmbedded = "embedded"
)

// Finding is one stored credential value that looks like a secret
// reference. It names where the value is, never the value.
type Finding struct {
	GatewayID string
	Entity    string
	ID        string
	Name      string
	Field     string
	Kind      string
}

// ScanSources is what ScanReferences reads: every registry, and every
// gateway with the entities of each that Entities lists.
type ScanSources struct {
	Registries RegistryLister
	Gateways   GatewayLister
	Entities   []EntityLister
}

// ScanReferences lists every stored credential value, across all gateways,
// that starts with or holds secret://. Before the first deploy that knows
// about references the expected result is empty: such a value would stop
// being sent as a literal credential.
func ScanReferences(ctx context.Context, src ScanSources) ([]Finding, error) {
	out, err := scanRegistries(ctx, src.Registries)
	if err != nil {
		return nil, err
	}
	if src.Gateways == nil || len(src.Entities) == 0 {
		return out, nil
	}
	seen := 0
	for page := 1; ; page++ {
		batch, total, err := src.Gateways.List(ctx, gateway.ListFilter{Page: page, Size: scanPageSize})
		if err != nil {
			return nil, fmt.Errorf("secret-refs-scan: list gateways: %w", err)
		}
		for _, gw := range batch {
			for _, list := range src.Entities {
				entities, err := list(ctx, gw.ID)
				if err != nil {
					return nil, fmt.Errorf("secret-refs-scan: gateway %s: %w", gw.ID, err)
				}
				for _, e := range entities {
					out = appendFindings(out, e, e.Uses, FindingReference)
					out = appendFindings(out, e, e.Embedded, FindingEmbedded)
				}
			}
		}
		seen += len(batch)
		if seen >= total {
			return out, nil
		}
		if len(batch) == 0 {
			return nil, fmt.Errorf("secret-refs-scan: read %d of %d gateways; the table changed during the scan, run it again", seen, total)
		}
	}
}

func scanRegistries(ctx context.Context, registries RegistryLister) ([]Finding, error) {
	var out []Finding
	seen := 0
	for page := 1; ; page++ {
		batch, total, err := registries.List(ctx, registry.ListFilter{Page: page, Size: scanPageSize})
		if err != nil {
			return nil, fmt.Errorf("secret-refs-scan: list registries: %w", err)
		}
		for _, reg := range batch {
			e := registryRefs(reg)
			out = appendFindings(out, e, e.Uses, FindingReference)
			out = appendFindings(out, e, e.Embedded, FindingEmbedded)
		}
		seen += len(batch)
		if seen >= total {
			return out, nil
		}
		if len(batch) == 0 {
			return nil, fmt.Errorf("secret-refs-scan: read %d of %d registries; the table changed during the scan, run it again", seen, total)
		}
	}
}

func registryRefs(reg *registry.Registry) NamedRefs {
	uses, embedded := appsecretref.RegistryReferences(reg)
	return NamedRefs{
		EntityRefs: appsecretref.EntityRefs{
			GatewayID: reg.GatewayID, Entity: refdomain.EntityRegistry, ID: reg.ID.String(), Uses: uses, Embedded: embedded,
		},
		Name: reg.Name,
	}
}

func appendFindings(out []Finding, e NamedRefs, uses []appsecretref.Use, kind string) []Finding {
	for _, u := range uses {
		out = append(out, Finding{
			GatewayID: e.GatewayID.String(),
			Entity:    string(e.Entity),
			ID:        e.ID,
			Name:      e.Name,
			Field:     strings.Join(u.Path, "."),
			Kind:      kind,
		})
	}
	return out
}
