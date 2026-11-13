// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

// ScanReferences lists every stored credential value, across all gateways,
// that starts with or holds secret://. Before the first deploy that knows
// about references the expected result is empty: such a value would stop
// being sent as a literal credential.
func ScanReferences(ctx context.Context, registries RegistryLister) ([]Finding, error) {
	var out []Finding
	seen := 0
	for page := 1; ; page++ {
		batch, total, err := registries.List(ctx, registry.ListFilter{Page: page, Size: scanPageSize})
		if err != nil {
			return nil, fmt.Errorf("secret-refs-scan: list registries: %w", err)
		}
		for _, reg := range batch {
			uses, embedded := appsecretref.RegistryReferences(reg)
			out = appendFindings(out, reg, uses, FindingReference)
			out = appendFindings(out, reg, embedded, FindingEmbedded)
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

func appendFindings(out []Finding, reg *registry.Registry, uses []appsecretref.Use, kind string) []Finding {
	for _, u := range uses {
		out = append(out, Finding{
			GatewayID: reg.GatewayID.String(),
			Entity:    string(refdomain.EntityRegistry),
			ID:        reg.ID.String(),
			Name:      reg.Name,
			Field:     strings.Join(u.Path, "."),
			Kind:      kind,
		})
	}
	return out
}
