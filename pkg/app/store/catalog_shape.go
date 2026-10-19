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

package store

import (
	"encoding/json"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// shapeCatalog answers CanonicalizeMCPAuthFromCatalog for one entry and never
// binds a platform OAuth client, so the shape is what Create persisted for a
// catalog install that carried no admin secret.
type shapeCatalog struct {
	entry catalogdomain.MCPServer
}

func (c shapeCatalog) GetByCode(code string) (catalogdomain.MCPServer, bool) {
	if code == c.entry.Code {
		return c.entry, true
	}
	return catalogdomain.MCPServer{}, false
}

func (c shapeCatalog) SharedOAuthCredentials(string) (string, string, bool) {
	return "", "", false
}

// storedCatalogShape is the mcp_target Create persists for a catalog entry:
// the shared shelf from catalogMCPTarget, then the auth canonicalisation the
// creator runs (resource fallback, registration, client-credentials token
// method). The result does not alias the catalog entry's slices.
func storedCatalogShape(entry catalogdomain.MCPServer) (*registrydomain.MCPTarget, error) {
	target := catalogMCPTarget(entry)
	if err := appregistry.CanonicalizeMCPAuthFromCatalog(target, shapeCatalog{entry: entry}); err != nil {
		return nil, err
	}
	return cloneMCPTarget(target)
}

func cloneMCPTarget(target *registrydomain.MCPTarget) (*registrydomain.MCPTarget, error) {
	if target == nil {
		return nil, nil
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return nil, err
	}
	var out registrydomain.MCPTarget
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
