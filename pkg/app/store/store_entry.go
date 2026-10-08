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
	"context"
	"strings"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// storeEntry is the catalog entry a Store code stands for: the catalog's own,
// or for a custom server one built from its registry, so a custom server is
// granted, installed and requested like a catalog one. False when the code
// names neither, or a custom server that is gone.
func storeEntry(
	ctx context.Context,
	catalog CatalogReader,
	registries RegistryLister,
	gatewayID ids.GatewayID,
	code string,
) (catalogdomain.MCPServer, bool, error) {
	code = strings.TrimSpace(code)
	if _, custom := registrydomain.ParseCustomStoreCode(code); !custom {
		entry, ok := catalog.GetByCode(code)
		return entry, ok, nil
	}
	if registries == nil {
		return catalogdomain.MCPServer{}, false, nil
	}
	found, err := findRegistriesByCode(ctx, registries, gatewayID, code)
	if err != nil || len(found) == 0 {
		return catalogdomain.MCPServer{}, false, err
	}
	return customEntry(code, found[0]), true, nil
}

// customEntry describes a custom server the way the catalog describes its
// servers. An admin configured it in full, so it never waits on admin setup
// and declares no per-user URL variables; a user signs in to it only when its
// auth forwards their own token.
func customEntry(code string, reg *registrydomain.Registry) catalogdomain.MCPServer {
	entry := catalogdomain.MCPServer{
		Code:        code,
		DisplayName: registryLabel(reg),
		URL:         reg.MCPTarget.URL,
		Transport:   string(reg.MCPTarget.Transport),
		SelfService: true,
	}
	if forwardedAuthOf(reg) != nil {
		entry.RequiresAuth = true
		entry.AuthHint = "oauth"
	}
	return entry
}
